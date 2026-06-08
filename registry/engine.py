"""
RegistryEngine: the orchestration that ties the pure core, the store, and the chain.

The chain access is injected (a `reader` for eth_call reads, a `writer` for signed writes),
so the whole flow can be exercised with fakes and no real money. Two guarantees the tests
pin down:

  - `trust_check` (the pre-payment gate) NEVER calls the writer. It only reads reputation
    and decides. A buyer agent calls this before paying.
  - The store only records a registration or feedback when a write actually returned a tx
    hash. No tx, no local claim.
"""
from __future__ import annotations

import time
from typing import Optional

from . import abi, core
from .core import ReputationSummary
from .discovery import select_trusted_services
from .store import Store


class RegistryEngine:
    def __init__(self, store: Store, reader, writer, reputation_address: str):
        self.store = store
        self.reader = reader
        self.writer = writer
        self.reputation_address = reputation_address

    # -- identity --

    def register_agent(self, name: str, domain: str, capabilities: Optional[list[str]] = None,
                       x402_endpoint: str = "", x402_price: int = 0,
                       description: str = "") -> dict:
        """Register an agent identity on Arc. Builds the agent card, validates it, and
        records the registration locally only if the chain write returns a tx."""
        card = core.build_agent_card(
            name=name, domain=domain, description=description,
            capabilities=capabilities, x402_endpoint=x402_endpoint, x402_price=x402_price,
        )
        ok, reason = core.validate_agent_card(card)
        if not ok:
            return {"ok": False, "reason": reason}

        card_uri = card["url"]
        tx = self.writer.register(card_uri)
        if not tx:
            return {"ok": False, "reason": "registration write returned no tx", "card": card}

        # agentId is the latest minted id. For a single registrar this is agent_count();
        # for production, resolve from the Registered event in the receipt.
        agent_id = self.reader.agent_count()
        owner = self.writer.address() or ""
        self.store.upsert_agent(agent_id, owner, name, domain, card_uri, list(capabilities or []), tx)
        return {"ok": True, "agent_id": agent_id, "tx": tx, "card_uri": card_uri, "card": card}

    def resolve_agent(self, agent_id: int) -> dict:
        """Live view of an agent from chain + local card metadata."""
        if not self.reader.exists(agent_id):
            return {"ok": False, "reason": "no such agent"}
        owner = self.reader.owner_of(agent_id)
        uri = self.reader.token_uri(agent_id)
        n, total, average = self.reader.get_summary(agent_id)
        local = self.store.get_agent(agent_id) or {}
        return {
            "ok": True, "agent_id": agent_id, "owner": owner, "card_uri": uri,
            "name": local.get("name"), "domain": local.get("domain"),
            "reputation": {"count": n, "total": total, "average": average},
        }

    # -- reputation: the pre-payment gate --

    def trust_check(self, agent_id: int, min_score: int = 70, min_count: int = 1) -> dict:
        """Decide whether an agent is trustworthy enough to pay. Reads only; no writes."""
        n, total, _avg = self.reader.get_summary(agent_id)
        summary = ReputationSummary(agent_id=agent_id, count=n, total=total)
        trusted = core.should_trust(summary, min_score=min_score, min_count=min_count)
        return {
            "agent_id": agent_id, "trusted": trusted,
            "count": summary.count, "average": summary.average,
            "min_score": min_score, "min_count": min_count,
        }

    # -- reputation: seller authorizes, buyer rates --

    def authorize_feedback(self, agent_id: int, client: str, valid_seconds: int = 600) -> dict:
        """Seller side: the agent owner signs a FeedbackAuth letting `client` rate it once.
        No transaction, just a signature handed to the buyer after a paid call."""
        key = getattr(self.writer, "private_key", None)
        if not key:
            return {"ok": False, "reason": "no signing key configured"}
        expiry = int(time.time()) + valid_seconds
        nonce = core.new_nonce()
        sig = core.sign_feedback_auth(key, self.reputation_address, agent_id, client, expiry, nonce)
        return {"ok": True, "agent_id": agent_id, "client": client, "expiry": expiry,
                "nonce": nonce, "signature": sig}

    def give_feedback(self, agent_id: int, score: int, tag: str, auth: dict, file_uri: str = "") -> dict:
        """Buyer side: submit feedback using a FeedbackAuth from the seller. Recorded
        locally only when the chain write returns a tx."""
        if not (0 <= score <= 100):
            return {"ok": False, "reason": "score must be 0-100"}
        tag_bytes = abi.tag_to_bytes32(tag)
        tx = self.writer.give_feedback(
            agent_id, score, tag_bytes, file_uri, int(auth["expiry"]), auth["nonce"], auth["signature"],
        )
        if not tx:
            return {"ok": False, "reason": "feedback write returned no tx"}
        self.store.record_feedback(agent_id, self.writer.address() or "", score, tag, tx)
        return {"ok": True, "agent_id": agent_id, "score": score, "tx": tx}

    # -- discovery --

    def register_service(self, endpoint: str, agent_id: int, price: int,
                         asset: str = core.USDC_ARC, description: str = "") -> dict:
        self.store.add_service(endpoint, agent_id, price, asset, description)
        return {"ok": True, "endpoint": endpoint, "agent_id": agent_id}

    def discover(self, min_score: int = 70, min_count: int = 1) -> list[dict]:
        """The discovery answer: trusted x402 services, best reputation first."""
        services = self.store.list_services()
        summaries: dict[int, ReputationSummary] = {}
        for svc in services:
            aid = svc["agent_id"]
            if aid in summaries:
                continue
            n, total, _ = self.reader.get_summary(aid)
            summaries[aid] = ReputationSummary(agent_id=aid, count=n, total=total)
        return select_trusted_services(services, summaries, min_score=min_score, min_count=min_count)
