"""
MCP server for the Arc Agent Registry.

Exposes the trust layer as tools a Claude Code agent can call: register an identity, look up
an agent, check a seller's reputation BEFORE paying (the gate), issue a feedback
authorization after a sale, rate a counterparty, and discover trusted x402 services.

Configuration (environment, never tool arguments):
  ARC_IDENTITY_ADDRESS    deployed IdentityRegistry address
  ARC_REPUTATION_ADDRESS  deployed ReputationRegistry address
  ARC_PRIVATE_KEY         key for writes/signing (reads work without it)
  ARC_REGISTRY_DB         local sqlite path (default arc_registry.db)
"""
from __future__ import annotations

import os
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .arc import ArcReader, ArcWriter, EXPLORER
from .engine import RegistryEngine
from .store import Store

mcp = FastMCP("arc-agent-registry")

_engine: Optional[RegistryEngine] = None


def _addresses() -> tuple[Optional[str], Optional[str]]:
    return os.getenv("ARC_IDENTITY_ADDRESS"), os.getenv("ARC_REPUTATION_ADDRESS")


def engine() -> RegistryEngine:
    global _engine
    if _engine is None:
        identity, reputation = _addresses()
        if not identity or not reputation:
            raise RuntimeError(
                "ARC_IDENTITY_ADDRESS and ARC_REPUTATION_ADDRESS must be set "
                "(deploy contracts/script/Deploy.s.sol first)."
            )
        reader = ArcReader(identity, reputation)
        writer = ArcWriter(identity, reputation)
        store = Store()
        _engine = RegistryEngine(store, reader, writer, reputation_address=reputation)
    return _engine


def _tx_url(tx: str) -> str:
    return f"{EXPLORER}/tx/{tx}"


@mcp.tool()
def registry_status() -> dict:
    """Show the registry configuration and whether a signing key is present."""
    identity, reputation = _addresses()
    writer = ArcWriter(identity or "", reputation or "")
    status = {
        "identity_registry": identity,
        "reputation_registry": reputation,
        "can_write": writer.configured,
        "my_address": writer.address(),
        "explorer": EXPLORER,
    }
    if identity and reputation:
        try:
            status["agent_count"] = ArcReader(identity, reputation).agent_count()
        except Exception as e:
            status["agent_count_error"] = str(e)
    return status


@mcp.tool()
def register_agent(name: str, domain: str, capabilities: Optional[list[str]] = None,
                   x402_endpoint: str = "", x402_price: int = 0, description: str = "") -> dict:
    """Register this agent's identity on Arc. If it sells an x402 service, give the endpoint
    and price (token base units). Returns the agent_id and the registration tx."""
    res = engine().register_agent(name, domain, capabilities, x402_endpoint, x402_price, description)
    if res.get("tx"):
        res["tx_url"] = _tx_url(res["tx"])
    return res


@mcp.tool()
def resolve_agent(agent_id: int) -> dict:
    """Look up an agent: owner, card URI, and on-chain reputation summary."""
    return engine().resolve_agent(agent_id)


@mcp.tool()
def trust_check(agent_id: int, min_score: int = 70, min_count: int = 1) -> dict:
    """THE PRE-PAYMENT GATE. Returns whether an agent is trustworthy enough to pay, based on
    on-chain reputation. Read-only. Call this before sending an x402 payment to a seller."""
    return engine().trust_check(agent_id, min_score=min_score, min_count=min_count)


@mcp.tool()
def authorize_feedback(agent_id: int, client: str, valid_seconds: int = 600) -> dict:
    """SELLER SIDE. After serving a paid request, sign a FeedbackAuth letting `client` rate
    this agent once. Hand the returned auth to the buyer. No transaction, just a signature."""
    return engine().authorize_feedback(agent_id, client, valid_seconds=valid_seconds)


@mcp.tool()
def give_feedback(agent_id: int, score: int, tag: str, expiry: int, nonce: str,
                  signature: str, file_uri: str = "") -> dict:
    """BUYER SIDE. Rate an agent (score 0-100) using a FeedbackAuth the seller gave you.
    Writes the feedback on-chain and returns the tx."""
    auth = {"expiry": expiry, "nonce": nonce, "signature": signature}
    res = engine().give_feedback(agent_id, score, tag, auth, file_uri=file_uri)
    if res.get("tx"):
        res["tx_url"] = _tx_url(res["tx"])
    return res


@mcp.tool()
def register_service(endpoint: str, agent_id: int, price: int,
                     asset: str = "0x3600000000000000000000000000000000000000",
                     description: str = "") -> dict:
    """Add an x402 service to the local discovery directory (endpoint -> agent -> price)."""
    return engine().register_service(endpoint, agent_id, price, asset, description)


@mcp.tool()
def discover(min_score: int = 70, min_count: int = 1) -> list[dict]:
    """Discovery: trusted x402 services, best reputation first. Each entry carries its
    seller's reputation so a buyer can pick whom to pay."""
    return engine().discover(min_score=min_score, min_count=min_count)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
