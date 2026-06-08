"""
Pure core: agent cards, reputation math, and the FeedbackAuth EIP-712 signature.

Nothing here touches the chain, a database, or the network. Every function is a plain
transformation of its inputs, so the trust-critical parts (the reputation gate and the
FeedbackAuth signature that the on-chain ReputationRegistry verifies) are deterministic
and testable without real money.

The FeedbackAuth typed data here is byte-for-byte the structure the Solidity
ReputationRegistry recovers in `giveFeedback`. If these drift apart, on-chain feedback
stops verifying, so the parity is covered by tests.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Optional

# EIP-712 domain of the ReputationRegistry. Must match the contract constructor.
REPUTATION_DOMAIN_NAME = "ArcAgentReputation"
REPUTATION_DOMAIN_VERSION = "1"

ARC_CHAIN_ID = 5042002
USDC_ARC = "0x3600000000000000000000000000000000000000"


# --------------------------------------------------------------------------- #
# Agent cards
# --------------------------------------------------------------------------- #

def well_known_card_url(domain: str) -> str:
    """The conventional location of an agent card for a domain."""
    domain = domain.strip().rstrip("/")
    if domain.startswith("http://") or domain.startswith("https://"):
        base = domain
    else:
        base = "https://" + domain
    return f"{base}/.well-known/agent-card.json"


def build_agent_card(name: str, domain: str, description: str = "",
                     capabilities: Optional[list[str]] = None,
                     x402_endpoint: str = "", x402_price: int = 0,
                     x402_asset: str = USDC_ARC) -> dict:
    """Build an A2A-style agent card. If the agent sells an x402 service, the payment
    block tells buyers where to call and the price in token base units."""
    card: dict = {
        "schemaVersion": "1",
        "name": name,
        "description": description,
        "url": well_known_card_url(domain),
        "capabilities": list(capabilities or []),
        "registrations": [{"network": f"eip155:{ARC_CHAIN_ID}"}],
    }
    if x402_endpoint:
        card["payment"] = {
            "protocol": "x402",
            "endpoint": x402_endpoint,
            "asset": x402_asset,
            "network": f"eip155:{ARC_CHAIN_ID}",
            "price": str(int(x402_price)),
        }
    return card


def validate_agent_card(card: dict) -> tuple[bool, str]:
    """Minimal structural validation of an agent card."""
    if not isinstance(card, dict):
        return False, "card is not an object"
    for required in ("name", "url"):
        if not card.get(required):
            return False, f"missing {required}"
    pay = card.get("payment")
    if pay is not None:
        if pay.get("protocol") != "x402":
            return False, "unsupported payment protocol"
        if not pay.get("endpoint"):
            return False, "payment block missing endpoint"
        try:
            int(pay.get("price", "0"))
        except (TypeError, ValueError):
            return False, "payment price is not an integer"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Reputation math + trust gate
# --------------------------------------------------------------------------- #

@dataclass
class ReputationSummary:
    agent_id: int
    count: int
    total: int

    @property
    def average(self) -> int:
        """Average score (0-100), integer floor, 0 when there is no feedback yet.
        Mirrors the contract's `sum / n`."""
        return 0 if self.count == 0 else self.total // self.count


def should_trust(summary: ReputationSummary, min_score: int = 70, min_count: int = 1) -> bool:
    """The pre-payment gate. An agent is trusted only once it has at least `min_count`
    feedbacks AND an average at or above `min_score`. A brand-new agent with no history
    is NOT trusted by default, which is the safe stance before sending money."""
    if summary.count < min_count:
        return False
    return summary.average >= min_score


# --------------------------------------------------------------------------- #
# FeedbackAuth (EIP-712) — must match ReputationRegistry exactly
# --------------------------------------------------------------------------- #

def new_nonce() -> str:
    """A random single-use 32-byte nonce for a FeedbackAuth."""
    return "0x" + secrets.token_hex(32)


def feedback_auth_typed_data(reputation_contract: str, agent_id: int, client: str,
                             expiry: int, nonce: str, chain_id: int = ARC_CHAIN_ID) -> dict:
    """The EIP-712 typed data for a FeedbackAuth. The agent owner signs this to let one
    `client` leave one piece of feedback for `agent_id`."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "FeedbackAuth": [
                {"name": "agentId", "type": "uint256"},
                {"name": "client", "type": "address"},
                {"name": "expiry", "type": "uint64"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "FeedbackAuth",
        "domain": {
            "name": REPUTATION_DOMAIN_NAME,
            "version": REPUTATION_DOMAIN_VERSION,
            "chainId": chain_id,
            "verifyingContract": reputation_contract,
        },
        "message": {
            "agentId": int(agent_id),
            "client": client,
            "expiry": int(expiry),
            "nonce": nonce,
        },
    }


def sign_feedback_auth(private_key: str, reputation_contract: str, agent_id: int,
                       client: str, expiry: int, nonce: str,
                       chain_id: int = ARC_CHAIN_ID) -> str:
    """Sign a FeedbackAuth with the agent owner's key. Returns the 0x signature that the
    contract's `giveFeedback` will recover."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    td = feedback_auth_typed_data(reputation_contract, agent_id, client, expiry, nonce, chain_id)
    signable = encode_typed_data(full_message=td)
    signed = Account.sign_message(signable, private_key)
    sig = signed.signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def recover_feedback_auth_signer(reputation_contract: str, agent_id: int, client: str,
                                 expiry: int, nonce: str, signature: str,
                                 chain_id: int = ARC_CHAIN_ID) -> str:
    """Recover the signer of a FeedbackAuth (used by tests and to pre-check an auth)."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    td = feedback_auth_typed_data(reputation_contract, agent_id, client, expiry, nonce, chain_id)
    signable = encode_typed_data(full_message=td)
    return Account.recover_message(signable, signature=signature)
