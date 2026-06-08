"""
Arc testnet chain layer for the registries.

Two halves:
  - Reads (`ArcReader`): eth_call into the IdentityRegistry / ReputationRegistry to fetch
    ownership, card URIs, and reputation summaries. No key needed.
  - Writes (`ArcWriter`): sign and broadcast contract calls (register, giveFeedback) as
    EIP-1559 (type 2) transactions, which Arc requires (20 Gwei minimum base fee; a legacy
    gasPrice tx can fail). The private key is read from the environment and is never logged
    or returned.

Arc quirks handled: USDC is the native gas token, type-2 fees with a 20 Gwei floor, a small
in-process nonce manager so a batch of writes gets consecutive nonces, and gas estimation
per call (contract writes are not a flat 21000 like a plain transfer).
"""
from __future__ import annotations

import os
from typing import Optional

import httpx

from . import abi

RPC_URL = os.getenv("ARC_TESTNET_RPC_URL", "https://rpc.testnet.arc.network")
CHAIN_ID = int(os.getenv("ARC_CHAIN_ID", "5042002"))
EXPLORER = "https://testnet.arcscan.app"
MIN_BASE_FEE_WEI = 20 * 10 ** 9
DEFAULT_PRIORITY_WEI = 10 ** 9


def rpc(method: str, params: list, url: str = RPC_URL) -> object:
    with httpx.Client(timeout=20.0) as client:
        r = client.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"RPC error on {method}: {data['error']}")
        return data["result"]


def _to_int(h) -> int:
    return int(h, 16) if isinstance(h, str) else int(h)


class ArcReader:
    """Read-only view of the registries. Safe to use with no key."""

    def __init__(self, identity_address: str, reputation_address: str):
        self.identity = identity_address
        self.reputation = reputation_address

    def _call(self, to: str, data: str) -> str:
        return rpc("eth_call", [{"to": to, "data": data}, "latest"])

    def agent_count(self) -> int:
        return abi.decode_uint(self._call(self.identity, abi.encode_agent_count()))

    def exists(self, agent_id: int) -> bool:
        return abi.decode_bool(self._call(self.identity, abi.encode_exists(agent_id)))

    def owner_of(self, agent_id: int) -> str:
        return abi.decode_address(self._call(self.identity, abi.encode_owner_of(agent_id)))

    def token_uri(self, agent_id: int) -> str:
        return abi.decode_string(self._call(self.identity, abi.encode_token_uri(agent_id)))

    def get_summary(self, agent_id: int) -> tuple[int, int, int]:
        """(count, total, average)."""
        return abi.decode_summary(self._call(self.reputation, abi.encode_get_summary(agent_id)))


class ArcWriter:
    """Signs and sends contract calls. Holds the key from ARC_PRIVATE_KEY."""

    def __init__(self, identity_address: str, reputation_address: str,
                 private_key: Optional[str] = None):
        self.identity = identity_address
        self.reputation = reputation_address
        self.private_key = private_key or os.getenv("ARC_PRIVATE_KEY")
        self._next_nonce: Optional[int] = None

    @property
    def configured(self) -> bool:
        return bool(self.private_key)

    def address(self) -> Optional[str]:
        if not self.private_key:
            return None
        from eth_account import Account
        return Account.from_key(self.private_key).address

    # -- fee + nonce (same approach as the guard's sender) --

    def _fees(self) -> tuple[int, int]:
        try:
            block = rpc("eth_getBlockByNumber", ["latest", False])
            base = _to_int(block.get("baseFeePerGas", "0x0"))
        except Exception:
            base = 0
        base = max(base, MIN_BASE_FEE_WEI)
        try:
            priority = _to_int(rpc("eth_maxPriorityFeePerGas", []))
        except Exception:
            priority = DEFAULT_PRIORITY_WEI
        if priority <= 0:
            priority = DEFAULT_PRIORITY_WEI
        return base * 2 + priority, priority

    def _reserve_nonce(self, address: str) -> int:
        chain_pending = _to_int(rpc("eth_getTransactionCount", [address, "pending"]))
        if self._next_nonce is None or chain_pending > self._next_nonce:
            self._next_nonce = chain_pending
        n = self._next_nonce
        self._next_nonce += 1
        return n

    def _estimate_gas(self, frm: str, to: str, data: str) -> int:
        try:
            est = _to_int(rpc("eth_estimateGas", [{"from": frm, "to": to, "data": data}]))
            return int(est * 12 // 10)  # 20% headroom
        except Exception:
            return 300000  # safe default for a small registry write

    def _send(self, to: str, data: str) -> str:
        if not self.private_key:
            raise RuntimeError("ARC_PRIVATE_KEY not set; cannot send")
        from eth_account import Account
        from eth_utils import to_checksum_address

        acct = Account.from_key(self.private_key)
        max_fee, priority = self._fees()
        gas = self._estimate_gas(acct.address, to, data)
        nonce = self._reserve_nonce(acct.address)
        tx = {
            "to": to_checksum_address(to),
            "value": 0,
            "data": data,
            "gas": gas,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority,
            "nonce": nonce,
            "chainId": CHAIN_ID,
            "type": 2,
        }
        signed = Account.sign_transaction(tx, self.private_key)
        raw = signed.raw_transaction.hex()
        if not raw.startswith("0x"):
            raw = "0x" + raw
        try:
            return rpc("eth_sendRawTransaction", [raw])
        except Exception:
            self._next_nonce = None
            raise

    # -- high-level writes --

    def register(self, card_uri: str) -> str:
        return self._send(self.identity, abi.encode_register(card_uri))

    def update_registration(self, agent_id: int, card_uri: str) -> str:
        return self._send(self.identity, abi.encode_update_registration(agent_id, card_uri))

    def give_feedback(self, agent_id: int, score: int, tag: bytes, file_uri: str,
                      expiry: int, nonce: str, signature: str) -> str:
        data = abi.encode_give_feedback(agent_id, score, tag, file_uri, expiry, nonce, signature)
        return self._send(self.reputation, data)
