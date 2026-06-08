"""
ABI encoding for the IdentityRegistry and ReputationRegistry calls.

Pure: turns Python arguments into the calldata bytes a transaction or eth_call carries,
and decodes return data back. Uses eth-abi for correct head/tail encoding of dynamic
types (string, bytes) and keccak for the 4-byte selectors. No chain access here.

The function signatures below must match the Solidity contracts character for character,
because the selector is keccak(signature)[:4]; a mismatch silently calls nothing.
"""
from __future__ import annotations

from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


# --- IdentityRegistry writes ---

def encode_register(card_uri: str) -> str:
    data = selector("register(string)") + encode(["string"], [card_uri])
    return "0x" + data.hex()


def encode_update_registration(agent_id: int, card_uri: str) -> str:
    data = selector("updateRegistration(uint256,string)") + encode(["uint256", "string"], [agent_id, card_uri])
    return "0x" + data.hex()


# --- ReputationRegistry writes ---

def encode_give_feedback(agent_id: int, score: int, tag: bytes, file_uri: str,
                         expiry: int, nonce: str, signature: str) -> str:
    sig_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
    nonce_bytes = bytes.fromhex(nonce[2:] if nonce.startswith("0x") else nonce)
    tag = (tag + b"\x00" * 32)[:32] if isinstance(tag, (bytes, bytearray)) else b"\x00" * 32
    data = selector("giveFeedback(uint256,uint8,bytes32,string,uint64,bytes32,bytes)") + encode(
        ["uint256", "uint8", "bytes32", "string", "uint64", "bytes32", "bytes"],
        [agent_id, score, tag, file_uri, expiry, nonce_bytes, sig_bytes],
    )
    return "0x" + data.hex()


def tag_to_bytes32(label: str) -> bytes:
    """Pack a short ascii label into bytes32 (right-padded), like Solidity's bytes32("x")."""
    b = label.encode()[:32]
    return b + b"\x00" * (32 - len(b))


# --- reads (eth_call) ---

def encode_owner_of(agent_id: int) -> str:
    return "0x" + (selector("ownerOf(uint256)") + encode(["uint256"], [agent_id])).hex()


def encode_token_uri(agent_id: int) -> str:
    return "0x" + (selector("tokenURI(uint256)") + encode(["uint256"], [agent_id])).hex()


def encode_exists(agent_id: int) -> str:
    return "0x" + (selector("exists(uint256)") + encode(["uint256"], [agent_id])).hex()


def encode_agent_count() -> str:
    return "0x" + selector("agentCount()").hex()


def encode_get_summary(agent_id: int) -> str:
    return "0x" + (selector("getSummary(uint256)") + encode(["uint256"], [agent_id])).hex()


# --- decoders ---

def _b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)


def decode_address(result: str) -> str:
    (addr,) = decode(["address"], _b(result))
    return to_checksum_address(addr)


def decode_string(result: str) -> str:
    (s,) = decode(["string"], _b(result))
    return s


def decode_bool(result: str) -> bool:
    (v,) = decode(["bool"], _b(result))
    return v


def decode_uint(result: str) -> int:
    (v,) = decode(["uint256"], _b(result))
    return v


def decode_summary(result: str) -> tuple[int, int, int]:
    """getSummary returns (uint64 count, uint256 total, uint256 average)."""
    n, total, average = decode(["uint64", "uint256", "uint256"], _b(result))
    return int(n), int(total), int(average)
