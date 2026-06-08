"""
The signature parity test: prove that a FeedbackAuth signed in Python (via eth-account's
encode_typed_data) recovers to the same signer when the digest is rebuilt EXACTLY the way
the Solidity ReputationRegistry rebuilds it on-chain.

If this passes, the on-chain `giveFeedback` will accept signatures produced by core.py. If
the typed-data and the contract ever drift apart, this test fails before any money moves.
"""
from eth_abi import encode
from eth_account import Account
from eth_keys.datatypes import Signature
from eth_utils import keccak, to_checksum_address

from registry import core

CHAIN_ID = core.ARC_CHAIN_ID
REP_CONTRACT = to_checksum_address("0x00000000000000000000000000000000000000aa")


def _contract_digest(agent_id, client, expiry, nonce_hex):
    """Reproduce ReputationRegistry's digest computation byte-for-byte."""
    domain_typehash = keccak(
        text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    domain_separator = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                domain_typehash,
                keccak(text=core.REPUTATION_DOMAIN_NAME),
                keccak(text=core.REPUTATION_DOMAIN_VERSION),
                CHAIN_ID,
                REP_CONTRACT,
            ],
        )
    )
    feedback_typehash = keccak(
        text="FeedbackAuth(uint256 agentId,address client,uint64 expiry,bytes32 nonce)")
    nonce_bytes = bytes.fromhex(nonce_hex[2:] if nonce_hex.startswith("0x") else nonce_hex)
    struct_hash = keccak(
        encode(
            ["bytes32", "uint256", "address", "uint64", "bytes32"],
            [feedback_typehash, agent_id, client, expiry, nonce_bytes],
        )
    )
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


def _recover_from_digest(digest: bytes, signature_hex: str) -> str:
    raw = bytes.fromhex(signature_hex[2:] if signature_hex.startswith("0x") else signature_hex)
    r, s, v = raw[:32], raw[32:64], raw[64]
    rec_id = v - 27 if v >= 27 else v
    sig = Signature(signature_bytes=r + s + bytes([rec_id]))
    pub = sig.recover_public_key_from_msg_hash(digest)
    return pub.to_checksum_address()


def test_python_signature_matches_contract_digest():
    agent_owner = Account.create()
    client = to_checksum_address("0x000000000000000000000000000000000000c11e")
    agent_id = 42
    expiry = 2_000_000_000
    nonce = core.new_nonce()

    # sign the way an agent owner would (the same path the MCP server uses)
    sig = core.sign_feedback_auth(
        agent_owner.key.hex(), REP_CONTRACT, agent_id, client, expiry, nonce, chain_id=CHAIN_ID)

    # rebuild the digest the way the contract does, and recover
    digest = _contract_digest(agent_id, client, expiry, nonce)
    recovered = _recover_from_digest(digest, sig)

    assert recovered.lower() == agent_owner.address.lower(), (
        "Python EIP-712 signature does not match the contract digest; "
        "giveFeedback would reject it on-chain"
    )


def test_wrong_chain_id_would_not_verify():
    agent_owner = Account.create()
    client = to_checksum_address("0x000000000000000000000000000000000000c11e")
    nonce = core.new_nonce()
    # sign with the wrong chain id
    sig = core.sign_feedback_auth(
        agent_owner.key.hex(), REP_CONTRACT, 1, client, 2_000_000_000, nonce, chain_id=1)
    # contract digest uses Arc chain id -> recovered signer differs
    digest = _contract_digest(1, client, 2_000_000_000, nonce)
    recovered = _recover_from_digest(digest, sig)
    assert recovered.lower() != agent_owner.address.lower()
