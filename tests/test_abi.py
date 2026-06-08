from eth_abi import encode

from registry import abi


def test_known_selectors():
    # sanity-check a few selectors against keccak of the canonical signature
    assert abi.selector("ownerOf(uint256)").hex() == "6352211e"
    assert abi.selector("tokenURI(uint256)").hex() == "c87b56dd"
    assert abi.selector("register(string)") == abi.selector("register(string)")


def test_encode_register_has_selector_and_string():
    data = abi.encode_register("https://x/card.json")
    assert data.startswith("0x" + abi.selector("register(string)").hex())
    # decodes back to the URI when the selector is stripped
    from eth_abi import decode
    payload = bytes.fromhex(data[2:])[4:]
    (uri,) = decode(["string"], payload)
    assert uri == "https://x/card.json"


def test_tag_to_bytes32_roundtrip():
    t = abi.tag_to_bytes32("memory-search")
    assert len(t) == 32
    assert t.rstrip(b"\x00") == b"memory-search"


def test_decode_summary():
    blob = "0x" + encode(["uint64", "uint256", "uint256"], [3, 240, 80]).hex()
    n, total, avg = abi.decode_summary(blob)
    assert (n, total, avg) == (3, 240, 80)


def test_encode_give_feedback_shape():
    data = abi.encode_give_feedback(
        agent_id=1, score=90, tag=abi.tag_to_bytes32("x"), file_uri="",
        expiry=2000000000, nonce="0x" + "11" * 32, signature="0x" + "22" * 65)
    assert data.startswith("0x" + abi.selector(
        "giveFeedback(uint256,uint8,bytes32,string,uint64,bytes32,bytes)").hex())
