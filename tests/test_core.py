from registry import core


def test_well_known_card_url():
    assert core.well_known_card_url("alice.example") == "https://alice.example/.well-known/agent-card.json"
    assert core.well_known_card_url("https://x.io/") == "https://x.io/.well-known/agent-card.json"


def test_build_and_validate_card_with_payment():
    card = core.build_agent_card(
        name="Alice", domain="alice.example", description="memory search",
        capabilities=["memory-search"], x402_endpoint="https://alice.example/x402/search",
        x402_price=10000,
    )
    ok, reason = core.validate_agent_card(card)
    assert ok, reason
    assert card["payment"]["protocol"] == "x402"
    assert card["payment"]["price"] == "10000"
    assert card["registrations"][0]["network"] == "eip155:5042002"


def test_validate_rejects_bad_card():
    ok, _ = core.validate_agent_card({"name": "no url"})
    assert not ok
    ok, _ = core.validate_agent_card(
        {"name": "x", "url": "u", "payment": {"protocol": "paypal", "endpoint": "e"}})
    assert not ok


def test_reputation_average_floor():
    s = core.ReputationSummary(agent_id=1, count=3, total=80 + 80 + 61)  # 221/3 = 73.67
    assert s.average == 73
    assert core.ReputationSummary(1, 0, 0).average == 0


def test_should_trust_gate():
    # new agent, no history -> not trusted
    assert core.should_trust(core.ReputationSummary(1, 0, 0)) is False
    # one good review meets default gate (min_count=1, min_score=70)
    assert core.should_trust(core.ReputationSummary(1, 1, 90)) is True
    # two reviews averaging 90 -> trusted; averaging 30 -> not
    assert core.should_trust(core.ReputationSummary(1, 2, 180)) is True
    assert core.should_trust(core.ReputationSummary(1, 2, 60)) is False  # avg 30
    # custom thresholds
    assert core.should_trust(core.ReputationSummary(1, 1, 90), min_count=3) is False


def test_feedback_auth_sign_and_recover_roundtrip():
    from eth_account import Account
    acct = Account.create()
    rep = "0x1111111111111111111111111111111111111111"
    nonce = core.new_nonce()
    sig = core.sign_feedback_auth(acct.key.hex(), rep, agent_id=7,
                                  client="0x2222222222222222222222222222222222222222",
                                  expiry=2000000000, nonce=nonce)
    recovered = core.recover_feedback_auth_signer(
        rep, 7, "0x2222222222222222222222222222222222222222", 2000000000, nonce, sig)
    assert recovered.lower() == acct.address.lower()


def test_feedback_auth_changing_client_breaks_recovery():
    from eth_account import Account
    acct = Account.create()
    rep = "0x1111111111111111111111111111111111111111"
    nonce = core.new_nonce()
    sig = core.sign_feedback_auth(acct.key.hex(), rep, 7,
                                  "0x2222222222222222222222222222222222222222", 2000000000, nonce)
    # recover with a different client address -> not the signer
    other = core.recover_feedback_auth_signer(
        rep, 7, "0x3333333333333333333333333333333333333333", 2000000000, nonce, sig)
    assert other.lower() != acct.address.lower()
