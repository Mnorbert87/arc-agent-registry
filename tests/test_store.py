import pytest

from registry.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    yield s
    s.close()


def test_upsert_and_get_agent(store):
    store.upsert_agent(1, "0xowner", "Alice", "alice.example",
                       "https://alice.example/card.json", ["memory-search"], "0xtx")
    a = store.get_agent(1)
    assert a["name"] == "Alice"
    assert a["tx_hash"] == "0xtx"
    # update in place
    store.upsert_agent(1, "0xowner", "Alice", "alice.example",
                       "https://alice.example/card2.json", ["memory-search"], "0xtx2")
    assert store.get_agent(1)["card_uri"].endswith("card2.json")
    assert len(store.list_agents()) == 1


def test_record_feedback_requires_tx(store):
    with pytest.raises(ValueError):
        store.record_feedback(1, "0xclient", 90, "x", "")
    store.record_feedback(1, "0xclient", 90, "memory-search", "0xtx")
    fb = store.feedback_for(1)
    assert len(fb) == 1 and fb[0]["score"] == 90


def test_services_directory(store):
    store.add_service("https://alice/x402/search", 1, 10000, "0x3600...", "memory search")
    store.add_service("https://rendezo/x402/render", 2, 50000, "0x3600...", "video render")
    assert len(store.list_services()) == 2
    svc = store.get_service("https://alice/x402/search")
    assert svc["agent_id"] == 1 and svc["price"] == 10000
    # upsert same endpoint updates price
    store.add_service("https://alice/x402/search", 1, 20000, "0x3600...", "memory search")
    assert store.get_service("https://alice/x402/search")["price"] == 20000
