"""
End-to-end flow with fake chain access: no RPC, no real money. Pins the two safety
guarantees: the trust gate never writes, and the store never records an unconfirmed write.
"""
import pytest

from registry import core
from registry.engine import RegistryEngine
from registry.store import Store


class FakeReader:
    def __init__(self):
        self.summaries: dict[int, tuple[int, int]] = {}  # agent_id -> (count, total)
        self._count = 0
        self._owners: dict[int, str] = {}
        self._uris: dict[int, str] = {}

    def set_summary(self, agent_id, count, total):
        self.summaries[agent_id] = (count, total)

    def add_agent(self, agent_id, owner, uri):
        self._count = max(self._count, agent_id)
        self._owners[agent_id] = owner
        self._uris[agent_id] = uri

    def agent_count(self):
        return self._count

    def exists(self, agent_id):
        return agent_id in self._owners

    def owner_of(self, agent_id):
        return self._owners[agent_id]

    def token_uri(self, agent_id):
        return self._uris[agent_id]

    def get_summary(self, agent_id):
        n, total = self.summaries.get(agent_id, (0, 0))
        return n, total, (0 if n == 0 else total // n)


class FakeWriter:
    """Returns a tx when ok, None when not. Records calls so we can assert the gate
    never touches it."""
    def __init__(self, ok=True, private_key=None, addr="0xA0Ce00000000000000000000000000000000A0Ce"):
        self.ok = ok
        self.private_key = private_key
        self._addr = addr
        self.calls: list[str] = []

    def register(self, card_uri):
        self.calls.append("register")
        return "0xregtx" if self.ok else None

    def give_feedback(self, *a, **k):
        self.calls.append("give_feedback")
        return "0xfbtx" if self.ok else None

    def address(self):
        return self._addr


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "e.db"))
    yield s
    s.close()


def test_register_agent_records_only_on_tx(store):
    reader = FakeReader()
    reader._count = 0
    # writer succeeds: after the "mint", count becomes 1
    writer = FakeWriter(ok=True)

    def register(uri):
        reader._count += 1  # simulate the on-chain mint advancing the count
        return FakeWriter.register(writer, uri)
    writer.register = register

    eng = RegistryEngine(store, reader, writer, reputation_address="0xRep")
    res = eng.register_agent("Alice", "alice.example", ["memory-search"],
                             x402_endpoint="https://alice.example/x402/search", x402_price=10000)
    assert res["ok"] and res["agent_id"] == 1
    assert store.get_agent(1)["name"] == "Alice"


def test_register_agent_no_tx_no_record(store):
    reader = FakeReader()
    writer = FakeWriter(ok=False)  # write returns None
    eng = RegistryEngine(store, reader, writer, "0xRep")
    res = eng.register_agent("Ghost", "ghost.example")
    assert not res["ok"]
    assert store.list_agents() == []


def test_trust_check_never_calls_writer(store):
    reader = FakeReader()
    reader.set_summary(5, count=0, total=0)  # no history
    writer = FakeWriter(ok=True)
    eng = RegistryEngine(store, reader, writer, "0xRep")

    res = eng.trust_check(5, min_score=70, min_count=1)
    assert res["trusted"] is False
    assert writer.calls == []  # the gate must not write anything

    reader.set_summary(5, count=2, total=180)  # avg 90
    res2 = eng.trust_check(5)
    assert res2["trusted"] is True and res2["average"] == 90
    assert writer.calls == []


def test_give_feedback_records_only_on_tx(store):
    reader = FakeReader()
    writer = FakeWriter(ok=True)
    eng = RegistryEngine(store, reader, writer, "0xRep")
    auth = {"expiry": 2000000000, "nonce": core.new_nonce(), "signature": "0x" + "22" * 65}
    res = eng.give_feedback(3, 95, "memory-search", auth)
    assert res["ok"] and res["tx"] == "0xfbtx"
    assert store.feedback_for(3)[0]["score"] == 95

    writer2 = FakeWriter(ok=False)
    eng2 = RegistryEngine(store, reader, writer2, "0xRep")
    res2 = eng2.give_feedback(3, 95, "memory-search", auth)
    assert not res2["ok"]
    assert len(store.feedback_for(3)) == 1  # nothing new recorded


def test_give_feedback_rejects_bad_score(store):
    eng = RegistryEngine(store, FakeReader(), FakeWriter(), "0xRep")
    res = eng.give_feedback(1, 150, "x", {"expiry": 1, "nonce": "0x00", "signature": "0x00"})
    assert not res["ok"]


def test_authorize_feedback_needs_key(store):
    rep = "0x00000000000000000000000000000000000000aa"
    client = "0x000000000000000000000000000000000000c11e"
    eng = RegistryEngine(store, FakeReader(), FakeWriter(private_key=None), rep)
    assert eng.authorize_feedback(1, client)["ok"] is False

    from eth_account import Account
    acct = Account.create()
    eng2 = RegistryEngine(store, FakeReader(), FakeWriter(private_key=acct.key.hex()), rep)
    auth = eng2.authorize_feedback(1, client)
    assert auth["ok"] and auth["signature"].startswith("0x")


def test_discover_filters_by_trust(store):
    reader = FakeReader()
    reader.set_summary(1, count=2, total=180)  # avg 90 -> trusted
    reader.set_summary(2, count=0, total=0)    # no history -> not trusted
    store.add_service("https://alice/x402/search", 1, 10000, core.USDC_ARC, "memory")
    store.add_service("https://new/x402/thing", 2, 5000, core.USDC_ARC, "new agent")

    eng = RegistryEngine(store, reader, FakeWriter(), "0xRep")
    trusted = eng.discover(min_score=70, min_count=1)
    assert [s["agent_id"] for s in trusted] == [1]
    assert trusted[0]["reputation_average"] == 90
