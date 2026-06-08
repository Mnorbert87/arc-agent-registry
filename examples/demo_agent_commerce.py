"""
A runnable narrative of the trust layer, with NO chain and NO keys (in-memory fakes).
Shows the exact lifecycle the real deployment follows:

  1. Alice registers an identity and lists its x402 memory-search service.
  2. Bob wants to buy. It runs the trust gate first -> Alice has no history -> NOT trusted.
  3. (In reality Bob pays via the x402 stack only if trusted; here we let the first sale
     happen, then) Alice authorizes Bob to rate it, Bob leaves a 95.
  4. Now the trust gate passes, and discovery surfaces Alice as a trusted service.

Run: python examples/demo_agent_commerce.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_account import Account  # noqa: E402

from registry import core  # noqa: E402
from registry.engine import RegistryEngine  # noqa: E402
from registry.store import Store  # noqa: E402


class FakeChain:
    """A tiny in-memory stand-in for both registries: minted agents + their feedback."""
    def __init__(self):
        self.owners = {}
        self.uris = {}
        self.summaries = {}  # agent_id -> (count, total)
        self.count = 0

    # reader surface
    def agent_count(self):
        return self.count

    def exists(self, a):
        return a in self.owners

    def owner_of(self, a):
        return self.owners[a]

    def token_uri(self, a):
        return self.uris[a]

    def get_summary(self, a):
        n, t = self.summaries.get(a, (0, 0))
        return n, t, (0 if n == 0 else t // n)


class FakeWriter:
    def __init__(self, chain, owner_key, uri_owner_addr):
        self.chain = chain
        self.private_key = owner_key
        self._addr = uri_owner_addr

    def register(self, card_uri):
        self.chain.count += 1
        aid = self.chain.count
        self.chain.owners[aid] = self._addr
        self.chain.uris[aid] = card_uri
        return f"0xREGISTER{aid:064x}"

    def give_feedback(self, agent_id, score, tag, file_uri, expiry, nonce, signature):
        n, t = self.chain.summaries.get(agent_id, (0, 0))
        self.chain.summaries[agent_id] = (n + 1, t + score)
        return f"0xFEEDBACK{agent_id:064x}"

    def address(self):
        return self._addr


def line(msg):
    print(f"  {msg}")


def main():
    alice = Account.create()
    bob = Account.create()
    rep_addr = "0x00000000000000000000000000000000000000aa"

    chain = FakeChain()
    store = Store(":memory:")

    # Alice's engine (seller: holds Alice's key)
    alice_writer = FakeWriter(chain, alice.key.hex(), alice.address)
    alice_eng = RegistryEngine(store, chain, alice_writer, reputation_address=rep_addr)

    print("\n1) Alice registers its identity and lists its x402 service")
    reg = alice_eng.register_agent(
        name="Alice", domain="alice.example", capabilities=["memory-search"],
        x402_endpoint="https://alice.example/x402/memory-search", x402_price=10000)
    aid = reg["agent_id"]
    line(f"agent_id={aid} owner={alice.address[:10]}... tx={reg['tx'][:18]}...")
    alice_eng.register_service(
        "https://alice.example/x402/memory-search", aid, 10000, core.USDC_ARC, "memory search")

    print("\n2) Bob checks Alice's reputation BEFORE paying (the gate)")
    bob_writer = FakeWriter(chain, bob.key.hex(), bob.address)
    bob_eng = RegistryEngine(store, chain, bob_writer, reputation_address=rep_addr)
    gate = bob_eng.trust_check(aid, min_score=70, min_count=1)
    line(f"trusted={gate['trusted']} (count={gate['count']}, avg={gate['average']}) -> "
         f"{'pay' if gate['trusted'] else 'no history yet, proceed with caution / small amount'}")

    print("\n3) After the paid call, Alice authorizes Bob to rate it; Bob leaves 95")
    auth = alice_eng.authorize_feedback(aid, bob.address, valid_seconds=600)
    line(f"FeedbackAuth signed by Alice: nonce={auth['nonce'][:14]}... expiry={auth['expiry']}")
    fb = bob_eng.give_feedback(aid, 95, "memory-search", auth)
    line(f"feedback on-chain: score=95 tx={fb['tx'][:18]}...")

    print("\n4) Now the gate passes and discovery surfaces Alice as trusted")
    gate2 = bob_eng.trust_check(aid)
    line(f"trusted={gate2['trusted']} (count={gate2['count']}, avg={gate2['average']})")
    found = bob_eng.discover(min_score=70, min_count=1)
    for s in found:
        line(f"DISCOVERED: {s['endpoint']} (agent {s['agent_id']}, "
             f"avg {s['reputation_average']} over {s['reputation_count']}) price={s['price']}")

    print("\nDone. This is the lifecycle the live deployment runs, with real txs on Arc.\n")
    store.close()


if __name__ == "__main__":
    main()
