# Arc Agent Registry

The trust layer for agent commerce on [Arc](https://www.arc.io), Circle's stablecoin L1
where USDC is the native gas token.

The x402 protocol already lets one AI agent pay another in USDC over HTTP. What it does not
answer is the question that comes first: **should I pay this agent at all?** This project is
the missing piece. It is an [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) aligned
identity and reputation registry deployed on Arc, plus an MCP server so any Claude Code agent
can register an on-chain identity, check a counterparty's reputation before paying, and rate
it afterwards.

ERC-8004 went live on Ethereum in January 2026. Nobody had put it on Arc. This does, and
wires it into the agent tooling.

## Where it sits

```
  buyer agent                              seller agent
  -----------                              ------------
  1. discover()         --- trusted x402 services --->
  2. trust_check(id)    --- read on-chain reputation -->   [ ReputationRegistry ]
  3. pay via x402  ------------------------------------>   (arc-x402-agent / arc-x402-server)
  4. give_feedback(id)  --- rate the seller on-chain --->  [ ReputationRegistry ]
                                                           [ IdentityRegistry  ]  <- register_agent()
```

It pairs with the existing payment stack: `arc-x402-agent` (buyer) calls `trust_check`
before `make_payment`; `arc-x402-server` (seller) hands the buyer a `FeedbackAuth` after a
paid call so the buyer can rate it.

## Contracts

- **IdentityRegistry** (`contracts/src/IdentityRegistry.sol`): a compact, dependency-free
  ERC-721. Each agent is a token; its `tokenURI` is the agent card
  (`https://<domain>/.well-known/agent-card.json`). `register(cardURI)` mints an identity.
- **ReputationRegistry** (`contracts/src/ReputationRegistry.sol`): clients leave a score
  (0-100). Feedback is gated by an EIP-712 `FeedbackAuth` the agent owner signs, so only a
  real counterparty can rate, each authorization is single-use (nonce), and the contract
  keeps an O(1) running average. EIP-2 low-s signature check, no external dependencies.

Deploy to Arc testnet (Arc requires EIP-1559, so do not pass `--legacy`):

```bash
cd contracts
forge test                      # 8 contract tests
forge script script/Deploy.s.sol:Deploy \
  --rpc-url arc_testnet --broadcast --private-key $ARC_PRIVATE_KEY
```

Put the two printed addresses into `.env`.

## Python package + MCP

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
pytest                          # 24 tests, no chain needed
python examples/demo_agent_commerce.py
```

The package mirrors the rest of the Arc stack: a pure `core` (cards, the reputation gate,
the FeedbackAuth signature), `abi`/`arc` for the chain, a `store` (SQLite index + service
directory), and an `engine` that injects chain access so the whole flow is testable with
fakes. `server.py` is the FastMCP entrypoint.

### MCP tools

| tool | side | what it does |
|------|------|--------------|
| `register_agent` | both | mint an identity, optionally list an x402 service |
| `resolve_agent` | both | owner, card URI, reputation summary |
| `trust_check` | buyer | the pre-payment gate: is this agent trustworthy enough to pay? |
| `authorize_feedback` | seller | sign a FeedbackAuth so a buyer can rate you (no tx) |
| `give_feedback` | buyer | rate a seller 0-100 using its FeedbackAuth (on-chain) |
| `register_service` / `discover` | both | the service directory, filtered by trust |

Run as an MCP server:

```bash
arc-private-key-and-addresses-in-env
python -m registry.server
```

## Security notes

- The private key is read from `ARC_PRIVATE_KEY` only, never a tool argument, and is never
  logged or returned. Use a throwaway testnet key.
- `trust_check` is read-only and never triggers a write: deciding whether to pay can never
  cost anything.
- Feedback cannot be faked: the contract verifies the agent owner's EIP-712 signature and
  rejects reused nonces. The Python signature is proven byte-for-byte equal to the contract
  digest in `tests/test_eip712_contract_parity.py`.
- A new agent with no history is **not** trusted by default. The safe stance before sending
  money is the explicit one.

## Status

Testnet. Contracts build and pass 8 Foundry tests; the Python package passes 24 tests; the
Arc testnet RPC is reachable (chain id 5042002). On-chain end-to-end (a real registration +
feedback tx with arcscan proof) needs a funded throwaway key from
[faucet.circle.com](https://faucet.circle.com).

MIT.
