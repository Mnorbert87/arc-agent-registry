# Security audit — arc-agent-registry contracts

**Date:** 2026-06-08
**Auditor:** Forge (adversarial test suite + self-audit, 2026-06-08)
**Scope:** `IdentityRegistry.sol`, `ReputationRegistry.sol`, `JobEscrow.sol`
**Method:** manual review of every trust-critical path + an adversarial Foundry suite
(unit, fuzz, reentrancy attacker contract, and a stateful solvency invariant).
**Tooling note:** no key required — everything here runs locally. Only testnet deploy needs a key.

## Result

**52 tests, 0 failures.** The solvency invariant survived **128,000** random calls with **0 reverts**.

| Suite | Tests | What it proves |
|-------|-------|----------------|
| `Registry.t.sol` | 10 | identity ownership, EIP-712 feedback auth, replay/expiry/score bounds, **signature malleability rejection**, **cross-agent replay rejection** |
| `JobEscrow.t.sol` | 26 | full lifecycle, access control, state machine, fee-on-transfer accounting, non-bool tokens, **reentrancy (CEI + mutex)** |
| `JobEscrowInvariant.t.sol` | 1 | escrow USDC balance **always equals** funds still owed (no over/under-payment, no fund extraction) |
| `Adversarial.t.sol` | 15 | **(Forge re-audit)** self-feedback inflation rejected, forged/short/zero/bad-`v` signatures rejected, auth dead after identity transfer, reentrancy on **refund/claim** + **cross-function** release→refund, claim-boundary strictness, post-terminal state locks |

## Forge fresh adversarial re-audit (2026-06-08)

Re-attacked all three contracts independently. One real defect found and fixed; 14 other
attack vectors held.

### F1 (Medium) — `ReputationRegistry`: agent owner could self-inflate reputation — **FIXED**

The agent owner holds the EIP-712 signing key **and** can be the `client`. Nothing stopped the
owner from signing a `FeedbackAuth` naming **itself** and calling `giveFeedback` to mint an
unbounded, self-issued perfect score with fresh nonces — defeating the registry's stated
anti-fake-review purpose. This is stronger than residual risk R1 (cherry-picking *third-party*
reviewers): it needs no second party at all.

- **PoC:** `test_Attack_SelfFeedbackInflationBlocked` (failed pre-fix: the call did not revert).
- **Fix:** `require(msg.sender != identity.ownerOf(agentId), "self feedback");` in `giveFeedback`.
  A legitimate third-party client is unaffected (`test_LegitClientStillWorks`).
- **Impact of fix:** `ReputationRegistry` bytecode changed → redeployed to Arc (see *Deployed
  addresses*). `IdentityRegistry` and `JobEscrow` were byte-identical and **not** redeployed.

### Held under fresh attack (no change needed)

- Reentrancy on **every** money path — `refund`, `claim`, and **cross-function** (re-enter
  `refund(B)` from inside `release(A)`) — all blocked by the global mutex.
- Signature hardening: forged signer, 64-byte truncated sig, all-zero sig, and out-of-range
  `v` (29) all revert; high-`s` malleability already covered.
- Stale-authority: a `FeedbackAuth` signed by the old owner is dead after the identity NFT is
  transferred (`ownerOf` recheck at call time).
- State-machine locks: claim is strict `>` at the review-window boundary; no claim without
  submit; no refund after submit; all actions dead after a terminal state.

## Confirmed defenses (attempted to break, could not)

1. **Reentrancy.** `JobEscrow` uses Checks-Effects-Interactions (status moved to a terminal
   state *before* any token transfer) plus a global non-reentrancy mutex. A malicious token
   that re-enters `release()` during payout is blocked on both layers — proven by
   `test_ReentrancySameJobBlockedNoDoublePay` (no double pay) and
   `test_ReentrancyOtherJobNotDrained` (a second job's funds stay locked).
2. **Signature malleability (EIP-2).** `ReputationRegistry._recover` rejects high-`s`
   signatures and non-{27,28} `v`. Forging the `s' = n − s` counterpart of a valid signature
   is rejected — `test_FeedbackRejectsMalleableSignature`.
3. **Feedback replay.** Single-use nonce per `(agentId, nonce)`; the same auth cannot be used
   twice, and an auth for agent A cannot be replayed on agent B (agentId is bound into the
   signed struct).
4. **Payment accounting.** Escrow custody is measured by **balance delta**, so a
   fee-on-transfer token can never make a job claim to hold more than it actually received —
   `test_FeeOnTransferEscrowsActualReceived`.
5. **Fund safety / no admin.** No owner, no pause, no upgrade. Funds only move along each
   job's own state machine; the deployer cannot touch escrowed funds.
6. **Liveness.** A silent client cannot lock a provider's payment forever (`claim()` after a
   review window); a non-delivering provider cannot lock a client's funds forever
   (`refund()` after the deadline).

## Residual risks — by design, not code bugs (documented, not "broken")

- **R1 — Reputation is self-selected.** An agent owner only signs `FeedbackAuth` for clients
  it chooses, so only favorable reviews tend to land. This is the ERC-8004 model; treat
  reputation as *advisory*, and ideally only issue a `FeedbackAuth` automatically on a
  **settled** payment (tie it to `JobEscrow` completion). *(The blatant sub-case — the owner
  rating itself — is now a hard revert; see F1.)*
- **R2 — Identity transfer carries reputation.** Reputation is keyed by `agentId`; selling/
  transferring the identity NFT carries its score to the new owner (reputation-laundering
  vector). Mitigation if it matters: reset or epoch aggregates on `Transfer`.
- **R3 — `block.timestamp` dependence.** Deadlines/review windows use `block.timestamp`
  (±~15s validator influence). Irrelevant at the day-scale windows intended here. (Lint flags
  this; it is intentional.)
- **R4 — Immutable EIP-712 domain.** `DOMAIN_SEPARATOR` caches `block.chainid` at deploy.
  Fine on a single chain; if Arc testnet ever hard-forks its chainId, redeploy. Low risk.
- **R5 — Off-chain deliverable.** `submit()` stores a `bytes32` digest only; the contract
  cannot judge work quality. That is the client's (or a future evaluator's) job — out of
  scope for the escrow primitive.

## Not testable without a key (deferred to testnet)

- Real Arc USDC (`0x3600…`) ERC-20 behavior and gas-in-USDC mechanics.
- Live EIP-1559 type-2 broadcast and on-chain event indexing.
- End-to-end x402 settle → FeedbackAuth → reputation flow against deployed addresses.

## Verdict

The three contracts are **safe to deploy to Arc testnet.** Every payout path is reentrancy-
and double-spend-resistant, the cryptography rejects malleable and replayed signatures, and
the solvency invariant holds under heavy fuzzing. After the Forge re-audit, the one real defect
(F1, self-feedback inflation) is fixed and the fixed `ReputationRegistry` is live on Arc. The
remaining items (R1–R5) are economic/design properties to decide on, not exploitable code
defects. Next step: wire reputation issuance to settled escrow completions (closes R1).

## Deployed addresses (Arc testnet, chainId 5042002)

| Contract | Address | Status |
|----------|---------|--------|
| `IdentityRegistry` | `0x899E0679F011643C3A4480cd77913B7871eaC8dB` | unchanged |
| `ReputationRegistry` | `0x1b647F2B25957e8eDD828C55e37b4777Aa15aed0` | **redeployed (F1 fix), 2026-06-08** |
| `JobEscrow` | `0x2c3EC2158312AC1D494044501E9A52aAABb07a43` | unchanged |

Previous `ReputationRegistry` (`0x65B1D3c5B8De41315C3c10B5E89E90C05f7D40C7`) is **stale** — it
lacks the F1 fix; do not use it. Deployer: `0x2e36F4037E711e1d4c853BBCBF7F526B3714A08a`.
Redeploy tx: `0x7e7ad40e8048ea42ea508e155e1b3450a7cdcbed02cb183471ea8b139387a873`.
