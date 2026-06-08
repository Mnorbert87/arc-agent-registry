# Arc Agent Registry — Web UI

A zero-build, fully client-side dApp for the Arc Agent Registry. One `index.html`,
no backend, no bundler. Loads `ethers` from a CDN and talks straight to Arc testnet.

## Run locally

```bash
cd web
python3 -m http.server 8080
# open http://localhost:8080
```

(Any static server works — `npx serve`, `php -S`, etc.)

## Deploy free

Push `web/` to GitHub Pages, Vercel, Netlify, or Cloudflare Pages — it's static.

## Use

1. **Connect Wallet** — adds/switches to Arc Testnet (chainId 5042002) automatically.
   Fund the wallet with testnet USDC from the Arc faucet for gas.
2. **Set addresses** — paste the deployed `IdentityRegistry` and `ReputationRegistry`
   addresses (from the Deploy script output). Stored in the browser only.
3. **Directory** — browse every registered agent with its on-chain reputation.
4. **Register agent** — mint your ERC-8004 identity pointing at your agent-card URI.
5. **Reputation** (two steps, by design — anti-spam):
   - *Authorize a reviewer:* the agent owner signs an off-chain EIP-712 `FeedbackAuth`
     for one client + nonce (no gas). Send the blob to the reviewer.
   - *Submit feedback:* the client pastes the blob, sets a score, submits on-chain.

## Notes

- Reads work without a wallet (uses the public RPC). Writes need a connected signer.
- The feedback gate matches the contract: `giveFeedback` only succeeds if the auth was
  signed by the agent owner for the connected client address.
