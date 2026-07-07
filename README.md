# Base Rug Pull Early Warning

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/khlndaaa/base-rugpull-warning?style=social)](https://github.com/khlndaaa/base-rugpull-warning/stargazers)
[![Built for Base](https://img.shields.io/badge/Built%20for-Base-0052FF)](https://base.org)

A public GitHub Actions template that daily scans a list of contracts on
**Base** and computes a heuristic **risk score (0-100)** based on:

1. **Source code verification** — an unverified contract can't be
   inspected directly, which is itself a strong signal of caution.
2. **Code patterns** commonly found in scam tokens: the ability to
   blacklist specific wallets, arbitrarily change fees/limits, toggle
   trading on/off, uncapped minting, and so on.
3. **Owner status** — whether contract ownership has been renounced,
   or the deployer still has full control.
4. **Proxy/upgradeable** — whether the contract's logic could be
   swapped after deployment.

## ⚠️ Understand the limitations

- This is a **heuristic screening tool, not a security audit**. The
  presence of a "suspicious" function does not automatically mean a
  contract is a scam — many fully legitimate tokens have, for example,
  `pause()` or `mint()` for valid reasons.
- The script **does not check**: whether liquidity is locked, whether
  the token can actually be sold back (honeypot simulation), or holder
  concentration. Those require heavier infrastructure to check reliably.
- This is not financial advice. Always verify a contract manually as
  well (Basescan/Blockscout, audits, project community) before making
  any decisions involving money.

## Impact & Adoption

This tool addresses a real, common problem: scam tokens are one of the
most frequent ways new users get hurt right after coming onchain, and
most rug-detection tools today are paid SaaS products behind a signup
wall. This one is free, open-source, and self-hostable in minutes —
fork the repo, add an address, done.

- 🆓 Zero cost to run — entirely on GitHub Actions' free tier
- 🔓 No signup, no server, no vendor lock-in — just fork and go
- 🧩 Fully open-source (MIT) — read, audit, or extend the logic yourself
- ⭐ If this tool caught something useful for you, a star helps other
  people find it — and if you used it to catch a real rug attempt,
  [open an issue](../../issues) or a discussion and share what
  happened. Real-world catches will be listed here.

**Used this tool and it helped?** Open a PR adding yourself to the list
below — it helps others trust the project and helps track real-world
impact:

| Project / User | What it caught | Date |
|---|---|---|
| _add yours here_ | | |

## Quick start

### 1. Get a free Blockscout Pro API key

1. https://dev.blockscout.com/ → Login
2. Create an API key (the free tier covers Base)

### 2. Add the secret to your repository

**Settings → Secrets and variables → Actions → New repository secret**
- Name: `BLOCKSCOUT_API_KEY`
- Value: your key

### 3. Add contract addresses to `watchlist.json`

```json
[
  "0xContractAddress1",
  "0xContractAddress2"
]
```

### 4. Run it manually

**Actions → Base Rug Pull Early Warning → Run workflow**

After that it runs automatically once a day at 08:00 UTC (change the
`cron` line in `.github/workflows/scan.yml` to adjust).

## Example output

```
🔍 Scanning 1 contract(s) on Base (chainId=8453)
⚠️  This is a heuristic screening, not a security audit. Always verify manually.

=== 0xContractAddress ===
✅ Source code verified | Proxy/upgradeable: no
👤 Owner: active (0xabc...123)
🔎 Patterns found (2):
   - maxTxAmount (+5) — arbitrary transaction/balance limits
   - mint (+4) — additional token supply can be minted post-deploy
📊 Risk score: 29/100 — 🟡 LOW RISK
```

## Structure

```
.
├── watchlist.json                # contract addresses to scan
├── rugcheck.py                    # main script
├── requirements.txt
└── .github/workflows/scan.yml     # daily run + manual trigger
```

## License

MIT — use it, modify it, fork it freely.
