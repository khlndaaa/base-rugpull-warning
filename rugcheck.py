#!/usr/bin/env python3
"""
Base Rug Pull Early Warning (public template).

For every contract in watchlist.json, checks a handful of heuristic risk
signals and computes a "risk score" (0-100, higher = riskier):

1. Whether the source code is verified (an unverified contract is itself
   a big red flag, since its logic cannot be audited).
2. Presence of code patterns commonly found in scam tokens (ability to
   blacklist specific wallets, arbitrarily change fees/limits, toggle
   trading on/off, etc.).
3. Whether contract ownership has been renounced — checked with a direct
   owner() call against the chain.
4. Whether the contract is a proxy/upgradeable contract — the owner
   could swap the logic after deployment.

IMPORTANT: this is a heuristic screening tool, not a security audit.
The presence of a single "suspicious" function does not automatically
mean a contract is malicious — many fully legitimate tokens also have,
for example, pause() or mint() for valid reasons. Always verify a
contract manually as well, and never rely solely on this script for
financial decisions.
"""

import os
import json
import requests

CHAIN_ID = 8453  # Base mainnet
BLOCKSCOUT_URL = "https://api.blockscout.com/v2/api"

PLACEHOLDER_ADDRESS = "0x0000000000000000000000000000000000000000"
BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# Function selector for owner() = keccak256("owner()")[:4]
OWNER_SELECTOR = "0x8da5cb5b"

API_KEY = os.environ.get("BLOCKSCOUT_API_KEY")
WATCHLIST_FILE = os.environ.get("WATCHLIST_FILE", "watchlist.json")

if not API_KEY:
    raise SystemExit("❌ BLOCKSCOUT_API_KEY secret is not set")

# Patterns worth flagging in the source code. Weights are approximate,
# not an exact science. Matching is a simple case-insensitive substring
# search (deliberately without word-boundary anchors, so combined names
# like setMaxTxAmount are still caught). The list is intentionally not
# exhaustive and is not an exploit guide — it's just a set of publicly
# known function names used for static text search.
SUSPICIOUS_PATTERNS = [
    ("blacklist", 8, "ability to block specific addresses"),
    ("excludefromfee", 6, "selective fees for different addresses"),
    ("settaxfee", 6, "fees can be changed after deployment"),
    ("setfee", 6, "fees can be changed after deployment"),
    ("maxtxamount", 5, "arbitrary transaction/balance limits"),
    ("maxwallet", 5, "arbitrary wallet balance limits"),
    ("antiwhale", 5, "artificial trading restrictions"),
    ("cooldown", 5, "artificial trading restrictions"),
    ("tradingenabled", 6, "trading can be manually toggled on/off"),
    ("opentrading", 6, "trading can be manually toggled on/off"),
    ("pause(", 5, "transfers can be fully halted"),
    ("mint(", 4, "additional token supply can be minted post-deploy"),
    ("selfdestruct", 7, "the contract can be destroyed"),
    ("delegatecall", 5, "logic can be delegated to another contract"),
]


def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def api_get(params, retries=2):
    query = {"chainid": CHAIN_ID, "apikey": API_KEY, **params}
    for attempt in range(retries + 1):
        try:
            resp = requests.get(BLOCKSCOUT_URL, params=query, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                continue
            print(f"⚠️  Failed to fetch data ({params.get('action')}): {e}")
            return None


def get_source_code(address):
    data = api_get({"module": "contract", "action": "getsourcecode", "address": address})
    if not data or data.get("status") != "1":
        return None
    result = data.get("result")
    if isinstance(result, list) and result:
        return result[0]
    return None


def get_owner_address(address):
    data = api_get({
        "module": "proxy",
        "action": "eth_call",
        "to": address,
        "data": OWNER_SELECTOR,
        "tag": "latest",
    })
    if not data:
        return "error"
    if "result" not in data or not data["result"] or data["result"] in ("0x", "0x0"):
        return None
    raw = data["result"]
    # result is a 32-byte word; the address is in the last 20 bytes
    return "0x" + raw[-40:].lower()


def scan_source_for_patterns(source_code):
    findings = []
    score = 0
    lowered = source_code.lower()
    for pattern, weight, description in SUSPICIOUS_PATTERNS:
        if pattern in lowered:
            findings.append((pattern.rstrip("("), weight, description))
            score += weight
    return findings, min(30, score)


def analyze_contract(address):
    result = {
        "address": address,
        "verified": False,
        "is_proxy": False,
        "owner": None,
        "owner_renounced": None,
        "findings": [],
        "risk_score": 0,
    }

    contract = get_source_code(address)

    if not contract or not contract.get("SourceCode"):
        result["risk_score"] = 40
        return result

    result["verified"] = True
    result["is_proxy"] = contract.get("Proxy") == "1"

    findings, pattern_score = scan_source_for_patterns(contract["SourceCode"])
    result["findings"] = findings

    score = pattern_score
    if result["is_proxy"]:
        score += 10

    owner = get_owner_address(address)
    if owner == "error":
        result["owner"] = "error"
    else:
        result["owner"] = owner
        if owner is not None:
            result["owner_renounced"] = owner in BURN_ADDRESSES
            if not result["owner_renounced"]:
                score += 20
        # if owner() isn't callable (contract without that pattern) —
        # don't penalize, it simply means the contract isn't Ownable

    result["risk_score"] = min(100, score)
    return result


def risk_label(score):
    if score >= 70:
        return "🔴 HIGH RISK"
    if score >= 40:
        return "🟠 MEDIUM RISK"
    if score >= 15:
        return "🟡 LOW RISK"
    return "🟢 NO SIGNALS FOUND"


def main():
    watchlist = load_json(WATCHLIST_FILE, [])
    watchlist = [a for a in watchlist if a.lower() != PLACEHOLDER_ADDRESS]

    if not watchlist:
        print(
            f"⚠️  {WATCHLIST_FILE} has no real addresses (only the example placeholder). "
            f"Add the contract addresses you want to scan."
        )
        return

    print(f"🔍 Scanning {len(watchlist)} contract(s) on Base (chainId={CHAIN_ID})")
    print("⚠️  This is a heuristic screening, not a security audit. Always verify manually.")

    for address in watchlist:
        print("")
        print(f"=== {address} ===")

        r = analyze_contract(address)

        if not r["verified"]:
            print(f"❌ Source code is NOT verified — {risk_label(r['risk_score'])} ({r['risk_score']}/100)")
            print("   Contract logic cannot be inspected directly.")
            continue

        print(f"✅ Source code verified | Proxy/upgradeable: {'yes' if r['is_proxy'] else 'no'}")

        if r["owner"] == "error":
            print("👤 Owner: could not be checked (temporary API error)")
        elif r["owner"] is not None:
            status = "renounced" if r["owner_renounced"] else f"active ({r['owner']})"
            print(f"👤 Owner: {status}")
        else:
            print("👤 Owner: owner() function absent or contract isn't Ownable")

        if r["findings"]:
            print(f"🔎 Patterns found ({len(r['findings'])}):")
            for name, weight, desc in r["findings"]:
                print(f"   - {name} (+{weight}) — {desc}")
        else:
            print("🔎 No suspicious patterns found in the source code")

        print(f"📊 Risk score: {r['risk_score']}/100 — {risk_label(r['risk_score'])}")


if __name__ == "__main__":
    main()
