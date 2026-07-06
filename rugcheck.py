#!/usr/bin/env python3
"""
Base Rug Pull Early Warning (публічний шаблон).

Для кожного контракту з watchlist.json перевіряє кілька евристичних
сигналів ризику й рахує "risk score" (0-100, вище = ризикованіше):

1. Чи верифікований сорс-код (неверифікований контракт — сам по собі
   великий червоний прапорець, бо код неможливо перевірити).
2. Наявність у верифікованому сорсі функцій/патернів, які часто
   зустрічаються в шахрайських токенах (можливість блокувати конкретні
   гаманці, довільно міняти комісію/ліміти транзакції, вимикати
   торгівлю тощо).
3. Чи "зречений" власник контракту (ownership renounced) — перевіряється
   викликом owner() напряму в блокчейн.
4. Чи є контракт proxy/upgradeable — власник міг би підмінити логіку
   контракту після деплою.

ВАЖЛИВО: це евристика для попереднього орієнтиру, а не аудит безпеки.
Наявність окремої "підозрілої" функції не означає автоматично, що
контракт шахрайський — багато легітимних токенів теж мають, наприклад,
pause() чи mint(). Завжди перевіряй контракт додатково вручну і не
покладайся тільки на цей скрипт для фінансових рішень.
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

# Селектор функції owner() = keccak256("owner()")[:4]
OWNER_SELECTOR = "0x8da5cb5b"

API_KEY = os.environ.get("BLOCKSCOUT_API_KEY")
WATCHLIST_FILE = os.environ.get("WATCHLIST_FILE", "watchlist.json")

if not API_KEY:
    raise SystemExit("❌ Не заданий секрет BLOCKSCOUT_API_KEY")

# Патерни в сорс-коді, які варто відзначити. Вага — орієнтовна, не точна
# наука. Пошук — простий регістронезалежний підрядок (навмисно без
# прив'язки до меж слова, щоб не пропускати збірні назви на кшталт
# setMaxTxAmount). Список навмисно не вичерпний і не є інструкцією —
# лише перелік публічно відомих назв функцій для статичного пошуку.
SUSPICIOUS_PATTERNS = [
    ("blacklist", 8, "можливість блокувати конкретні адреси"),
    ("excludefromfee", 6, "вибіркові комісії для різних адрес"),
    ("settaxfee", 6, "комісію можна змінювати після деплою"),
    ("setfee", 6, "комісію можна змінювати після деплою"),
    ("maxtxamount", 5, "довільні ліміти на транзакції/баланс"),
    ("maxwallet", 5, "довільні ліміти на баланс гаманця"),
    ("antiwhale", 5, "штучні обмеження торгівлі"),
    ("cooldown", 5, "штучні обмеження торгівлі"),
    ("tradingenabled", 6, "торгівлю можна вмикати/вимикати вручну"),
    ("opentrading", 6, "торгівлю можна вмикати/вимикати вручну"),
    ("pause(", 5, "перекази можна повністю зупинити"),
    ("mint(", 4, "можлива додаткова емісія токенів після деплою"),
    ("selfdestruct", 7, "контракт можна знищити"),
    ("delegatecall", 5, "делегування логіки іншому контракту"),
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
            print(f"⚠️  Не вдалося отримати дані ({params.get('action')}): {e}")
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
    if not data or "result" not in data:
        return None
    raw = data["result"]
    if not raw or raw in ("0x", "0x0"):
        return None
    # результат — 32-байтне слово, адреса в останніх 20 байтах
    hex_addr = "0x" + raw[-40:]
    return hex_addr.lower()


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
    result["owner"] = owner
    if owner is not None:
        result["owner_renounced"] = owner in BURN_ADDRESSES
        if not result["owner_renounced"]:
            score += 20
    # якщо owner() не викликається (контракт без такого патерну) —
    # не штрафуємо, це просто означає, що контракт не Ownable

    result["risk_score"] = min(100, score)
    return result


def risk_label(score):
    if score >= 70:
        return "🔴 ВИСОКИЙ РИЗИК"
    if score >= 40:
        return "🟠 СЕРЕДНІЙ РИЗИК"
    if score >= 15:
        return "🟡 НИЗЬКИЙ РИЗИК"
    return "🟢 СИГНАЛІВ НЕ ЗНАЙДЕНО"


def main():
    watchlist = load_json(WATCHLIST_FILE, [])
    watchlist = [a for a in watchlist if a.lower() != PLACEHOLDER_ADDRESS]

    if not watchlist:
        print(
            f"⚠️  У {WATCHLIST_FILE} немає реальних адрес (тільки приклад-заглушка). "
            f"Додай адреси контрактів, які хочеш сканувати."
        )
        return

    print(f"🔍 Сканую {len(watchlist)} контракт(ів) у мережі Base (chainId={CHAIN_ID})")
    print("⚠️  Це евристичний скринінг, а не аудит безпеки. Перевіряй додатково вручну.")

    for address in watchlist:
        print("")
        print(f"=== {address} ===")

        r = analyze_contract(address)

        if not r["verified"]:
            print(f"❌ Сорс-код НЕ верифікований — {risk_label(r['risk_score'])} ({r['risk_score']}/100)")
            print("   Неможливо перевірити логіку контракту напряму.")
            continue

        print(f"✅ Сорс-код верифікований | Proxy/upgradeable: {'так' if r['is_proxy'] else 'ні'}")

        if r["owner"] is not None:
            status = "зречений (renounced)" if r["owner_renounced"] else f"активний ({r['owner']})"
            print(f"👤 Власник: {status}")
        else:
            print("👤 Власник: функція owner() відсутня або не Ownable-контракт")

        if r["findings"]:
            print(f"🔎 Знайдені патерни ({len(r['findings'])}):")
            for name, weight, desc in r["findings"]:
                print(f"   - {name} (+{weight}) — {desc}")
        else:
            print("🔎 Підозрілих патернів у сорс-коді не знайдено")

        print(f"📊 Risk score: {r['risk_score']}/100 — {risk_label(r['risk_score'])}")


if __name__ == "__main__":
    main()
