import hashlib
import requests
import os

# ── STEP A: Load rockyou.txt ──────────────────────────────────────
def load_rockyou():
    path = "rockyou.txt"

    if not os.path.exists(path):
        print("[!] rockyou.txt not found in this folder.")
        print("    Download it and place it here:", os.getcwd())
        return set()

    print("[*] Loading rockyou.txt — this takes a few seconds...")
    with open(path, "r", encoding="latin-1") as f:
        wordlist = {line.strip() for line in f}

    print(f"[+] Loaded {len(wordlist):,} passwords successfully!\n")
    return wordlist


# ── STEP B: Check against rockyou ────────────────────────────────
def check_rockyou(password: str, wordlist: set) -> dict:
    if not wordlist:
        return {"checked": False, "found": False, "reason": "Wordlist not loaded"}

    found = password in wordlist
    return {
        "checked": True,
        "found":   found,
        "message": "COMPROMISED — found in rockyou.txt!" if found
                   else "Safe — not in rockyou.txt.",
    }


# ── STEP C: Check against Have I Been Pwned API ───────────────────
# How it works:
#   1. Hash your password using SHA-1
#   2. Send only the FIRST 5 characters of the hash to HIBP
#   3. HIBP sends back ~800 hashes that start with those 5 chars
#   4. You search through them locally for your full hash
#   5. Your actual password NEVER leaves your computer — privacy safe!

def check_hibp(password: str) -> dict:
    # Step C1 — hash the password
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    prefix = sha1_hash[:5]   # first 5 chars → sent to server
    suffix = sha1_hash[5:]   # rest → checked locally, never sent

    print(f"  [*] SHA-1 prefix sent to HIBP : {prefix}")
    print(f"  [*] Suffix checked locally    : {suffix[:10]}...")

    # Step C2 — call the API
    try:
        url = "https://api.pwnedpasswords.com/range/" + prefix
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        return {"checked": False, "found": False, "count": 0, "reason": "No internet connection"}
    except requests.exceptions.Timeout:
        return {"checked": False, "found": False, "count": 0, "reason": "Request timed out"}

    # Step C3 — search for our suffix in the response
    for line in response.text.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return {
                "checked": True,
                "found":   True,
                "count":   int(count),
                "message": f"COMPROMISED — seen {int(count):,} times in real breaches!",
            }

    return {
        "checked": True,
        "found":   False,
        "count":   0,
        "message": "Safe — not found in any breach database.",
    }


# ── STEP D: Run everything ────────────────────────────────────────
def check_password(password, wordlist):
    print(f"\n{'='*45}")
    print(f"  Checking: {'*' * len(password)}  ({len(password)} chars)")
    print(f"{'='*45}")

    rockyou_result = check_rockyou(password, wordlist)
    print(f"  RockYou : {rockyou_result['message'] if rockyou_result['checked'] else rockyou_result['reason']}")

    print(f"  HIBP    : checking...", end="\r")
    hibp_result = check_hibp(password)
    print(f"  HIBP    : {hibp_result['message'] if hibp_result['checked'] else hibp_result['reason']}          ")

    if rockyou_result.get("found") or hibp_result.get("found"):
        print(f"\n  ⚠  VERDICT: DO NOT USE THIS PASSWORD")
    else:
        print(f"\n  ✓  VERDICT: Password not found in known breaches")

    print(f"{'='*45}\n")


if __name__ == "__main__":
    # Load the wordlist once
    wordlist = load_rockyou()

    # Test passwords
    passwords_to_test = [
        "password",
        "123456",
        "P@ssw0rd",
        "xK#9mQv!2nLp@8rT",
    ]

    for pwd in passwords_to_test:
        check_password(pwd, wordlist)