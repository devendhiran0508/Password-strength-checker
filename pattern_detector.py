import re


# ── 1. Keyboard walk detection ────────────────────────────────────────────────
# These are sequences that are easy to type but easy to guess

KEYBOARD_WALKS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",   # horizontal rows
    "qwerty", "asdfgh", "zxcvbn",            # common subsets
    "qazwsx", "wsxedc", "edcrfv",            # diagonal walks
    "1234567890", "0987654321",              # number rows
    "abcdefghijklmnopqrstuvwxyz",            # alphabet walk
]

def detect_keyboard_walk(password: str) -> list:
    """Find any keyboard walk sequences of 4+ characters."""
    found = []
    pwd_lower = password.lower()

    for walk in KEYBOARD_WALKS:
        # check forward
        for i in range(len(walk) - 3):
            chunk = walk[i:i+4]              # 4-char sliding window
            if chunk in pwd_lower:
                found.append(f"Keyboard walk detected: '{chunk}'")

        # check reverse
        reversed_walk = walk[::-1]
        for i in range(len(reversed_walk) - 3):
            chunk = reversed_walk[i:i+4]
            if chunk in pwd_lower:
                found.append(f"Reverse keyboard walk detected: '{chunk}'")

    return list(set(found))                  # remove duplicates


# ── 2. Repeated character detection ──────────────────────────────────────────
def detect_repeated_chars(password: str) -> list:
    """Detect 3+ repeated characters in a row like 'aaa' or '111'."""
    found = []
    matches = re.findall(r"(.)\1{2,}", password)   # same char 3+ times
    for match in matches:
        found.append(f"Repeated characters detected: '{match * 3}'")
    return found


# ── 3. Leet-speak detection ───────────────────────────────────────────────────
# Attackers use dictionaries that automatically try leet substitutions.
# So p@ssw0rd is just as guessable as password to a modern cracker.

LEET_MAP = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "2": "z",
}

COMMON_WORDS = [
    "password", "hello", "welcome", "admin", "login",
    "user", "letmein", "monkey", "dragon", "master",
    "shadow", "sunshine", "princess", "football", "baseball",
]

def decode_leet(password: str) -> str:
    """Convert leet-speak back to plain text."""
    decoded = password.lower()
    for leet_char, real_char in LEET_MAP.items():
        decoded = decoded.replace(leet_char, real_char)
    return decoded

def detect_leet_speak(password: str) -> list:
    """Check if password is just a common word with leet substitutions."""
    found = []
    decoded = decode_leet(password)

    for word in COMMON_WORDS:
        if word in decoded:
            found.append(
                f"Leet-speak of common word detected: "
                f"'{password}' decodes to contain '{word}'"
            )
    return found


# ── 4. Common endings detection ───────────────────────────────────────────────
# Adding 1, 123, or ! at the end is the most predictable habit

COMMON_ENDINGS = ["1", "12", "123", "1234", "!", "!!", "123!", "2024", "2025"]

def detect_common_endings(password: str) -> list:
    """Detect predictable suffixes people add to weak passwords."""
    found = []
    for ending in COMMON_ENDINGS:
        if password.endswith(ending) and len(password) > len(ending):
            found.append(f"Predictable ending detected: '...{ending}'")
    return found


# ── 5. Repeated pattern detection ────────────────────────────────────────────
def detect_repeated_patterns(password: str) -> list:
    """Detect if the password is just a short pattern repeated."""
    found = []
    length = len(password)

    for pattern_len in range(2, length // 2 + 1):
        pattern = password[:pattern_len]
        if pattern * (length // pattern_len) == password[:pattern_len * (length // pattern_len)]:
            if len(pattern) < length:
                found.append(f"Repeated pattern detected: '{pattern}' repeated")
                break

    return found


# ── 6. Master function — run all checks ──────────────────────────────────────
def detect_patterns(password: str) -> dict:
    """
    Run all pattern checks and return findings + a penalty score.
    Each detected weakness reduces score by 15 points (max penalty: 60).
    """
    all_findings = []

    all_findings += detect_keyboard_walk(password)
    all_findings += detect_repeated_chars(password)
    all_findings += detect_leet_speak(password)
    all_findings += detect_common_endings(password)
    all_findings += detect_repeated_patterns(password)

    penalty = min(len(all_findings) * 15, 60)   # max 60 point deduction

    return {
        "findings":     all_findings,
        "penalty":      penalty,
        "clean":        len(all_findings) == 0,
    }


# ── 7. Pretty printer ─────────────────────────────────────────────────────────
def print_pattern_result(password: str, result: dict) -> None:
    print(f"\n{'─'*45}")
    print(f"  Password : {'*' * len(password)}  ({len(password)} chars)")

    if result["clean"]:
        print(f"  ✓  No weak patterns detected!")
    else:
        print(f"  ⚠  {len(result['findings'])} pattern(s) found "
              f"(penalty: -{result['penalty']} pts):\n")
        for finding in result["findings"]:
            print(f"     • {finding}")

    print(f"{'─'*45}")


# ── 8. Demo ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_passwords = [
        "qwerty123",        # keyboard walk + common ending
        "aaabbbccc",        # repeated chars
        "p@ssw0rd",         # leet-speak
        "hello123!",        # common ending
        "abcabc",           # repeated pattern
        "xK#9mQv!2nLp@8rT", # genuinely strong — should be clean
    ]

    for pwd in test_passwords:
        result = detect_patterns(pwd)
        print_pattern_result(pwd, result)