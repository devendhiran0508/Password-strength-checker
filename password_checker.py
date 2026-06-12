import math
import string
import re


# ── 1. Charset size detection ──────────────────────────────────────────────────
def get_charset_size(password: str) -> int:
    """Return the total pool of characters the password draws from."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26   # lowercase letters
    if re.search(r"[A-Z]", password):
        size += 26   # uppercase letters
    if re.search(r"[0-9]", password):
        size += 10   # digits
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        size += 32   # common symbols
    return size if size > 0 else 1


# ── 2. Entropy calculation ─────────────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """
    Entropy (bits) = log2(charset_size ^ length)
                   = length * log2(charset_size)

    Higher entropy = harder to brute-force.
    Rule of thumb:
        < 28 bits  → Very Weak
        28–35      → Weak
        36–59      → Fair
        60–127     → Strong
        128+       → Very Strong
    """
    charset_size = get_charset_size(password)
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


# ── 3. Scoring engine ──────────────────────────────────────────────────────────
def score_password(password: str) -> dict:
    """
    Score a password from 0–100 and return detailed feedback.

    Scoring breakdown:
        Length          → up to 30 pts
        Character mix   → up to 40 pts
        Entropy bonus   → up to 30 pts
    """
    score = 0
    feedback = []

    # --- Length scoring ---
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
    elif length >= 6:
        score += 6
    else:
        score += 0
        feedback.append("Too short — use at least 8 characters.")

    # --- Character class scoring (10 pts each) ---
    has_lower  = bool(re.search(r"[a-z]", password))
    has_upper  = bool(re.search(r"[A-Z]", password))
    has_digit  = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password))

    if has_lower:
        score += 10
    else:
        feedback.append("Add lowercase letters (a–z).")

    if has_upper:
        score += 10
    else:
        feedback.append("Add uppercase letters (A–Z).")

    if has_digit:
        score += 10
    else:
        feedback.append("Add numbers (0–9).")

    if has_symbol:
        score += 10
    else:
        feedback.append("Add symbols (!@#$% etc.).")

    # --- Entropy bonus ---
    entropy = calculate_entropy(password)
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 22
    elif entropy >= 40:
        score += 14
    elif entropy >= 28:
        score += 6
    else:
        feedback.append(f"Low entropy ({entropy} bits) — password is too predictable.")

    # --- Clamp score to 0–100 ---
    score = min(score, 100)

    # --- Strength label ---
    if score >= 80:
        label = "Very Strong"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Fair"
    elif score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    if not feedback:
        feedback.append("Great password! No obvious weaknesses found.")

    return {
        "password":     password,
        "score":        score,
        "label":        label,
        "entropy_bits": entropy,
        "charset_size": get_charset_size(password),
        "length":       length,
        "feedback":     feedback,
        "char_classes": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits":    has_digit,
            "symbols":   has_symbol,
        },
    }


# ── 4. Pretty printer ──────────────────────────────────────────────────────────
def print_result(result: dict) -> None:
    bar_filled = int(result["score"] / 5)   # 20-char bar
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print("\n" + "─" * 44)
    print(f"  Password : {'*' * result['length']}  ({result['length']} chars)")
    print(f"  Score    : [{bar}] {result['score']}/100")
    print(f"  Strength : {result['label']}")
    print(f"  Entropy  : {result['entropy_bits']} bits  "
          f"(charset: {result['charset_size']} chars)")
    print()
    print("  Character classes:")
    for cls, present in result["char_classes"].items():
        tick = "✓" if present else "✗"
        print(f"    {tick}  {cls}")
    print()
    print("  Feedback:")
    for tip in result["feedback"]:
        print(f"    • {tip}")
    print("─" * 44 + "\n")


# ── 5. Quick demo ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_passwords = [
        "abc",
        "password",
        "P@ssw0rd",
        "MyD0g$Nam3IsMax",
        "xK#9mQv!2nLp@8rT",
    ]

    for pwd in test_passwords:
        result = score_password(pwd)
        print_result(result)