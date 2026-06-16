from flask import Flask, render_template, request
from password_checker import score_password
from breach_checker import load_rockyou, check_rockyou, check_hibp
from pattern_detector import detect_patterns

app = Flask(__name__)

# Load rockyou once when the app starts (not on every request)
print("[*] Loading wordlist...")
wordlist = load_rockyou()
print("[+] App ready!\n")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    password = None

    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if password:
            # Phase 1 — score the password
            score_data = score_password(password)

            # Phase 2 — breach checks
            rockyou_data = check_rockyou(password, wordlist)
            hibp_data    = check_hibp(password)

            # Phase 3 — pattern detection
            pattern_data = detect_patterns(password)

            # Apply pattern penalty to score
            final_score = max(0, score_data["score"] - pattern_data["penalty"])

            # Combine all feedback
            all_feedback = score_data["feedback"] + pattern_data["findings"]

            # Check if compromised
            compromised = rockyou_data.get("found") or hibp_data.get("found")

            result = {
                "score":        final_score,
                "label":        score_data["label"],
                "entropy_bits": score_data["entropy_bits"],
                "charset_size": score_data["charset_size"],
                "length":       score_data["length"],
                "char_classes": score_data["char_classes"],
                "compromised":  compromised,
                "hibp_count":   hibp_data.get("count", 0),
                "feedback":     all_feedback,
            }

    return render_template("index.html", result=result, password=password)


if __name__ == "__main__":
    app.run(debug=True)