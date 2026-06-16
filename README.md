# 🔐 Password Strength Checker

A Python + Flask web application that checks password strength using entropy
calculation, detects weak patterns (keyboard walks, leet-speak, repeated
characters), and verifies passwords against real-world breach databases
(RockYou wordlist + Have I Been Pwned API).

Built as a hands-on cybersecurity learning project covering cryptography
basics, secure API usage (k-anonymity), regex pattern detection, and Flask
web development.

---

## Features

- **Entropy-based scoring** — calculates password strength mathematically (bits of entropy), not just length checks
- **Breach detection** — checks against 14M+ leaked passwords (RockYou) and the live Have I Been Pwned database
- **Privacy-safe API lookup** — uses k-anonymity, so your real password never leaves your machine
- **Pattern detection** — catches keyboard walks (`qwerty`), leet-speak (`p@ssw0rd`), repeated characters, and predictable endings
- **Web UI** — clean, dark-themed interface with a live strength meter
- **Unit tested** — core logic covered with `pytest`

---

## Project Structure

```
password_project/
├── venv/                    # virtual environment (created by you)
├── templates/
│   └── index.html           # web UI
├── tests/
│   └── test_checker.py      # unit tests
├── rockyou.txt               # breach wordlist (downloaded separately)
├── password_checker.py       # Phase 1 — scoring + entropy engine
├── breach_checker.py         # Phase 2 — RockYou + HIBP API checks
├── pattern_detector.py       # Phase 3 — weak pattern detection
├── app.py                    # Phase 4 — Flask web app (ties everything together)
└── requirements.txt          # Python dependencies
```

---

## Requirements

- Python 3.8 or higher (tested on 3.10)
- Internet connection (for the Have I Been Pwned API check)
- ~150 MB free disk space (for the RockYou wordlist)

---

## Setup Guide (Step by Step)

### 1. Clone or download the project

```bash
git clone <your-repo-url>
cd password_project
```

### 2. Create and activate a virtual environment

This keeps your dependencies isolated from your system Python.

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Mac / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You'll know it worked when you see `(venv)` at the start of your terminal line.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install flask requests colorama pytest
```

### 4. Download the RockYou wordlist

This is a list of 14 million real passwords leaked in past data breaches —
used to instantly flag commonly used passwords.

**Option A — Direct download (Windows/Mac/Linux):**

1. Open this link in your browser:
   `https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt`
2. Save the downloaded file as `rockyou.txt`
3. Move it into the root of your `password_project` folder (same level as `app.py`)

**Option B — Already on Kali Linux:**

The file is pre-installed but compressed. Extract it:
```bash
gunzip -k /usr/share/wordlists/rockyou.txt.gz
cp /usr/share/wordlists/rockyou.txt ./password_project/rockyou.txt
```

**Verify it downloaded correctly:**
```bash
# Windows
dir rockyou.txt

# Mac/Linux
ls -lh rockyou.txt
```

You should see a file roughly **130–140 MB** in size.

> **Note:** If `rockyou.txt` is missing, the app still works — it will just
> skip the local wordlist check and rely on the Have I Been Pwned API alone.

### 5. Run the application

```bash
python app.py
```

You should see output like:
```
[*] Loading wordlist...
[+] Loaded 14,344,391 passwords successfully!
[+] App ready!

 * Running on http://127.0.0.1:5000
```

### 6. Open it in your browser

Go to:
```
http://127.0.0.1:5000
```

Type any password into the box and click **Check**. You'll instantly see:
- Strength score (0–100) and label (Weak / Fair / Strong / Very Strong)
- Entropy in bits
- Which character types are present
- Whether it's been found in breach databases, and how many times
- Specific suggestions to improve it

---

## Running Tests

```bash
pytest tests/
```

This runs unit tests covering the scoring engine and pattern detector to
make sure core logic behaves correctly.

---

## How It Works (Technical Overview)

### Entropy Calculation
```
entropy (bits) = password_length × log2(charset_size)
```
A longer password using a wider character set (upper + lower + digits +
symbols) has exponentially more possible combinations, making brute-force
attacks harder.

### K-Anonymity (Have I Been Pwned API)
Your password is never sent over the network. Instead:
1. The password is hashed locally using SHA-1
2. Only the **first 5 characters** of the hash are sent to the API
3. The API returns ~800 hashes that share that prefix
4. The full match is checked **locally** on your machine

This is the same privacy-preserving technique used by Chrome, Firefox, and
1Password's breach alerts.

### Pattern Detection
Even a password that scores well on entropy can be insecure if it follows a
predictable pattern. This project checks for:
- Keyboard walks (`qwerty`, `asdf`, `12345`)
- Repeated characters (`aaa`, `111`)
- Leet-speak substitutions of common words (`p@ssw0rd` → `password`)
- Predictable endings (`hello123`, `name2025`)
- Repeated short patterns (`abcabc`)

---

## Troubleshooting

**"rockyou.txt not found" message**
Make sure the file is named exactly `rockyou.txt` and sits in the same
folder as `app.py`, not inside a subfolder.

**HIBP check shows "No internet connection"**
The Have I Been Pwned API requires outbound internet access. Check your
firewall or network settings if this fails repeatedly.

**`AttributeError: 'str' object has no attribute 'get'`**
This means one of the checker functions is returning a plain string
instead of a dictionary. Ensure `check_rockyou()` and `check_hibp()` in
`breach_checker.py` both return dictionaries with `checked`, `found`, and
`message` keys.

**Port 5000 already in use**
Stop any other Flask app running, or change the port in `app.py`:
```python
app.run(debug=True, port=5050)
```

---