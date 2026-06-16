# tests/test_checker.py
from password_checker import score_password
from pattern_detector import detect_patterns

def test_weak_password_scores_low():
    result = score_password("abc")
    assert result["score"] < 30

def test_strong_password_scores_high():
    result = score_password("xK#9mQv!2nLp@8rT")
    assert result["score"] >= 80

def test_leet_speak_detected():
    result = detect_patterns("p@ssw0rd")
    assert result["clean"] == False

def test_strong_password_no_patterns():
    result = detect_patterns("xK#9mQv!2nLp@8rT")
    assert result["clean"] == True