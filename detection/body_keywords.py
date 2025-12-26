import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/suspicious_keywords.txt")

def load_keywords():
    try:
        with open(DATA_PATH, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        # fallback hardcoded keywords
        return ["urgent", "password", "verify", "account", "click here", "login", "bank", "security alert"]

KEYWORDS = load_keywords()

def body_detection(parsed_email):
    body = parsed_email.get("Body", "").lower()
    keywords_found = [kw for kw in KEYWORDS if kw in body]
    total_hits = len(keywords_found)

    if total_hits == 0:
        risk_level = "none"
    elif total_hits <= 2:
        risk_level = "low"
    elif total_hits <= 5:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "keywords_found": keywords_found,
        "total_hits": total_hits,
        "risk_level": risk_level
    }
