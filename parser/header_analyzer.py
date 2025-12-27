import re

def extract_domain(email):
    if not email or "@" not in email:
        return ""
    return email.split("@")[-1].strip(">").strip().lower()

def analyze_headers(parsed_email):
    results = {}

    # ---------------- FROM / REPLY-TO ----------------
    from_header = parsed_email.get("From", "")
    reply_to = parsed_email.get("Reply-To", "")

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to)

    results["from_domain"] = from_domain
    results["reply_to_domain"] = reply_to_domain

    # ---------------- AUTHENTICATION RESULTS ----------------
    auth_results = parsed_email.get("Authentication-Results", "").lower()

    # SPF
    if "spf=pass" in auth_results:
        results["SPF"] = {"result": "pass"}
    elif "spf=fail" in auth_results:
        results["SPF"] = {"result": "fail"}
    else:
        results["SPF"] = {"result": "unknown"}

    # DKIM
    if "dkim=pass" in auth_results:
        results["DKIM"] = {"result": "pass"}
    elif "dkim=fail" in auth_results or "dkim=timeout" in auth_results:
        results["DKIM"] = {"result": "fail"}
    else:
        results["DKIM"] = {"result": "unknown"}

    # DMARC + AUTH DOMAIN
    if "dmarc=pass" in auth_results:
        results["DMARC"] = "pass"
    else:
        results["DMARC"] = "fail"

    # Extract auth domain (header.from=example.com)
    match = re.search(r"header\.from=([a-z0-9\.-]+)", auth_results)
    results["auth_domain"] = match.group(1) if match else ""

    return results
