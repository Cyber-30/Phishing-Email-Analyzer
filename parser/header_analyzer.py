import re

def parse_auth_results(auth_header):
    results = {
        "spf": {"result": "none", "risk": "low"},
        "dkim": {"result": "none", "risk": "low"},
        "dmarc": {"result": "none", "risk": "medium"}
    }

    if not auth_header:
        return results

    auth_header = auth_header.lower()

    def extract(proto):
        match = re.search(rf"{proto}=(pass|fail|softfail|neutral)", auth_header)
        return match.group(1) if match else "none"

    spf = extract("spf")
    dkim = extract("dkim")
    dmarc = extract("dmarc")

    results["spf"]["result"] = spf
    results["dkim"]["result"] = dkim
    results["dmarc"]["result"] = dmarc

    if spf == "fail":
        results["spf"]["risk"] = "high"
    elif spf == "softfail":
        results["spf"]["risk"] = "medium"
    elif spf == "neutral":
        results["spf"]["risk"] = "low"
    else:
        results["spf"]["risk"] = "none"

    if dkim == "fail":
        results["dkim"]["risk"] = "high"
    elif dkim == "pass":
        results["dkim"]["risk"] = "none"

    if dmarc == "fail":
        results["dmarc"]["risk"] = "critical"
    elif dmarc == "pass":
        results["dmarc"]["risk"] = "none"

    return results


def check_from_return_mismatch(from_header, return_path):
    if not from_header or not return_path:
        return False

    from_domain = re.search(r"@([\w\.-]+)", from_header)
    return_domain = re.search(r"@([\w\.-]+)", return_path)

    if not from_domain or not return_domain:
        return False

    return from_domain.group(1).lower() != return_domain.group(1).lower()


def extract_sender_ip(received_headers):
    if not received_headers:
        return None

    for header in reversed(received_headers):
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", header)
        if match:
            return match.group(0)

    return None


def analyze_headers(parsed_email):
    headers = parsed_email.get("headers", {})

    auth_results = parse_auth_results(headers.get("Authentication-Results"))
    from_return_mismatch = check_from_return_mismatch(
        headers.get("From"),
        headers.get("Return-Path")
    )
    sender_ip = extract_sender_ip(headers.get("Received"))

    return {
        "authentication": auth_results,
        "from_return_mismatch": from_return_mismatch,
        "sender_ip": sender_ip
    }
