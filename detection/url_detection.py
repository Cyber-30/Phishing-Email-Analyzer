import re
from urllib.parse import urlparse

# Common phishing-related TLDs
SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "click", "country", "link", "support", "review"
}

# Common URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly"
}

URL_REGEX = r"(https?://[^\s\"'>]+)"

def extract_urls(text):
    if not text:
        return []
    return re.findall(URL_REGEX, text)

def is_ip_based_url(netloc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc) is not None

def analyze_url(url):
    parsed = urlparse(url)
    findings = []

    domain = parsed.netloc.lower()

    # HTTP check
    if parsed.scheme == "http":
        findings.append("Uses HTTP instead of HTTPS")

    # IP-based URL
    if is_ip_based_url(domain):
        findings.append("IP-based URL detected")

    # Suspicious TLD
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        findings.append(f"Suspicious TLD: .{tld}")

    # URL shortener
    if domain in URL_SHORTENERS:
        findings.append("URL shortener detected")

    return {
        "url": url,
        "domain": domain,
        "findings": findings,
        "risk_score": len(findings)
    }

def url_detection(parsed_email):
    body = parsed_email.get("Body", "")
    urls = extract_urls(body)

    analyzed_urls = []
    total_score = 0

    for url in urls:
        analysis = analyze_url(url)
        total_score += analysis["risk_score"]
        analyzed_urls.append(analysis)

    # Overall risk assessment
    if total_score == 0:
        risk_level = "none"
    elif total_score <= 2:
        risk_level = "low"
    elif total_score <= 5:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "urls_found": urls,
        "url_count": len(urls),
        "total_score": total_score,
        "risk_level": risk_level,
        "details": analyzed_urls
    }
