def risk_scoring(header_results, body_results, url_results=None):
    score = 0
    reasons = []

    # ================= IDENTITY & AUTHENTICATION =================
    spf = header_results.get("SPF", {})
    dkim = header_results.get("DKIM", {})
    dmarc = header_results.get("DMARC", "fail")

    from_domain = header_results.get("from_domain", "").lower()
    auth_domain = header_results.get("auth_domain", "").lower()
    reply_to_domain = header_results.get("reply_to_domain", "").lower()

    # --- SPF / DKIM (informational, low weight) ---
    if spf.get("result") not in ("pass", "neutral"):
        score += 1
        reasons.append("SPF authentication failed or missing")

    if dkim.get("result") != "pass":
        score += 1
        reasons.append("DKIM authentication failed or missing")

    # --- DMARC failure ---
    if dmarc != "pass":
        score += 3
        reasons.append("DMARC policy failed")

    # --- Authentication domain mismatch ---
    if auth_domain and from_domain and auth_domain != from_domain:
        score += 4
        reasons.append(
            f"Authentication domain ({auth_domain}) does not match visible sender domain ({from_domain})"
        )

    # --- Reply-To mismatch (very strong signal) ---
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        score += 4
        reasons.append(
            f"Reply-To domain mismatch detected ({reply_to_domain})"
        )

    # ================= BRAND IMPERSONATION =================
    high_value_brands = {
        "chase.com",
        "paypal.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com"
    }

    if (
        from_domain in high_value_brands
        and auth_domain
        and auth_domain != from_domain
    ):
        score += 5
        reasons.append(
            f"Brand impersonation detected for high-value domain ({from_domain})"
        )

    # ================= IP REPUTATION =================
    ip_rep = header_results.get("ip_reputation", {})
    if ip_rep.get("score", 0) >= 2:
        score += 2
        reasons.append(
            ip_rep.get("reason", "Sender IP has poor reputation")
        )

    # ================= EMAIL BODY ANALYSIS =================
    body_risk = body_results.get("risk_level", "none")

    if body_risk == "low":
        score += 1
        reasons.append("Low-risk phishing language detected")

    elif body_risk == "medium":
        score += 3
        reasons.append("Urgent or manipulative phishing language detected")

    elif body_risk == "high":
        score += 5
        reasons.append("Credential harvesting or account threat language detected")

    # ================= URL ANALYSIS =================
    if url_results:
        url_risk = url_results.get("risk_level", "none")
        url_details = url_results.get("details", [])
        url_count = url_results.get("url_count", 0)

        if url_risk == "low":
            score += 1
            reasons.append("Suspicious URL patterns detected")

        elif url_risk == "medium":
            score += 4
            reasons.append("Redirector or shortened URLs detected")

        elif url_risk == "high":
            score += 6
            reasons.append("Highly malicious external URLs detected")

        # External link vs sender domain
        if from_domain and url_count > 0:
            external_urls = [
                u for u in url_details if u.get("domain") != from_domain
            ]
            if external_urls:
                score += 3
                reasons.append("Embedded URLs do not belong to sender domain")

    # ================= FINAL VERDICT =================
    if score >= 12:
        verdict = "PHISHING"
    elif score >= 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGIT"

    return {
        "total_score": score,
        "verdict": verdict,
        "reasons": reasons
    }
