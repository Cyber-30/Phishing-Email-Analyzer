def calculate_risk_level(score):
    """Convert numerical score to SOC-style risk level"""
    if score == 0:
        return "LEGIT"
    elif score <= 3:
        return "SUSPICIOUS"
    else:
        return "PHISHING"


def risk_scoring(header_analysis, body_analysis):
    """
    Combine header and body analysis to calculate overall risk.

    Inputs:
        header_analysis: dict from header_analyzer.py
        body_analysis: dict from body_keywords.py

    Output:
        dict:
            - total_score: numeric
            - verdict: LEGIT/SUSPICIOUS/PHISHING
            - details: dictionary of contributing factors
    """

    total_score = 0
    details = {}

    # --- SPF Risk ---
    spf_risk = header_analysis["authentication"]["spf"]["risk"]
    spf_score_map = {"none": 0, "low": 1, "medium": 2, "high": 3}
    total_score += spf_score_map.get(spf_risk, 0)
    details["SPF"] = spf_risk

    # --- DKIM Risk ---
    dkim_risk = header_analysis["authentication"]["dkim"]["risk"]
    dkim_score_map = {"none": 0, "low": 1, "medium": 2, "high": 3}
    total_score += dkim_score_map.get(dkim_risk, 0)
    details["DKIM"] = dkim_risk

    # --- DMARC Risk ---
    dmarc_risk = header_analysis["authentication"]["dmarc"]["risk"]
    dmarc_score_map = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    total_score += dmarc_score_map.get(dmarc_risk, 0)
    details["DMARC"] = dmarc_risk

    # --- From/Return-Path Mismatch ---
    mismatch = header_analysis.get("from_return_mismatch", False)
    if mismatch:
        total_score += 2
        details["From_Return_Mismatch"] = "Yes"
    else:
        details["From_Return_Mismatch"] = "No"

    # --- Body Keywords Risk ---
    body_risk = body_analysis.get("risk_level", "none")
    body_score_map = {"none": 0, "low": 1, "medium": 2, "high": 3}
    total_score += body_score_map.get(body_risk, 0)
    details["Body_Risk"] = body_risk
    details["Keywords_Found"] = body_analysis.get("keywords_found", [])

    # --- Sender IP optional enhancement ---
    # You can later add reputation scoring here

    verdict = calculate_risk_level(total_score)

    return {
        "total_score": total_score,
        "verdict": verdict,
        "details": details
    }
