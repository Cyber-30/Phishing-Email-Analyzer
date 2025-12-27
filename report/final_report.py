from datetime import datetime

def generate_soc_report(email_subject, sender, recipient, risk_analysis):
    """
    Generate a SOC-style report for an analyzed email.
    """

    verdict = risk_analysis.get("verdict", "UNKNOWN")
    score = risk_analysis.get("total_score", 0)
    reasons = risk_analysis.get("reasons", [])

    # Severity mapping (SOC style)
    if verdict == "LEGIT":
        severity = "None"
    elif verdict == "SUSPICIOUS":
        severity = "Medium"
    elif verdict == "PHISHING":
        severity = "High"
    else:
        severity = "Unknown"

    report = {
        "Report_Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Email_Subject": email_subject,
        "Sender": sender,
        "Recipient": recipient,
        "Final_Verdict": verdict,
        "Severity": severity,
        "Total_Score": score,
        "Contributing_Factors": reasons,
        "Analyst_Comments": ""
    }

    # SOC-style analyst comments
    if verdict == "LEGIT":
        report["Analyst_Comments"] = (
            "Email passed authentication checks and no malicious indicators "
            "were identified. No action required."
        )

    elif verdict == "SUSPICIOUS":
        report["Analyst_Comments"] = (
            "Email exhibits some suspicious indicators. User awareness advised. "
            "Recommend avoiding link interaction until further verification."
        )

    elif verdict == "PHISHING":
        report["Analyst_Comments"] = (
            "Email contains multiple high-risk phishing indicators. Immediate action "
            "recommended: block sender, warn users, and report to security team."
        )

    else:
        report["Analyst_Comments"] = (
            "Unable to determine verdict automatically. Manual SOC review required."
        )

    return report


def print_soc_report(report):
    """
    Print the SOC report in a professional, analyst-friendly format.
    """

    print("=" * 70)
    print("SOC EMAIL ANALYSIS REPORT".center(70))
    print("=" * 70)

    print(f"Report Generated : {report['Report_Generated']}")
    print(f"Email Subject    : {report['Email_Subject']}")
    print(f"Sender           : {report['Sender']}")
    print(f"Recipient        : {report['Recipient']}")

    print("-" * 70)
    print(f"FINAL VERDICT    : {report['Final_Verdict']}")
    print(f"SEVERITY         : {report['Severity']}")
    print(f"TOTAL SCORE      : {report['Total_Score']}")

    print("-" * 70)
    print("CONTRIBUTING FACTORS:")
    if report["Contributing_Factors"]:
        for reason in report["Contributing_Factors"]:
            print(f"  - {reason}")
    else:
        print("  None")

    print("-" * 70)
    print("ANALYST COMMENTS:")
    print(f"  {report['Analyst_Comments']}")

    print("=" * 70)
