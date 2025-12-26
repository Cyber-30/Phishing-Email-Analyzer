from datetime import datetime

def generate_soc_report(email_subject, sender, recipient, risk_analysis):
    """
    Generate a SOC-style report for an analyzed email.

    Inputs:
        email_subject: string, email subject line
        sender: string, email From address
        recipient: string, email To address
        risk_analysis: dict from risk_scoring.py module

    Output:
        dict representing SOC report
    """

    report = {
        "Report_Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Email_Subject": email_subject,
        "Sender": sender,
        "Recipient": recipient,
        "Final_Verdict": risk_analysis.get("verdict", "UNKNOWN"),
        "Total_Score": risk_analysis.get("total_score", 0),
        "Contributing_Factors": risk_analysis.get("details", {}),
        "Analyst_Comments": ""
    }

    # Add automatic SOC-style comment based on verdict
    verdict = report["Final_Verdict"]

    if verdict == "LEGIT":
        report["Analyst_Comments"] = "No suspicious activity detected. Email appears legitimate."
    elif verdict == "SUSPICIOUS":
        report["Analyst_Comments"] = (
            "Some indicators of phishing detected. User caution advised. "
            "Further investigation recommended if links or attachments are present."
        )
    elif verdict == "PHISHING":
        report["Analyst_Comments"] = (
            "Multiple high-risk indicators detected. Email highly likely to be phishing. "
            "Do not click links or open attachments. Alert security team immediately."
        )
    else:
        report["Analyst_Comments"] = "Verdict could not be determined. Review manually."

    return report


def print_soc_report(report):
    """
    Print the SOC report in a professional, easy-to-read format.
    """
    print("="*60)
    print("SOC ANALYSIS REPORT".center(60))
    print("="*60)
    print(f"Report Generated : {report['Report_Generated']}")
    print(f"Email Subject    : {report['Email_Subject']}")
    print(f"Sender           : {report['Sender']}")
    print(f"Recipient        : {report['Recipient']}")
    print("-"*60)
    print(f"FINAL VERDICT    : {report['Final_Verdict']}")
    print(f"TOTAL SCORE      : {report['Total_Score']}")
    print("-"*60)
    print("CONTRIBUTING FACTORS:")
    for key, value in report['Contributing_Factors'].items():
        print(f"  {key}: {value}")
    print("-"*60)
    print("ANALYST COMMENTS:")
    print(f"  {report['Analyst_Comments']}")
    print("="*60)