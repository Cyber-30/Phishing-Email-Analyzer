import os
from parser.email_parser import parse_email
from parser.header_analyzer import analyze_headers
from detection.body_keywords import body_detection
from detection.ip_reputation import check_ip_reputation
from detection.url_detection import url_detection
from scoring.risk_scoring import risk_scoring
from report.final_report import generate_soc_report, print_soc_report

def run_analysis(email_path):
    parsed_email = parse_email(email_path)

    header_results = analyze_headers(parsed_email)
    body_results = body_detection(parsed_email)
    url_results = url_detection(parsed_email)

    sender_ip = header_results.get("sender_ip")
    ip_rep = check_ip_reputation(sender_ip)
    header_results["ip_reputation"] = ip_rep

    risk_results = risk_scoring(header_results, body_results, url_results)

    report = generate_soc_report(
        email_subject=parsed_email.get("Subject", "N/A"),
        sender=parsed_email.get("From", "N/A"),
        recipient=parsed_email.get("To", "N/A"),
        risk_analysis=risk_results
    )

    print_soc_report(report)

if __name__ == "__main__":
    print("\n=== Phishing Email Analyzer ===\n")
    email_path = input("Enter the file path for the email file (.eml): ").strip()

    if not email_path:
        print("❌ No file path provided.")
        exit(1)

    if not os.path.isfile(email_path):
        print(f"❌ File not found: {email_path}")
        exit(1)

    run_analysis(email_path)
