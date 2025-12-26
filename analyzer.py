from parser.email_parser import parse_email  # renamed for clarity
from parser.header_analyzer import analyze_headers
from detection.body_keywords import body_detection
from detection.ip_reputation import check_ip_reputation
from scoring.risk_scoring import risk_scoring
from report.final_report import generate_soc_report, print_soc_report

def run_analysis(email_path):
    
    parsed_email = parse_email(email_path)  # 1. Email parsing

    
    header_results = analyze_headers(parsed_email)  # 2. Header analysis

    
    body_results = body_detection(parsed_email) # 3. Body keyword detection

    
    ip_score = check_ip_reputation(header_results.get("sender_ip")) # 4. IP reputation check    

    
    if ip_score:
        header_results["ip_reputation_score"] = ip_score
    risk_results = risk_scoring(header_results, body_results)   # 5. Risk scoring

    
    report = generate_soc_report(
        email_subject=parsed_email.get("Subject", "No Subject"), 
        sender=parsed_email.get("From", "Unknown"),
        recipient=parsed_email.get("To", "Unknown"),
        risk_analysis=risk_results
    )

    
    print_soc_report(report) # 6. Report generation
    return report

if __name__ == "__main__":
    sample_email = "samples/phishing.eml"  
    run_analysis(sample_email)
