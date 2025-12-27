import spf
import dkim
import re

def extract_domain(email_address):
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@")[-1].lower()

# ---------------- SPF CHECK ----------------
def check_spf(sender_ip, mail_from, helo_host):
    try:
        result, explanation = spf.check2(
            i=sender_ip,
            s=mail_from,
            h=helo_host
        )
    except Exception as e:
        return {
            "result": "error",
            "aligned": False,
            "explanation": str(e)
        }

    from_domain = extract_domain(mail_from)
    spf_domain = extract_domain(mail_from)

    aligned = (from_domain == spf_domain)

    return {
        "result": result,
        "aligned": aligned,
        "explanation": explanation
    }

# ---------------- DKIM CHECK ----------------
def extract_dkim_domain(raw_email_bytes):
    match = re.search(br"d=([^;]+)", raw_email_bytes)
    if match:
        return match.group(1).decode().lower()
    return None

def check_dkim(raw_email_bytes, from_header):
    try:
        dkim_pass = dkim.verify(raw_email_bytes)
    except Exception:
        return {
            "result": "fail",
            "aligned": False
        }

    from_domain = extract_domain(from_header)
    dkim_domain = extract_dkim_domain(raw_email_bytes)

    aligned = dkim_domain == from_domain

    return {
        "result": "pass" if dkim_pass else "fail",
        "aligned": aligned
    }

# ---------------- DMARC CHECK ----------------
def check_dmarc(spf_result, dkim_result):
    if (
        spf_result["result"] == "pass" and spf_result["aligned"]
    ) or (
        dkim_result["result"] == "pass" and dkim_result["aligned"]
    ):
        return "pass"
    return "fail"
