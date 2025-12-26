import spf
import dkim

def check_spf(sender_ip, mail_from, helo_host):
    """
    sender_ip: IP address of SMTP client
    mail_from: envelope-from address
    helo_host: HELO/EHLO hostname
    """

    try:
        result, explanation = spf.check2(
            i=sender_ip,
            s=mail_from,
            h=helo_host
        )
    except Exception as e:
        return {
            "spf_result": "error",
            "spf_explanation": str(e)
        }

    return {
        "spf_result": result,
        "spf_explanation": explanation
    }

def check_dkim(raw_email_bytes):
    try:
        return dkim.verify(raw_email_bytes)
    except Exception:
        return False

if (SPF pass and aligned) OR (DKIM pass and aligned):
    DMARC pass
else:
    DMARC fail
