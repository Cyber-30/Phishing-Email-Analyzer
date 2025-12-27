import os
import ipaddress

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/bad_ip_list.txt")

def load_bad_ips():
    try:
        with open(DATA_PATH, "r") as f:
            return set(ip.strip() for ip in f if ip.strip())
    except FileNotFoundError:
        return set()

BAD_IPS = load_bad_ips()

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def check_ip_reputation(sender_ip):
    """
    Checks sender IP against static reputation list.
    Returns SOC-style structured result.
    """

    if not sender_ip:
        return {
            "score": 0,
            "risk": "unknown",
            "reason": "Sender IP not found"
        }

    if is_private_ip(sender_ip):
        return {
            "score": 0,
            "risk": "none",
            "reason": "Private/internal IP address"
        }

    if sender_ip in BAD_IPS:
        return {
            "score": 2,
            "risk": "high",
            "reason": "Sender IP found in known bad IP list"
        }

    return {
        "score": 0,
        "risk": "none",
        "reason": "No reputation issues found"
    }