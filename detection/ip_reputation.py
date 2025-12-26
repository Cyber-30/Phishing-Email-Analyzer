import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/bad_ip_list.txt")

def load_bad_ips():
    try:
        with open(DATA_PATH, "r") as f:
            return set(ip.strip() for ip in f.readlines() if ip.strip())
    except FileNotFoundError:
        return set()

BAD_IPS = load_bad_ips()

def check_ip_reputation(sender_ip):
    """
    Check if sender IP is in bad IP list.
    Returns a numeric score (2 = high risk, 0 = safe)
    """
    if not sender_ip:
        return 0
    if sender_ip in BAD_IPS:
        return 2
    return 0
