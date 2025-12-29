# 🛡️ Phishing Email Analyzer (SOC-Style)

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Security](https://img.shields.io/badge/Cybersecurity-SOC%20Analysis-red)
![Status](https://img.shields.io/badge/Status-Active-success)

A **SOC-oriented phishing email analysis tool** that analyzes raw `.eml` files and classifies emails as **LEGIT**, **SUSPICIOUS**, or **PHISHING** using real-world detection logic.

Designed to simulate **Tier-1 / Tier-2 SOC analyst workflows**.

---

## 🔍 Features

- Email header analysis (SPF, DKIM, DMARC)
- Authentication domain vs visible sender mismatch detection
- Brand impersonation detection (banks & financial services)
- URL extraction and risk analysis
- Phishing language detection
- Risk scoring engine
- SOC-style analysis report

---

## 📂 Project Structure

<p align="center">
  <img src="img/Screenshot from 2025-12-29 17-44-13.png" alt="Phishing Email Analyzer" width="600">
</p>


---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/phishing-email-analyzer.git
cd phishing-email-analyzer
pip install spf dkim
```

## ▶️ Usage

```bash
Enter the file path for the email file (.eml): /path/to/email.eml
```

## 🧮 Risk Scoring Breakdown

| Category | Detection Condition | Score |
|--------|---------------------|-------|
| SPF | SPF authentication failed or missing | +1 |
| DKIM | DKIM authentication failed or missing | +1 |
| DMARC | DMARC policy failed | +3 |
| Domain Alignment | Authentication domain ≠ visible sender domain | +4 |
| Reply-To Mismatch | Reply-To domain differs from From domain | +4 |
| Brand Impersonation | High-value brand impersonation (Bank / Finance / Tech) | +5 |
| IP Reputation | Sender IP has poor reputation | +2 |
| Body Analysis | Low-risk phishing language | +1 |
| Body Analysis | Urgent or manipulative language | +3 |
| Body Analysis | Credential harvesting / account threat language | +5 |
| URL Analysis | Suspicious URL patterns | +1 |
| URL Analysis | Redirector or shortened URLs | +4 |
| URL Analysis | Highly malicious external URLs | +6 |
| URL Domain Mismatch | Embedded URLs do not belong to sender domain | +3 |


## 🎯 Verdict Classification

| Total Score Range | Verdict |
|------------------|---------|
| 0 – 5 | LEGIT |
| 6 – 11 | SUSPICIOUS |
| ≥ 12 | PHISHING |


## 🚨 Severity Mapping

| Verdict | Severity | Action |
|-------|----------|-----------|
| LEGIT | None | No action required |
| SUSPICIOUS | Medium | User caution advised, monitor activity |
| PHISHING | High | Block email, alert security team immediately |
