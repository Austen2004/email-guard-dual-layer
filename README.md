# 🛡️ DualShield Email Guard

### Two-Layer Gmail Spam & Threat Protection System
*(Traditional Heuristic Engine + Machine Learning Classifier)*

DualShield Email Guard is a comprehensive email security system designed to intercept, categorize, and protect users from malicious incoming emails (spam, phishing, CEO wire fraud, malware lures, and advance fee scams).

It implements a **defense-in-depth architecture** featuring two distinct security layers:
1. **Layer 1: Traditional Heuristic & Rule-Based Engine** (Deterministic fast-path inspection).
2. **Layer 2: Machine Learning Classifier** (Probabilistic TF-IDF n-grams + Explainable AI attribution).
3. **Arbitration & Enforcement Engine**: Synthesizes both layers into actions: **`BLOCKED`** (quarantined away from inbox) or **`NOTIFIED`** (delivered with prominent injected safety banner and push alert) or **`ALLOWED`** (verified clean).

---

## 🏛️ System Architecture

```
Incoming Email Stream (Sender, Subject, Body, Headers, Attachments, URLs)
    │
    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: Traditional & Heuristic Protection Engine                   │
│  ├─ 1. Reputation & Threat Blacklist Check                             │
│  ├─ 2. Cryptographic Auth Validation (SPF / DKIM / DMARC verification) │
│  ├─ 3. Identity Spoofing & Lookalikes (Display Name vs Sender Domain)  │
│  ├─ 4. Dangerous Attachments (.exe, .scr, double-extensions .pdf.exe)  │
│  ├─ 5. Link Safety (Raw IP URLs, URL shorteners, high-abuse TLDs)      │
│  └─ 6. Heuristic RegEx Patterns (Urgency tactics, credential harvest)  │
│     ► Output: Heuristic Risk Score (0-100) + Rule Violations           │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  LAYER 2: Machine Learning Classifier Engine (XAI)                    │
│  ├─ Text Preprocessing (Tokenization, HTML strip, URL normalization)  │
│  ├─ TF-IDF Feature Extraction (Unigrams + Bigrams, sublinear TF)       │
│  ├─ Trained Calibrated Linear Classifier (Logistic Regression)         │
│  └─ Explainable AI (XAI) Feature Attribution (Top spam/ham tokens)    │
│     ► Output: Spam Probability (0.0 to 1.0) + Word Influence Weights   │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  DUALSHIELD ARBITRATION & ENFORCEMENT ENGINE                           │
│  ├─ BLOCKED (Quarantine):                                              │
│  │    • Hard rule violation (malware file, blacklisted sender) OR       │
│  │    • Dual-layer consensus (L1 Score >= 50 AND L2 ML Prob >= 70%) OR │
│  │    • Critical ML Threat (L2 ML Prob >= 88%)                         │
│  │    • Action: Intercepted & quarantined, sender blocked               │
│  │                                                                     │
│  ├─ NOTIFIED (Warning Injected):                                       │
│  │    • Moderate Risk (L1 Score >= 35 OR L2 ML Prob >= 45%)            │
│  │    • Action: Injected safety banner into email + Gmail alert push   │
│  │                                                                     │
│  └─ ALLOWED (Delivered Safe):                                          │
│       • Low risk on both layers; delivered with verified clean tag.    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🌟 Key Features

- **Dual-Layer Defense In-Depth**: Combines deterministic rules (fast, zero false negatives on known IOCs) with statistical machine learning (detects zero-day phrasing, stealthy lures, and polymorphic text).
- **Explainable AI (XAI)**: Displays token-level weight contributions showing exactly which words pushed the ML model towards "SPAM" or "HAM".
- **Gmail Safety Injection Simulation**: Demonstrates what recipients see in Gmail, including injected warning banners (`⚠️ PROCEED WITH CAUTION`) and desktop security alert notifications.
- **Simulated Protected Inbox**: Full Gmail mockup showing how clean emails, flagged emails, and quarantined threats are isolated in real time.
- **Dynamic Policy Manager**: Add custom domains to the blacklist, inspect whitelists, and view active risk thresholds.
- **Live Gmail Integration Support**: Includes production-ready Python connector for live Gmail mailboxes via IMAP (App Password) or Google Cloud Gmail API.

---

## 🚀 Quick Start Guide

### 1. Requirements
Python 3.10+ with standard data science packages:
```bash
pip install fastapi uvicorn scikit-learn pandas numpy joblib pydantic pytest
```

### 2. Launch the Interactive Web Dashboard
Run the FastAPI application:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### 3. Run Automated Test Suite
Validate the detection engine against 9 standard realistic attack scenarios:
```bash
python test_suite.py
```
Output:
```
test_ceo_fraud_blocked_or_flagged ... ok
test_crypto_scam_blocked ... ok
test_legitimate_github_pr_allowed ... ok
test_legitimate_google_docs_allowed ... ok
test_legitimate_stripe_receipt_allowed ... ok
test_legitimate_work_meeting_allowed ... ok
test_malware_attachment_blocked ... ok
test_marketing_borderline_flagged_with_notification ... ok
test_phishing_paypal_blocked ... ok

Ran 9 tests in 0.064s - OK
```

### 4. Standalone Model Retraining
Evaluate the machine learning pipeline and generate precision/recall metrics:
```bash
python train_model.py
```

---

## 🔬 Demonstration Test Scenarios

The web interface includes 1-click loading for these realistic test cases:

| Scenario | Category | Layer 1 Result | Layer 2 ML Result | Final Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Fake PayPal Suspension** | Phishing | Raw IP URL, Spoofed domain, Urgency (+75 pts) | 99% Spam Probability | **BLOCKED & Quarantined** |
| **Overdue Invoice .exe** | Malware | Double extension `.pdf.exe` (+50 pts, Hard Block) | 98% Spam Probability | **BLOCKED & Quarantined** |
| **CEO Urgent Wire Transfer** | BEC / Fraud | Mismatched Reply-To, Wire keywords (+50 pts) | 88% Spam Probability | **BLOCKED & Quarantined** |
| **2026 Crypto Airdrop Prize** | Scam | Suspicious TLD `.xyz`, Financial lure (+60 pts) | 89% Spam Probability | **BLOCKED & Quarantined** |
| **Aggressive 90% Off Sale** | Borderline | URL shortener `bit.ly`, High caps (+40 pts) | 52% Spam Probability | **NOTIFIED (Warning Banner)** |
| **Google Docs Collaboration** | Legitimate | Genuine domain, SPF/DKIM pass (0 pts) | 2% Spam Probability | **ALLOWED (Verified Safe)** |
| **GitHub Pull Request #142** | Legitimate | Genuine domain, SPF/DKIM pass (0 pts) | 1% Spam Probability | **ALLOWED (Verified Safe)** |
| **Stripe Payment Receipt** | Legitimate | Genuine domain, SPF/DKIM pass (0 pts) | 3% Spam Probability | **ALLOWED (Verified Safe)** |
| **Sprint Planning Agenda** | Legitimate | Internal domain, Clean text (0 pts) | 1% Spam Probability | **ALLOWED (Verified Safe)** |

---

## 🔌 Connecting to Live Gmail

DualShield includes a built-in module `LiveGmailIMAPConnector` in `gmail_service.py` to scan real-world Gmail accounts.

### Step 1: Generate a Google App Password
1. Navigate to: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Generate an App Password named **"DualShield"** (16 letters).

### Step 2: Run Live Inspection Script
```python
from gmail_service import LiveGmailIMAPConnector

connector = LiveGmailIMAPConnector(
    email_address="your.name@gmail.com",
    app_password="xxxx xxxx xxxx xxxx"
)

# Fetch unread emails, scan with DualShield, and return verdicts
results = connector.fetch_and_scan_unread(max_emails=5)
for item in results:
    verdict = item["verdict"]
    print(f"[{verdict['action']}] {item['email']['subject']} -> {verdict['primary_reason']}")
```

---

## 📁 Repository Structure

```
email-guard-dual-layer/
├── app.py                     # FastAPI REST API & Web Dashboard Server
├── layer1_traditional.py      # Layer 1 Heuristics, Regex, SPF/DKIM, Attachment Checks
├── layer2_ml.py               # Layer 2 TF-IDF + Logistic Regression with Explainability
├── fusion_engine.py           # Two-Layer Arbitration, Policy Matrix & Notification Generator
├── gmail_service.py           # Virtual Gmail Mailbox Simulator & Live IMAP Connector
├── sample_emails.py           # 9 Curated Realistic Ham & Spam Test Cases
├── train_model.py             # ML Model Training & Accuracy Benchmark Utility
├── test_suite.py              # Automated Unit Tests Validating All Attack Scenarios
├── requirements.txt           # Python Package Dependencies
├── static/                    # Frontend UI Assets
│   ├── index.html             # Responsive Dashboard UI (Tailwind CSS)
│   ├── app.js                 # Frontend Controller & Real-Time Visualization
│   └── style.css              # Custom Styling & Animations
├── models/                    # Serialized Machine Learning Weights
│   └── spam_classifier.joblib # Trained TF-IDF Pipeline
└── README.md                  # Comprehensive Documentation
```

---

## 🛡️ License & Academic Use
Developed as an academic and engineering demonstration of **Defense-in-Depth for Email Gateways**. Free to adapt for production and research prototypes.
