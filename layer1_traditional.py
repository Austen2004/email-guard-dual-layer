"""
Layer 1: Traditional & Heuristic Security Engine.
Provides deterministic, rule-based inspection including:
- SPF / DKIM / DMARC authentication parsing
- Sender identity & Display Name Spoofing detection (VIP Impersonation)
- Lookalike / Homoglyph / Typosquatted domain analysis
- Dangerous attachment detection (executables, double extensions)
- Malicious & suspicious link analysis (Raw IP URLs, suspicious TLDs, URL shorteners)
- Pattern & heuristic regex matching (Urgency, credential harvesting, financial fraud)
- Blacklist / Whitelist reputation checks
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict

# Known trusted brand domains vs brand keywords
BRAND_DOMAINS = {
    "paypal": ["paypal.com", "intl.paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "docs.google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "binance": ["binance.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "github": ["github.com"],
    "stripe": ["stripe.com"]
}

# High-risk executable and script attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".vbs", ".js", ".cmd", ".pif", 
    ".hta", ".jar", ".iso", ".wsf", ".ps1", ".cpl"
}

# Suspicious high-abuse Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".buzz", ".club", ".surf", ".work", ".icu", ".cam", ".gdn"}

# Common URL shorteners frequently abused in spam/phishing
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "ow.ly", "rebrand.ly"}

# Static Blacklist for immediate critical blocking
GLOBAL_BLACKLIST_DOMAINS = {
    "malicious-phish-hub.com",
    "evil-hacker-site.org",
    "temp-mail.xyz",
    "paypa1-security-verification.com"
}

# Static Whitelist
GLOBAL_WHITELIST_DOMAINS = {
    "docs.google.com",
    "google.com",
    "github.com",
    "stripe.com",
    "acmetech.com"
}


@dataclass
class TriggeredRule:
    rule_id: str
    category: str
    severity: str  # "INFO", "WARNING", "HIGH", "CRITICAL"
    description: str
    score_points: int


@dataclass
class Layer1Report:
    score: int                     # Heuristic risk score (0 to 100)
    risk_tier: str                 # "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    is_hard_block: bool            # True if critical rule mandates immediate block
    triggered_rules: List[Dict[str, Any]] = field(default_factory=list)
    extracted_urls: List[str] = field(default_factory=list)
    flagged_attachments: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TraditionalRuleEngine:
    """Deterministic, rule-based email threat inspector."""

    def __init__(self, custom_blacklist: Optional[List[str]] = None):
        self.blacklist = set(GLOBAL_BLACKLIST_DOMAINS)
        if custom_blacklist:
            self.blacklist.update(custom_blacklist)
        self.whitelist = set(GLOBAL_WHITELIST_DOMAINS)

    def extract_domain(self, email_str: str) -> str:
        """Extract domain part of an email address."""
        if not email_str:
            return ""
        # Match inside <...> if present
        match = re.search(r'<([^>]+)>', email_str)
        if match:
            email_str = match.group(1)
        if "@" in email_str:
            return email_str.split("@")[-1].strip().lower()
        return email_str.strip().lower()

    def analyze(self, email_data: Dict[str, Any]) -> Layer1Report:
        score = 0
        triggered: List[TriggeredRule] = []
        hard_block = False

        sender = email_data.get("sender", "")
        sender_name = email_data.get("sender_name", "")
        reply_to = email_data.get("reply_to", "")
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        headers = email_data.get("headers", {})
        attachments = email_data.get("attachments", [])

        sender_domain = self.extract_domain(sender)
        reply_domain = self.extract_domain(reply_to)

        # -------------------------------------------------------------
        # 1. Blacklist / Whitelist Check
        # -------------------------------------------------------------
        if sender_domain in self.blacklist:
            triggered.append(TriggeredRule(
                rule_id="RULE_BLACKLIST_HIT",
                category="Reputation",
                severity="CRITICAL",
                description=f"Sender domain '{sender_domain}' is on the global threat blacklist.",
                score_points=50
            ))
            score += 50
            hard_block = True

        # -------------------------------------------------------------
        # 2. Email Authentication Checks (SPF, DKIM, DMARC)
        # -------------------------------------------------------------
        spf = headers.get("SPF", "").lower()
        dkim = headers.get("DKIM", "").lower()
        dmarc = headers.get("DMARC", "").lower()

        if spf == "fail":
            triggered.append(TriggeredRule(
                rule_id="RULE_SPF_FAIL",
                category="Authentication",
                severity="HIGH",
                description="SPF verification failed: sending server not authorized for this domain.",
                score_points=25
            ))
            score += 25
        elif spf == "softfail":
            triggered.append(TriggeredRule(
                rule_id="RULE_SPF_SOFTFAIL",
                category="Authentication",
                severity="WARNING",
                description="SPF check softfailed: questionable server authorization.",
                score_points=12
            ))
            score += 12

        if dkim == "fail":
            triggered.append(TriggeredRule(
                rule_id="RULE_DKIM_FAIL",
                category="Authentication",
                severity="HIGH",
                description="DKIM cryptographic signature verification failed.",
                score_points=20
            ))
            score += 20

        if dmarc == "fail":
            triggered.append(TriggeredRule(
                rule_id="RULE_DMARC_FAIL",
                category="Authentication",
                severity="HIGH",
                description="DMARC policy enforcement failed.",
                score_points=25
            ))
            score += 25

        # -------------------------------------------------------------
        # 3. Sender Identity & Display Name Spoofing
        # -------------------------------------------------------------
        full_sender_str = f"{sender_name} {sender}".lower()
        for brand, legit_domains in BRAND_DOMAINS.items():
            if brand in full_sender_str:
                # Brand is claimed in name or sender
                if sender_domain not in legit_domains:
                    triggered.append(TriggeredRule(
                        rule_id="RULE_BRAND_IMPERSONATION",
                        category="Identity Spoofing",
                        severity="CRITICAL",
                        description=f"Display name claims to be '{brand.title()}', but sender domain '{sender_domain}' is not legitimate.",
                        score_points=35
                    ))
                    score += 35

        # Check Reply-To mismatch
        if reply_domain and sender_domain and reply_domain != sender_domain:
            # Check if reply domain is a disposable or free webmail service
            if any(free in reply_domain for free in ["temp-mail", "protonmail", "mailinator", "xyz"]):
                triggered.append(TriggeredRule(
                    rule_id="RULE_REPLYTO_MISMATCH",
                    category="Identity Spoofing",
                    severity="HIGH",
                    description=f"Mismatched Reply-To address ('{reply_domain}') routes replies away from '{sender_domain}'.",
                    score_points=25
                ))
                score += 25

        # Lookalike / Leetspeak / Typosquatting in domain
        lookalike_patterns = [
            (r'paypa[l1i]', 'PayPal lookalike'),
            (r'micros[0o]ft', 'Microsoft lookalike'),
            (r'g[0o]{2}gle', 'Google lookalike'),
            (r'arnaz[0o]n', 'Amazon lookalike'),
            (r'app[l1i]e', 'Apple lookalike')
        ]
        for pattern, brand_name in lookalike_patterns:
            if re.search(pattern, sender_domain):
                if not any(sender_domain.endswith(d) for d in [".google.com", ".paypal.com", ".microsoft.com", ".apple.com", ".amazon.com"]):
                    triggered.append(TriggeredRule(
                        rule_id="RULE_TYPOSQUATTING",
                        category="Domain Heuristics",
                        severity="CRITICAL",
                        description=f"Detected typosquatting/homoglyph domain ({brand_name}): '{sender_domain}'.",
                        score_points=40
                    ))
                    score += 40

        # High-risk TLD in sender domain
        for tld in SUSPICIOUS_TLDS:
            if sender_domain.endswith(tld):
                triggered.append(TriggeredRule(
                    rule_id="RULE_SUSPICIOUS_SENDER_TLD",
                    category="Domain Heuristics",
                    severity="HIGH",
                    description=f"Sender domain uses high-abuse top-level domain '{tld}'.",
                    score_points=20
                ))
                score += 20
                break

        # -------------------------------------------------------------
        # 4. Attachment Inspection
        # -------------------------------------------------------------
        flagged_att = []
        for att in attachments:
            att_lower = att.lower()
            # Double extension check: e.g., Invoice.pdf.exe
            if re.search(r'\.[a-z0-9]{2,4}\.(exe|scr|vbs|bat|js|cmd|pif)$', att_lower):
                triggered.append(TriggeredRule(
                    rule_id="RULE_DOUBLE_EXTENSION",
                    category="Malware Attachment",
                    severity="CRITICAL",
                    description=f"Dangerous double extension detected on attachment: '{att}'.",
                    score_points=50
                ))
                score += 50
                flagged_att.append(att)
                hard_block = True
            elif any(att_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                triggered.append(TriggeredRule(
                    rule_id="RULE_EXECUTABLE_ATTACHMENT",
                    category="Malware Attachment",
                    severity="CRITICAL",
                    description=f"High-risk executable attachment detected: '{att}'.",
                    score_points=50
                ))
                score += 50
                flagged_att.append(att)
                hard_block = True

        # -------------------------------------------------------------
        # 5. Link & URL Analysis
        # -------------------------------------------------------------
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        extracted_urls = urls

        for url in urls:
            url_lower = url.lower()
            # Raw IP URL check: http://192.168.1.1/...
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                triggered.append(TriggeredRule(
                    rule_id="RULE_RAW_IP_URL",
                    category="Malicious Links",
                    severity="HIGH",
                    description=f"Raw IP address used in link target instead of domain name: '{url}'.",
                    score_points=35
                ))
                score += 35

            # URL Shortener check
            if any(shortener in url_lower for shortener in URL_SHORTENERS):
                triggered.append(TriggeredRule(
                    rule_id="RULE_URL_SHORTENER",
                    category="Suspicious Links",
                    severity="WARNING",
                    description=f"Obfuscated link detected using URL shortener: '{url}'.",
                    score_points=15
                ))
                score += 15

            # High-risk TLD
            for tld in SUSPICIOUS_TLDS:
                if tld in url_lower:
                    triggered.append(TriggeredRule(
                        rule_id="RULE_SUSPICIOUS_TLD",
                        category="Suspicious Links",
                        severity="WARNING",
                        description=f"Link targets high-abuse top-level domain '{tld}'.",
                        score_points=15
                    ))
                    score += 15
                    break

        # -------------------------------------------------------------
        # 6. Pattern & Keyword Heuristics
        # -------------------------------------------------------------
        combined_text = f"{subject}\n{body}".lower()

        # Urgency & Fear Tactics
        urgency_regex = r'\b(urgent|immediate action|account suspended|frozen|terminated|act now|within 24 hours|24 hours to confirm|deadline|final notice)\b'
        urgency_matches = re.findall(urgency_regex, combined_text)
        if len(urgency_matches) >= 2:
            triggered.append(TriggeredRule(
                rule_id="RULE_URGENCY_TACTICS",
                category="Psychological Manipulation",
                severity="MEDIUM",
                description=f"Excessive urgency keywords detected: {', '.join(set(urgency_matches))}.",
                score_points=20
            ))
            score += 20

        # Credential Theft Phrases
        cred_regex = r'\b(verify your credentials|confirm password|login details|social security|credit card details|update billing|restore access|validate account)\b'
        cred_matches = re.findall(cred_regex, combined_text)
        if cred_matches:
            triggered.append(TriggeredRule(
                rule_id="RULE_CREDENTIAL_HARVESTING",
                category="Phishing Indicators",
                severity="HIGH",
                description=f"Credential harvesting trigger phrases: {', '.join(set(cred_matches))}.",
                score_points=25
            ))
            score += 25

        # Financial Scam / Prize / Crypto
        financial_regex = r'\b(lottery|won|allocated wallet|1\.85 btc|bitcoin deposit|airdrop|gas fee|inheritance|wire transfer|beneficiary routing)\b'
        fin_matches = re.findall(financial_regex, combined_text)
        if fin_matches:
            triggered.append(TriggeredRule(
                rule_id="RULE_FINANCIAL_LURE",
                category="Financial Fraud",
                severity="HIGH",
                description=f"Financial lure or crypto scam phrasing: {', '.join(set(fin_matches))}.",
                score_points=25
            ))
            score += 25

        # Excessive Capitalization & Exclamations
        if len(subject) > 10:
            caps_count = sum(1 for c in subject if c.isupper())
            caps_ratio = caps_count / len(subject)
            if caps_ratio > 0.40:
                triggered.append(TriggeredRule(
                    rule_id="RULE_EXCESSIVE_CAPS",
                    category="Spam Styling",
                    severity="WARNING",
                    description=f"Excessive capitalization in subject line ({int(caps_ratio*100)}% uppercase).",
                    score_points=12
                ))
                score += 12

        if "!!!" in subject or "!!!" in body:
            triggered.append(TriggeredRule(
                rule_id="RULE_EXCLAMATION_SPIKE",
                category="Spam Styling",
                severity="INFO",
                description="Repeated exclamation marks ('!!!') detected.",
                score_points=8
            ))
            score += 8

        # -------------------------------------------------------------
        # 7. Whitelist Bonus (Legitimate verification)
        # -------------------------------------------------------------
        if sender_domain in self.whitelist and spf == "pass" and dkim == "pass":
            # Reputable sender with valid cryptographic signatures
            score = max(0, score - 30)

        # Cap score between 0 and 100
        score = min(100, max(0, score))

        # Risk tier determination
        if hard_block or score >= 70:
            risk_tier = "CRITICAL" if hard_block else "HIGH"
        elif score >= 40:
            risk_tier = "MEDIUM"
        elif score >= 15:
            risk_tier = "LOW"
        else:
            risk_tier = "CLEAN"

        summary = (
            f"Layer 1 Risk Score: {score}/100 ({risk_tier}). "
            f"Triggered {len(triggered)} rule(s)."
        )

        return Layer1Report(
            score=score,
            risk_tier=risk_tier,
            is_hard_block=hard_block,
            triggered_rules=[t.__dict__ for t in triggered],
            extracted_urls=extracted_urls,
            flagged_attachments=flagged_att,
            summary=summary
        )
