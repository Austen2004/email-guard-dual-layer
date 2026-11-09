"""
DualShield Fusion & Policy Arbitration Engine.
Synthesizes Layer 1 (Traditional Heuristics) and Layer 2 (ML Classifier)
into actionable security enforcement: BLOCKED, NOTIFIED, or ALLOWED.
Generates Gmail-styled warning banners and push notification payloads.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from layer1_traditional import TraditionalRuleEngine, Layer1Report
from layer2_ml import MLEmailClassifier, MLReport


@dataclass
class UserNotification:
    title: str
    body: str
    urgency: str       # "CRITICAL", "WARNING", "INFO"
    action_type: str   # "QUARANTINE_ALERT", "SAFETY_BANNER", "DELIVERY_CONFIRMATION"
    timestamp: str


@dataclass
class DualShieldVerdict:
    action: str                     # "BLOCKED", "NOTIFIED", "ALLOWED"
    threat_level: str               # "CRITICAL", "HIGH", "SUSPICIOUS", "SAFE"
    primary_reason: str
    layer1_report: Dict[str, Any]
    layer2_report: Dict[str, Any]
    user_notification: Optional[Dict[str, Any]]
    injected_banner_html: Optional[str]
    injected_banner_text: Optional[str]
    sanitized_email: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DualShieldFusionEngine:
    """Ensemble arbiter balancing deterministic rules with probabilistic ML."""

    def __init__(self, rule_engine: Optional[TraditionalRuleEngine] = None,
                 ml_classifier: Optional[MLEmailClassifier] = None):
        self.layer1 = rule_engine or TraditionalRuleEngine()
        self.layer2 = ml_classifier or MLEmailClassifier()

    def inspect_email(self, email_data: Dict[str, Any]) -> DualShieldVerdict:
        """Execute full 2-layer inspection pipeline."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Step 1: Traditional Layer Inspection
        l1_report: Layer1Report = self.layer1.analyze(email_data)

        # Step 2: Machine Learning Layer Inspection
        l2_report: MLReport = self.layer2.predict(email_data)

        # Step 3: Arbitration & Decision Matrix
        score1 = l1_report.score
        hard_block = l1_report.is_hard_block
        prob2 = l2_report.spam_probability

        action = "ALLOWED"
        threat_level = "SAFE"
        primary_reason = "Email passed traditional heuristic checks and ML classification confidence."
        notification = None
        banner_html = None
        banner_text = None

        sender = email_data.get("sender", "Unknown")
        subject = email_data.get("subject", "No Subject")

        # --- Policy Decision Matrix ---
        if hard_block:
            action = "BLOCKED"
            threat_level = "CRITICAL"
            primary_reason = f"Layer 1 Critical Rule Violation: Dangerous attachment or blacklisted sender ({l1_report.risk_tier})."
        elif prob2 >= 0.70 and score1 >= 50:
            action = "BLOCKED"
            threat_level = "CRITICAL"
            primary_reason = f"Dual-Layer Consensus: High heuristic score ({score1}/100) and high ML spam confidence ({int(prob2*100)}%)."
        elif prob2 >= 0.88:
            action = "BLOCKED"
            threat_level = "HIGH"
            primary_reason = f"Layer 2 Strong ML Threat: {int(prob2*100)}% spam/phishing probability."
        elif score1 >= 75:
            action = "BLOCKED"
            threat_level = "HIGH"
            primary_reason = f"Layer 1 Severe Risk: Score of {score1}/100 exceeds critical block threshold."
        elif score1 >= 35 or prob2 >= 0.45:
            action = "NOTIFIED"
            threat_level = "SUSPICIOUS"
            if score1 >= 35 and prob2 >= 0.45:
                primary_reason = f"Suspicious Email: Both heuristic flags ({score1} pts) and elevated ML score ({int(prob2*100)}%) require user vigilance."
            elif score1 >= 35:
                primary_reason = f"Suspicious Attributes: Traditional checks flagged potential spoofing or unverified authentication ({score1} pts)."
            else:
                primary_reason = f"ML Anomaly Alert: Machine learning classifier detected spam pattern ({int(prob2*100)}% probability)."
        else:
            action = "ALLOWED"
            threat_level = "SAFE"
            primary_reason = f"Clean Email: Traditional score ({score1}/100) and ML spam probability ({int(prob2*100)}%) are well below thresholds."

        # --- Generate Notifications & Safety Injections ---
        if action == "BLOCKED":
            notification = UserNotification(
                title=f"🚨 [BLOCKED] Threat Intercepted from {sender}",
                body=f"DualShield blocked an email with subject: '{subject}'. Reason: {primary_reason}. The message was quarantined safely.",
                urgency="CRITICAL",
                action_type="QUARANTINE_ALERT",
                timestamp=now_str
            )
            banner_html = f"""<div style="background-color: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 14px; margin-bottom: 16px; font-family: sans-serif;">
                <div style="display: flex; align-items: center; gap: 8px; color: #b91c1c; font-weight: bold; font-size: 15px;">
                    <span>🛡️ DUALSHIELD SECURITY: MESSAGE BLOCKED & QUARANTINED</span>
                </div>
                <p style="color: #7f1d1d; margin: 6px 0 0 0; font-size: 13px;">
                    <strong>Threat Reason:</strong> {primary_reason}
                </p>
                <p style="color: #991b1b; margin: 4px 0 0 0; font-size: 12px;">
                    This message was automatically isolated from your Gmail inbox. Do not reply or open attachments.
                </p>
            </div>"""
            banner_text = f"[DUALSHIELD BLOCKED] THREAT INTERCEPTED: {primary_reason}\n"

        elif action == "NOTIFIED":
            notification = UserNotification(
                title=f"⚠️ [WARNING] Suspicious Email: {subject[:40]}...",
                body=f"DualShield flagged incoming email from {sender}. Review carefully before clicking links or replying.",
                urgency="WARNING",
                action_type="SAFETY_BANNER",
                timestamp=now_str
            )
            banner_html = f"""<div style="background-color: #fffbeb; border: 2px solid #f59e0b; border-radius: 8px; padding: 14px; margin-bottom: 16px; font-family: sans-serif;">
                <div style="display: flex; align-items: center; gap: 8px; color: #b45309; font-weight: bold; font-size: 15px;">
                    <span>⚠️ DUALSHIELD WARNING: PROCEED WITH CAUTION</span>
                </div>
                <p style="color: #92400e; margin: 6px 0 0 0; font-size: 13px;">
                    <strong>Alert:</strong> {primary_reason}
                </p>
                <ul style="color: #78350f; margin: 6px 0 0 16px; padding: 0; font-size: 12px;">
                    <li>Verify the sender's actual address ({sender}) before replying.</li>
                    <li>Avoid clicking any unverified links or downloading attachments.</li>
                    <li>Never provide passwords, credit cards, or two-factor codes via email.</li>
                </ul>
            </div>"""
            banner_text = f"[DUALSHIELD CAUTION] SUSPICIOUS MESSAGE: {primary_reason}\n"

        else: # ALLOWED
            banner_html = f"""<div style="background-color: #f0fdf4; border: 1px solid #86efac; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-family: sans-serif;">
                <span style="color: #166534; font-size: 12px; font-weight: 600;">
                    ✓ Verified Safe by DualShield (Layer 1: {score1}/100, Layer 2 ML: {int(prob2*100)}% spam prob)
                </span>
            </div>"""
            banner_text = "[DUALSHIELD] Verified Safe\n"

        # Prepare sanitized email object with banner prepended
        sanitized = dict(email_data)
        original_body = sanitized.get("body", "")
        if banner_text:
            sanitized["body_with_banner"] = f"{banner_text}\n{original_body}"
        if banner_html:
            sanitized["html_with_banner"] = f"{banner_html}\n<div>{original_body.replace(chr(10), '<br>')}</div>"

        return DualShieldVerdict(
            action=action,
            threat_level=threat_level,
            primary_reason=primary_reason,
            layer1_report=l1_report.to_dict(),
            layer2_report=l2_report.to_dict(),
            user_notification=notification.__dict__ if notification else None,
            injected_banner_html=banner_html,
            injected_banner_text=banner_text,
            sanitized_email=sanitized,
            timestamp=now_str
        )
