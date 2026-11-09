"""
Gmail Integration & Simulation Service for DualShield Email Guard.
Provides:
1. Simulated Gmail Inbox Engine (stores, routes, and simulates notifications).
2. Live Gmail IMAP / API Connector module for real-world Gmail integration.
"""

import imaplib
import email
from email.header import decode_header
from typing import Dict, List, Any, Optional
from datetime import datetime

from sample_emails import SAMPLE_EMAILS
from fusion_engine import DualShieldFusionEngine, DualShieldVerdict


class GmailSimulatorService:
    """Simulates an interactive Gmail mailbox managed by DualShield."""

    def __init__(self, fusion_engine: Optional[DualShieldFusionEngine] = None):
        self.fusion = fusion_engine or DualShieldFusionEngine()
        self.inbox: List[Dict[str, Any]] = []
        self.quarantine: List[Dict[str, Any]] = []
        self.notifications: List[Dict[str, Any]] = []
        self.scan_history: List[Dict[str, Any]] = []
        self.metrics = {
            "total_scanned": 0,
            "blocked_count": 0,
            "notified_count": 0,
            "allowed_count": 0,
            "layer1_critical_hits": 0,
            "layer2_ml_spam_hits": 0
        }

        # Initialize with pre-scanned sample emails
        self._seed_sample_inbox()

    def _seed_sample_inbox(self):
        """Seed the mailbox with standard demo emails."""
        for sample in SAMPLE_EMAILS:
            self.process_incoming_email(sample)

    def process_incoming_email(self, email_data: Dict[str, Any]) -> DualShieldVerdict:
        """Run email through dual layers, update mailbox folders, and emit notifications."""
        verdict: DualShieldVerdict = self.fusion.inspect_email(email_data)
        verdict_dict = verdict.to_dict()

        # Update Metrics
        self.metrics["total_scanned"] += 1
        if verdict.action == "BLOCKED":
            self.metrics["blocked_count"] += 1
        elif verdict.action == "NOTIFIED":
            self.metrics["notified_count"] += 1
        else:
            self.metrics["allowed_count"] += 1

        if verdict.layer1_report.get("is_hard_block") or verdict.layer1_report.get("score", 0) >= 50:
            self.metrics["layer1_critical_hits"] += 1
        if verdict.layer2_report.get("spam_probability", 0) >= 0.70:
            self.metrics["layer2_ml_spam_hits"] += 1

        # Mailbox Item Representation
        item = {
            "id": email_data.get("id", f"msg_{datetime.now().timestamp()}"),
            "sender": email_data.get("sender", "Unknown"),
            "sender_name": email_data.get("sender_name", ""),
            "reply_to": email_data.get("reply_to", ""),
            "subject": email_data.get("subject", "No Subject"),
            "original_body": email_data.get("body", ""),
            "body_with_banner": verdict.sanitized_email.get("body_with_banner", email_data.get("body", "")),
            "html_with_banner": verdict.sanitized_email.get("html_with_banner", ""),
            "headers": email_data.get("headers", {}),
            "attachments": email_data.get("attachments", []),
            "action": verdict.action,
            "threat_level": verdict.threat_level,
            "primary_reason": verdict.primary_reason,
            "layer1_score": verdict.layer1_report.get("score", 0),
            "layer1_rules": verdict.layer1_report.get("triggered_rules", []),
            "layer2_spam_prob": verdict.layer2_report.get("spam_probability", 0.0),
            "top_spam_features": verdict.layer2_report.get("top_spam_features", []),
            "top_ham_features": verdict.layer2_report.get("top_ham_features", []),
            "timestamp": verdict.timestamp,
            "folder": "Quarantine" if verdict.action == "BLOCKED" else "Inbox"
        }

        # Store in appropriate folder
        if verdict.action == "BLOCKED":
            self.quarantine.insert(0, item)
        else:
            self.inbox.insert(0, item)

        # Store notification if any
        if verdict.user_notification:
            self.notifications.insert(0, verdict.user_notification)

        self.scan_history.insert(0, {
            "id": item["id"],
            "sender": item["sender"],
            "subject": item["subject"],
            "action": verdict.action,
            "layer1_score": item["layer1_score"],
            "layer2_prob": item["layer2_spam_prob"],
            "timestamp": item["timestamp"]
        })

        return verdict

    def get_inbox_items(self) -> List[Dict[str, Any]]:
        return self.inbox

    def get_quarantine_items(self) -> List[Dict[str, Any]]:
        return self.quarantine

    def get_notifications(self) -> List[Dict[str, Any]]:
        return self.notifications

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics

    def reset_inbox(self):
        """Reset mailbox back to standard state."""
        self.inbox.clear()
        self.quarantine.clear()
        self.notifications.clear()
        self.scan_history.clear()
        self.metrics = {
            "total_scanned": 0,
            "blocked_count": 0,
            "notified_count": 0,
            "allowed_count": 0,
            "layer1_critical_hits": 0,
            "layer2_ml_spam_hits": 0
        }
        self._seed_sample_inbox()


class LiveGmailIMAPConnector:
    """
    Connects to real live Gmail via IMAP with App Passwords.
    Inspects new messages using the dual-layer engine.
    """

    def __init__(self, email_address: str, app_password: str,
                 fusion_engine: Optional[DualShieldFusionEngine] = None):
        self.email_address = email_address
        self.app_password = app_password
        self.fusion = fusion_engine or DualShieldFusionEngine()
        self.imap_server = "imap.gmail.com"

    def fetch_and_scan_unread(self, max_emails: int = 10) -> List[Dict[str, Any]]:
        """
        Connect to Gmail IMAP, search unread emails in INBOX,
        run them through DualShield, and return verdicts.
        """
        results = []
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server)
            mail.login(self.email_address, self.app_password)
            mail.select("INBOX")

            status, messages = mail.search(None, 'UNSEEN')
            if status != "OK" or not messages[0]:
                mail.close()
                mail.logout()
                return results

            msg_ids = messages[0].split()[-max_emails:]

            for msg_id in msg_ids:
                status, msg_data = mail.fetch(msg_id, "(RFC822)")
                if status != "OK":
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Decode Subject
                subject_header = decode_header(msg.get("Subject", ""))[0]
                subject = subject_header[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(subject_header[1] or "utf-8", errors="ignore")

                # Extract From and Reply-To
                sender = msg.get("From", "")
                reply_to = msg.get("Reply-To", sender)

                # Extract Headers
                spf = "pass" if "spf=pass" in msg.get("Received-SPF", "").lower() else "none"
                dkim = "pass" if "dkim=pass" in msg.get("Authentication-Results", "").lower() else "none"
                dmarc = "pass" if "dmarc=pass" in msg.get("Authentication-Results", "").lower() else "none"

                # Extract Body & Attachments
                body = ""
                attachments = []
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        disp = str(part.get("Content-Disposition"))
                        if content_type == "text/plain" and "attachment" not in disp:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode("utf-8", errors="ignore")
                        elif "attachment" in disp:
                            filename = part.get_filename()
                            if filename:
                                attachments.append(filename)
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="ignore")

                email_payload = {
                    "id": f"gmail_{msg_id.decode()}",
                    "sender": sender,
                    "sender_name": sender.split("<")[0].strip() if "<" in sender else "",
                    "reply_to": reply_to,
                    "subject": subject,
                    "body": body,
                    "headers": {"SPF": spf, "DKIM": dkim, "DMARC": dmarc},
                    "attachments": attachments
                }

                verdict = self.fusion.inspect_email(email_payload)
                results.append({
                    "email": email_payload,
                    "verdict": verdict.to_dict()
                })

            mail.close()
            mail.logout()
            return results

        except Exception as e:
            print(f"[Live Gmail IMAP Error]: {e}")
            return [{"error": str(e)}]
