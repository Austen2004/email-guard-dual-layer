"""
DualShield - Live Gmail Scanner CLI Utility.
Prompts for Gmail credentials and scans your unread incoming emails.
"""

import sys
import getpass
from gmail_service import LiveGmailIMAPConnector

def main():
    print("=" * 65)
    print(" 🛡️  DualShield Email Guard - Live Gmail Scanner")
    print("=" * 65)
    print("This tool connects to your real Gmail account via IMAP and scans")
    print("your unread emails using the Two-Layer Defense system.\n")
    print("NOTE: You need a 16-letter Google App Password.")
    print("Generate one here: https://myaccount.google.com/apppasswords\n")

    # Prompt user for credentials
    email_address = input("Enter your Gmail address: ").strip()
    if not email_address or "@" not in email_address:
        print("❌ Error: Invalid email address.")
        sys.exit(1)

    app_password = getpass.getpass("Enter your 16-character App Password (hidden): ").strip()
    # Remove any spaces the user might have pasted (Google displays them as 'xxxx xxxx xxxx xxxx')
    app_password = app_password.replace(" ", "")

    if len(app_password) < 14:
        print("❌ Warning: Google App Passwords are usually 16 characters.")

    print(f"\nConnecting to imap.gmail.com for {email_address}...")
    connector = LiveGmailIMAPConnector(email_address=email_address, app_password=app_password)

    print("Fetching and scanning unread emails (up to 5)...\n")
    results = connector.fetch_and_scan_unread(max_emails=5)

    if not results:
        print("ℹ️  No unread emails found in your INBOX.")
        print("👉 Tip: Open Gmail, mark an email as UNREAD (or send yourself a test email), then run this tool again.")
        return

    for idx, item in enumerate(results, 1):
        if "error" in item:
            print(f"❌ Connection Error: {item['error']}")
            print("👉 Check that 2-Step Verification is ON and your App Password is typed correctly.")
            return

        v = item["verdict"]
        email_data = item["email"]
        action = v.get("action", "UNKNOWN")
        subject = email_data.get("subject", "No Subject")
        sender = email_data.get("sender", "Unknown")
        l1_score = v.get("layer1_report", {}).get("score", 0)
        l2_prob = int(v.get("layer2_report", {}).get("spam_probability", 0) * 100)

        # Print formatted verdict
        print("-" * 65)
        if action == "BLOCKED":
            print(f"[{idx}] 🚨 ACTION: [BLOCKED & QUARANTINED]")
        elif action == "NOTIFIED":
            print(f"[{idx}] ⚠️ ACTION: [NOTIFIED - WARNING BANNER INJECTED]")
        else:
            print(f"[{idx}] ✅ ACTION: [ALLOWED - VERIFIED SAFE]")

        print(f"    From:    {sender}")
        print(f"    Subject: {subject}")
        print(f"    Scores:  Layer 1 (Heuristic): {l1_score}/100 | Layer 2 (ML): {l2_prob}% spam prob")
        print(f"    Reason:  {v.get('primary_reason', '')}")

    print("-" * 65)
    print("Scan complete.")

if __name__ == "__main__":
    main()
