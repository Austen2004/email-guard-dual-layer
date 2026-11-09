"""
Curated Realistic Email Dataset and Test Library for DualShield Email Guard.
Contains diverse samples of Ham (Legitimate), Phishing, Scams, Malware, and Marketing.
"""

SAMPLE_EMAILS = [
    {
        "id": "sample_phish_paypal",
        "category": "Phishing",
        "label": "Fake PayPal - Urgent Account Suspension",
        "sender": "service@paypa1-security-verification.com",
        "sender_name": "PayPal Support",
        "reply_to": "attacker-drop@temp-mail.xyz",
        "subject": "URGENT: Your PayPal Account Has Been Suspended - Verify Identity Immediately",
        "body": """Dear Customer,

We detected unusual login attempts to your PayPal account from an unrecognized IP address (Moscow, Russia).

For your protection, we have temporarily restricted your account. You have 24 hours to confirm your identity, or your funds will be permanently frozen.

Please click the secure link below to verify your login credentials, credit card details, and social security number:
http://185.220.101.5/paypal-login/verify.php?token=92837482

Do not ignore this warning. Immediate action is required.

Sincerely,
PayPal Security Team
Copyright 1999-2026 PayPal Inc.""",
        "headers": {
            "SPF": "fail",
            "DKIM": "fail",
            "DMARC": "fail",
            "Return-Path": "<bounce@paypa1-security-verification.com>"
        },
        "attachments": []
    },
    {
        "id": "sample_malware_invoice",
        "category": "Malware Lure",
        "label": "Malware Attachment - Overdue Invoice",
        "sender": "billing-department@quickbooks-invoicing-portal.com",
        "sender_name": "Accounting Services",
        "reply_to": "billing-department@quickbooks-invoicing-portal.com",
        "subject": "FINAL NOTICE: Overdue Invoice #INV-88392 Payment Required Today",
        "body": """Attached is your overdue invoice #INV-88392 totaling $4,850.00.

Failure to remit payment within 24 hours will result in immediate legal collection proceedings and reporting to credit bureaus.

Download and review the attached invoice details immediately. Enable macros if prompted to view encrypted billing lines.

Best regards,
Billing Operations Dept""",
        "headers": {
            "SPF": "softfail",
            "DKIM": "none",
            "DMARC": "none",
            "Return-Path": "<billing-department@quickbooks-invoicing-portal.com>"
        },
        "attachments": ["Invoice_INV88392_Overdue.pdf.exe"]
    },
    {
        "id": "sample_ceo_fraud",
        "category": "CEO Fraud / BEC",
        "label": "CEO Fraud - Confidential Wire Transfer",
        "sender": "ceo.tim.cook@apple-executives-office.com",
        "sender_name": "Tim Cook",
        "reply_to": "private.wire.desk77@protonmail.com",
        "subject": "CONFIDENTIAL: Urgent acquisition wire transfer needed today",
        "body": """Hi,

Are you at your desk? I am currently in an all-day executive board meeting with poor phone reception.

We are closing a confidential strategic acquisition today, and I need an urgent wire transfer of $78,500 processed before 4:00 PM EST.

Please respond immediately to this email so I can send you the escrow beneficiary routing details. Keep this strictly between us until the official press release tomorrow.

Thanks,
Tim Cook
Chief Executive Officer""",
        "headers": {
            "SPF": "pass",
            "DKIM": "none",
            "DMARC": "fail",
            "Return-Path": "<ceo.tim.cook@apple-executives-office.com>"
        },
        "attachments": []
    },
    {
        "id": "sample_crypto_scam",
        "category": "Advance Fee / Scam",
        "label": "Crypto Lottery / Prize Scam",
        "sender": "claim-reward@binance-giveaway-airdrop.xyz",
        "sender_name": "Binance Official Reward",
        "reply_to": "claim-reward@binance-giveaway-airdrop.xyz",
        "subject": "CONGRATULATIONS! You have won 1.85 BTC ($125,000 USD) in our 2026 Crypto Airdrop",
        "body": """You have been randomly selected as the 1st prize winner of our global community loyalty airdrop!

Your allocated wallet balance: 1.85000000 BTC.

To claim your prize, you must deposit 0.015 BTC to verify your receiving wallet address:
Bitcoin Deposit Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Once the network gas fee is confirmed, your 1.85 BTC will be credited instantly to your account.
Offer expires in 12 hours!

Binance Rewards Foundation""",
        "headers": {
            "SPF": "none",
            "DKIM": "none",
            "DMARC": "none",
            "Return-Path": "<claim-reward@binance-giveaway-airdrop.xyz>"
        },
        "attachments": []
    },
    {
        "id": "sample_marketing_borderline",
        "category": "Borderline Spam",
        "label": "Aggressive Marketing - Flash Sale Discount",
        "sender": "deals@mega-promotions-store.club",
        "sender_name": "MegaDeals",
        "reply_to": "support@mega-promotions-store.club",
        "subject": "LAST CHANCE! 90% OFF EVERYTHING - ACT FAST BEFORE MIDNIGHT!!!",
        "body": """DON'T MISS OUT!
Massive inventory clearance sale! Get up to 90% off electronics, smart watches, luxury sunglasses, and home gadgets!
Click here to claim your exclusive discount code:
https://bit.ly/megadeals-discount-2026

Buy 1 Get 2 FREE on all orders! Limited stock remaining!
Hurry before stock runs out forever!

Unsubscribe by clicking here: https://mega-promotions-store.club/opt-out""",
        "headers": {
            "SPF": "pass",
            "DKIM": "pass",
            "DMARC": "pass",
            "Return-Path": "<bounce@mega-promotions-store.club>"
        },
        "attachments": []
    },
    {
        "id": "sample_unverified_vendor",
        "category": "Suspicious / Notified",
        "label": "Unverified External Sender - Warning Banner Injected",
        "sender": "proposals@b2b-cloud-solutions.xyz",
        "sender_name": "CloudSolutions Sales",
        "reply_to": "proposals@b2b-cloud-solutions.xyz",
        "subject": "Action Required: Updated pricing proposal for AcmeTech team",
        "body": """Hi David,

Following up on our discussion last month regarding database migration. We have updated our enterprise quote.

Please review the attached pricing schedule before Friday. Let us know if you need any adjustments.

Best regards,
James Walker
Account Executive | CloudSolutions""",
        "headers": {
            "SPF": "softfail",
            "DKIM": "fail",
            "DMARC": "none",
            "Return-Path": "<bounce@b2b-cloud-solutions.xyz>"
        },
        "attachments": ["Proposal_Pricing_2026.pdf"]
    },
    {
        "id": "sample_legit_google_docs",
        "category": "Legitimate",
        "label": "Google Docs - Legitimate Collaboration",
        "sender": "comments-noreply@docs.google.com",
        "sender_name": "Google Docs",
        "reply_to": "comments-noreply@docs.google.com",
        "subject": "Sarah Miller commented on \"Q4 Product Roadmap & Sprint Planning\"",
        "body": """Hi Alex,

Sarah Miller added a comment on Q4 Product Roadmap & Sprint Planning:

\"Looks great! I left feedback on the technical milestones in section 3. Can we sync for 10 minutes tomorrow morning to finalize the launch date?\"

Open in Docs: https://docs.google.com/document/d/1a2b3c4d5e6f7g8h9/edit?usp=sharing

Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043
You are receiving this email because you are a collaborator on this document.""",
        "headers": {
            "SPF": "pass",
            "DKIM": "pass",
            "DMARC": "pass",
            "Return-Path": "<3w4e5r-comments-noreply@docs.google.com>"
        },
        "attachments": []
    },
    {
        "id": "sample_legit_work_meeting",
        "category": "Legitimate",
        "label": "Internal Team - Sprint Planning Meeting",
        "sender": "david.chen@acmetech.com",
        "sender_name": "David Chen",
        "reply_to": "david.chen@acmetech.com",
        "subject": "Sprint 42 Retrospective and Planning Agenda for Thursday",
        "body": """Hi team,

Here is our proposed agenda for Thursday's sprint planning session at 10:00 AM:

1. Sprint 42 retrospective notes (15 mins)
2. Review remaining backend tickets for API v2 release (20 mins)
3. Demo of new user onboarding flow (15 mins)
4. Estimation & story point assignment for Sprint 43 (20 mins)

Please review the Jira board prior to the meeting and add any blockers to the retro board.

Thanks,
David Chen
Engineering Lead | AcmeTech""",
        "headers": {
            "SPF": "pass",
            "DKIM": "pass",
            "DMARC": "pass",
            "Return-Path": "<david.chen@acmetech.com>"
        },
        "attachments": ["Sprint_42_Summary.pdf"]
    },
    {
        "id": "sample_legit_github_pr",
        "category": "Legitimate",
        "label": "GitHub - Pull Request Notification",
        "sender": "notifications@github.com",
        "sender_name": "GitHub Notifications",
        "reply_to": "reply+AB12CD34EF56@reply.github.com",
        "subject": "[my-org/auth-service] Pull Request #142: Fix token expiration refresh race condition",
        "body": """@octocat approved this pull request.

View pull request on GitHub: https://github.com/my-org/auth-service/pull/142

Commit summary:
- Fix race condition when refreshing expired JWTs
- Add unit tests for concurrent token renewal
- Update documentation in README.md

All CI tests passed (12 / 12 checks successful).
Ready to merge into main.""",
        "headers": {
            "SPF": "pass",
            "DKIM": "pass",
            "DMARC": "pass",
            "Return-Path": "<noreply@github.com>"
        },
        "attachments": []
    },
    {
        "id": "sample_legit_stripe_receipt",
        "category": "Legitimate",
        "label": "Stripe - Payment Receipt",
        "sender": "receipts@stripe.com",
        "sender_name": "Stripe Payments",
        "reply_to": "support@stripe.com",
        "subject": "Your receipt from Cloud Services Inc (#1984-2026)",
        "body": """Receipt from Cloud Services Inc
Amount paid: $29.00
Date: November 6, 2026
Payment method: Mastercard ending in 4242

Summary:
- Developer Pro Subscription (Nov 6 - Dec 6): $29.00

If you have any questions about this receipt, please visit https://support.stripe.com or contact Cloud Services Inc directly.

Stripe, 510 Townsend Street, San Francisco, CA 94103""",
        "headers": {
            "SPF": "pass",
            "DKIM": "pass",
            "DMARC": "pass",
            "Return-Path": "<receipts+bounce@stripe.com>"
        },
        "attachments": []
    }
]
