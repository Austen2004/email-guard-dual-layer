"""
Layer 2: Machine Learning Classifier Engine.
Provides probabilistic classification using TF-IDF n-grams + Calibrated Linear Model,
complete with Explainable AI (XAI) feature attribution breakdown.
"""

import os
import re
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "spam_classifier.joblib")


@dataclass
class MLReport:
    spam_probability: float         # 0.0 to 1.0 (e.g., 0.94)
    ham_probability: float          # 0.0 to 1.0
    classification: str             # "SPAM" or "HAM"
    confidence: float               # Confidence percentage (e.g., 94.2%)
    top_spam_features: List[Dict[str, Any]] # Explainability: Words indicative of spam
    top_ham_features: List[Dict[str, Any]]  # Explainability: Words indicative of ham
    processed_text_snippet: str
    model_version: str = "v1.2-tfidf-logistic"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_training_corpus() -> Tuple[List[str], List[int]]:
    """
    Curated, high-fidelity synthetic corpus representing modern spam/phishing
    attacks alongside realistic business, personal, and transactional emails.
    Label 1 = SPAM / MALICIOUS / PHISHING
    Label 0 = HAM / LEGITIMATE
    """
    texts = []
    labels = []

    # ==================== SPAM / PHISHING SAMPLES (Label 1) ====================
    spam_templates = [
        "URGENT: Your account has been suspended! Click here to verify your credentials immediately within 24 hours.",
        "Your PayPal account is restricted due to unusual login from Russia. Confirm your password and credit card details now.",
        "Final notice: Overdue invoice #99281. Open the attached file and remit payment immediately or face legal action.",
        "Congratulations! You won 2.5 Bitcoin in our annual crypto lottery. Deposit 0.01 BTC to claim your wallet prize.",
        "Security Alert: Google Workspace password expired. Reset your password immediately by clicking the link below.",
        "Dear beneficiary, I am barrister Nelson holding $15.5 Million USD for you. Send your bank account and passport.",
        "ACT NOW! 90% discount on all designer watches and luxury handbags. Click here for limited time coupon code.",
        "Netflix payment failed! Update your credit card information immediately to prevent service disruption.",
        "USPS package delivery failed: Your parcel is on hold at distribution center. Pay $2.99 redelivery fee online.",
        "Urgent wire transfer needed. Are you available? I need you to transfer $45,000 to this vendor account before 3pm.",
        "You have received an encrypted secure message from Chase Bank. Log in to view your document.",
        "Hot singles in your neighborhood want to meet you! Register for free today.",
        "Make $5,000 a week working from home with no experience needed! Click here to start earning passive income.",
        "Your Microsoft 365 cloud subscription has expired. Renew today to avoid losing your mailbox and OneDrive files.",
        "Immediate action required: Unrecognized login detected on your Instagram account. Tap to verify identity.",
        "Invoice attached for your recent purchase of $1,299 Apple MacBook Pro. If you did not make this purchase, call support.",
        "Exclusive invitation: Join our VIP insider trading Telegram channel for 1000% crypto gains guaranteed.",
        "Free Amazon Gift Card! You have been selected to take a 30-second customer satisfaction survey to get $500.",
        "Tax refund notification: IRS has processed your tax return of $3,450. Submit your banking routing details.",
        "Confirm your identity: Suspicious activity detected on your Coinbase wallet. Unlock your digital assets now.",
        "FINAL WARNING: Your antivirus protection expired yesterday. Your PC is infected with 7 critical viruses.",
        "DHL Express: Tracking #8829140. Package delivery failed. Download shipping label attachment to reschedule.",
        "You have 1 unread voice message from Unknown Caller. Click audio player link to listen to recording.",
        "Confidential business proposal: Joint venture partnership with $25 million endowment fund.",
        "Urgent memo from Human Resources: Changes to employee health insurance benefits for 2026. Review policy.",
        "Earn double rewards on your crypto holdings! Stake Ethereum for 45% annual yield guaranteed returns.",
        "DocuSign: Please sign confidential contract agreement #DOC-9921 from external legal counsel.",
        "Dear Customer, your Apple ID has been locked for security reasons. Unlock your Apple account immediately.",
        "Win an iPhone 17 Pro Max! Click the wheel to spin and claim your free smartphone prize.",
        "Payment verification required: Credit card declined for your monthly order. Update billing method."
    ]

    for text in spam_templates:
        texts.append(text)
        labels.append(1)

    # Replicate with minor variations to bolster dataset size & variation
    for text in spam_templates:
        texts.append(f"Subject: Important Notification - {text}")
        labels.append(1)
        texts.append(f"FWD: Alert - {text} Please review as soon as possible.")
        labels.append(1)

    # ==================== HAM / LEGITIMATE SAMPLES (Label 0) ====================
    ham_templates = [
        "Hi Alex, can we reschedule our 1:1 meeting tomorrow to 3:30 PM? Let me know if that works for you.",
        "Here is the Q3 sprint retrospective summary and action items. Great job everyone on shipping the feature on time.",
        "Your GitHub pull request #42 has been reviewed and approved by Sarah. All continuous integration tests passed.",
        "Thanks for lunch yesterday! Let's definitely catch up again next week when you're back in the office.",
        "Attached is the draft slide deck for the client presentation on Thursday. Please add your comments in section 2.",
        "Your receipt from Stripe: Developer Pro subscription payment of $29.00 processed successfully.",
        "Google Calendar: Reminder - Team Architecture Sync is starting in 10 minutes in Room 4A and via Google Meet.",
        "Hi Mom, I arrived safely at the hotel. Weather is great here! Will call you on Saturday evening.",
        "Meeting notes from today's discussion with the design team: we decided to proceed with the minimalist layout.",
        "Your Amazon package with order #112-998341 has been delivered to your front porch. Have a great day!",
        "Quarterly financial report is available for review on the internal shared drive under Finance/2026.",
        "Please review the attached bug report regarding the pagination glitch on the customer dashboard.",
        "Doctor appointment confirmation: Your annual health checkup is scheduled for Wednesday at 9:00 AM.",
        "Thank you for your feedback on our product. Our engineering team is currently investigating the issue.",
        "Flight itinerary for your upcoming trip to Seattle: Flight UA 442 departing at 8:15 AM from Terminal 2.",
        "Hey everyone, the office coffee machine has been repaired and is working again in the breakroom.",
        "Weekly newsletter from TechCrunch: The latest developments in robotics, AI advancements, and startup funding.",
        "Here are the interview questions for our senior backend developer candidate coming in tomorrow.",
        "Your monthly electric utility bill of $74.20 is scheduled for automatic deduction on November 15.",
        "Great presentation this morning David! The client was very impressed with the API throughput benchmarks.",
        "Team lunch this Friday to celebrate Emma's birthday! Please vote on the restaurant options by Wednesday.",
        "Code review request: Added unit test coverage for user authentication and session revocation.",
        "Slack notification: You were mentioned by Michael in #engineering: 'Can you take a look at the logs?'",
        "Here is the agenda for our upcoming board of directors quarterly meeting on November 20.",
        "Your library books are due in 3 days. You can renew them online through your patron account.",
        "Thanks for submitting your expense report for the conference in Chicago. It has been approved.",
        "Summary of customer support tickets resolved this week: 98% satisfaction rating achieved.",
        "New comment on Jira ticket DEV-4091: 'Reproduced on staging environment, working on hotfix.'",
        "Hi everyone, please remember to submit your timesheets before Friday 5:00 PM.",
        "Your Uber ride receipt: $18.45 for your trip from Downtown to Central Station."
    ]

    for text in ham_templates:
        texts.append(text)
        labels.append(0)

    for text in ham_templates:
        texts.append(f"Subject: Project Update - {text}")
        labels.append(0)
        texts.append(f"RE: Follow up - {text} Thanks, have a wonderful weekend.")
        labels.append(0)

    return texts, labels


class MLEmailClassifier:
    """TF-IDF + Logistic Regression Classifier with Explainability."""

    def __init__(self):
        self.model: Optional[Pipeline] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[LogisticRegression] = None
        self._initialize_model()

    def _initialize_model(self):
        """Load trained model from disk or train fresh model if not found."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        if os.path.exists(MODEL_PATH):
            try:
                data = joblib.load(MODEL_PATH)
                self.model = data["pipeline"]
                self.vectorizer = self.model.named_steps["tfidf"]
                self.classifier = self.model.named_steps["clf"]
                return
            except Exception as e:
                print(f"[ML Engine] Failed loading saved model: {e}. Retraining...")

        self.train_and_save()

    def train_and_save(self) -> Dict[str, Any]:
        """Train classifier on corpus and save serialized artifact."""
        texts, labels = get_training_corpus()

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=3500,
                sublinear_tf=True,
                lowercase=True,
                stop_words="english"
            )),
            ("clf", LogisticRegression(
                C=2.5,
                max_iter=500,
                solver="liblinear",
                class_weight="balanced",
                random_state=42
            ))
        ])

        pipeline.fit(texts, labels)
        preds = pipeline.predict(texts)
        acc = accuracy_score(labels, preds)
        rep = classification_report(labels, preds, output_dict=True)

        self.model = pipeline
        self.vectorizer = pipeline.named_steps["tfidf"]
        self.classifier = pipeline.named_steps["clf"]

        joblib.dump({"pipeline": pipeline, "metrics": rep}, MODEL_PATH)

        return {
            "accuracy": float(acc),
            "samples_count": len(texts),
            "report": rep
        }

    def preprocess_email(self, email_data: Dict[str, Any]) -> str:
        """Combine sender, subject, and body into a normalized text representation."""
        sender = email_data.get("sender", "")
        sender_name = email_data.get("sender_name", "")
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")

        # Clean HTML tags if present
        clean_body = re.sub(r'<[^>]+>', ' ', body)
        clean_text = f"{sender_name} {sender} {subject} {clean_body}"
        return clean_text

    def predict(self, email_data: Dict[str, Any]) -> MLReport:
        """Analyze email and return probability, prediction, and XAI feature weights."""
        if self.model is None or self.classifier is None or self.vectorizer is None:
            self._initialize_model()

        text = self.preprocess_email(email_data)
        probs = self.model.predict_proba([text])[0]
        ham_prob = float(probs[0])
        spam_prob = float(probs[1])

        classification = "SPAM" if spam_prob >= 0.50 else "HAM"
        confidence = float(max(spam_prob, ham_prob) * 100.0)

        # -------------------------------------------------------------
        # Explainable AI (XAI): Feature Attribution
        # -------------------------------------------------------------
        # Extract features present in this specific email
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        coefs = self.classifier.coef_[0]

        # Transform email text to TF-IDF vector
        tfidf_vec = self.vectorizer.transform([text]).toarray()[0]
        active_indices = np.where(tfidf_vec > 0)[0]

        top_spam = []
        top_ham = []

        if len(active_indices) > 0:
            # Word contribution = TF-IDF weight * Model coefficient
            contributions = [
                (feature_names[i], float(tfidf_vec[i] * coefs[i]))
                for i in active_indices
            ]

            # Positive contribution -> points towards SPAM
            # Negative contribution -> points towards HAM
            spam_sorted = sorted([c for c in contributions if c[1] > 0], key=lambda x: x[1], reverse=True)
            ham_sorted = sorted([c for c in contributions if c[1] < 0], key=lambda x: x[1])

            top_spam = [{"token": token, "weight": round(weight, 3)} for token, weight in spam_sorted[:6]]
            top_ham = [{"token": token, "weight": round(abs(weight), 3)} for token, weight in ham_sorted[:6]]

        snippet = text[:150].strip() + ("..." if len(text) > 150 else "")

        return MLReport(
            spam_probability=round(spam_prob, 4),
            ham_probability=round(ham_prob, 4),
            classification=classification,
            confidence=round(confidence, 1),
            top_spam_features=top_spam,
            top_ham_features=top_ham,
            processed_text_snippet=snippet
        )
