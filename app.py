"""
FastAPI Server for DualShield Email Guard.
Serves the web dashboard, REST APIs for email scanning, mailbox simulation,
threat metrics, and ML model retraining.
"""

import os
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from layer1_traditional import TraditionalRuleEngine
from layer2_ml import MLEmailClassifier
from fusion_engine import DualShieldFusionEngine
from gmail_service import GmailSimulatorService
from sample_emails import SAMPLE_EMAILS

app = FastAPI(
    title="DualShield Email Guard",
    description="Two-layer Gmail spam and threat protection (Traditional Rules + Machine Learning)",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core services
rule_engine = TraditionalRuleEngine()
ml_classifier = MLEmailClassifier()
fusion_engine = DualShieldFusionEngine(rule_engine=rule_engine, ml_classifier=ml_classifier)
gmail_service = GmailSimulatorService(fusion_engine=fusion_engine)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)


class EmailScanRequest(BaseModel):
    id: Optional[str] = "custom_email"
    sender: str = Field(..., example="service@paypa1-security.com")
    sender_name: Optional[str] = Field("", example="PayPal Support")
    reply_to: Optional[str] = Field("", example="attacker@temp-mail.xyz")
    subject: str = Field(..., example="URGENT: Verify Your Account")
    body: str = Field(..., example="Click here to confirm password: http://192.168.1.1/login")
    headers: Optional[Dict[str, str]] = Field(default_factory=lambda: {"SPF": "none", "DKIM": "none", "DMARC": "none"})
    attachments: Optional[List[str]] = Field(default_factory=list)


class BlacklistDomainRequest(BaseModel):
    domain: str


@app.post("/api/scan")
def scan_email(payload: EmailScanRequest) -> Dict[str, Any]:
    """Inspect an email through Layer 1 (Heuristic) and Layer 2 (ML), returning verdict."""
    data = payload.model_dump()
    verdict = fusion_engine.inspect_email(data)
    return verdict.to_dict()


@app.post("/api/simulate-receive")
def simulate_receive_email(payload: EmailScanRequest) -> Dict[str, Any]:
    """Run email through DualShield and deposit it into the virtual Gmail mailbox."""
    data = payload.model_dump()
    verdict = gmail_service.process_incoming_email(data)
    return {
        "verdict": verdict.to_dict(),
        "mailbox_state": {
            "inbox_count": len(gmail_service.get_inbox_items()),
            "quarantine_count": len(gmail_service.get_quarantine_items()),
            "notifications_count": len(gmail_service.get_notifications())
        }
    }


@app.get("/api/samples")
def get_sample_emails() -> List[Dict[str, Any]]:
    """Return pre-configured realistic attack and benign samples."""
    return SAMPLE_EMAILS


@app.get("/api/inbox")
def get_inbox() -> List[Dict[str, Any]]:
    """Return emails in the simulated Gmail Inbox."""
    return gmail_service.get_inbox_items()


@app.get("/api/quarantine")
def get_quarantine() -> List[Dict[str, Any]]:
    """Return emails intercepted and quarantined by DualShield."""
    return gmail_service.get_quarantine_items()


@app.get("/api/notifications")
def get_notifications() -> List[Dict[str, Any]]:
    """Return simulated Gmail security alert notifications."""
    return gmail_service.get_notifications()


@app.get("/api/metrics")
def get_metrics() -> Dict[str, Any]:
    """Return threat detection counters and stats."""
    return gmail_service.get_metrics()


@app.post("/api/inbox/reset")
def reset_inbox() -> Dict[str, str]:
    """Reset simulated mailbox to default test dataset."""
    gmail_service.reset_inbox()
    return {"status": "success", "message": "Simulated mailbox reset successfully"}


@app.get("/api/rules")
def get_active_rules() -> Dict[str, Any]:
    """Return current blacklist, whitelist, and suspicious TLDs."""
    from layer1_traditional import SUSPICIOUS_TLDS, DANGEROUS_EXTENSIONS, BRAND_DOMAINS
    return {
        "blacklist": list(rule_engine.blacklist),
        "whitelist": list(rule_engine.whitelist),
        "suspicious_tlds": list(SUSPICIOUS_TLDS),
        "dangerous_extensions": list(DANGEROUS_EXTENSIONS),
        "protected_brands": list(BRAND_DOMAINS.keys())
    }


@app.post("/api/rules/blacklist")
def add_blacklist_domain(req: BlacklistDomainRequest) -> Dict[str, Any]:
    """Add a domain to Layer 1's active threat blacklist."""
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    rule_engine.blacklist.add(domain)
    return {"status": "success", "added_domain": domain, "total_blacklist_count": len(rule_engine.blacklist)}


@app.post("/api/train")
def retrain_model() -> Dict[str, Any]:
    """Retrain Layer 2 Machine Learning classifier and return benchmark metrics."""
    results = ml_classifier.train_and_save()
    return results


# Mount static directory and index route
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "DualShield Email Guard API is running. UI file index.html is being initialized."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
