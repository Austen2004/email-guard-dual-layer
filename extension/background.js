/**
 * DualShield Chrome Extension - Background Service Worker
 */

const API_BASE_URL = "http://127.0.0.1:8000";

// Listen for messages from content script or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "SCAN_EMAIL") {
    handleEmailScan(request.payload)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => {
        // Fallback to client-side heuristic inspection if server is offline
        const fallback = runClientSideHeuristics(request.payload);
        sendResponse({ success: true, data: fallback, isFallback: true, error: error.message });
      });
    return true; // Keep message channel open for async response
  }

  if (request.type === "CHECK_SERVER_STATUS") {
    fetch(`${API_BASE_URL}/api/metrics`)
      .then(res => res.json())
      .then(data => sendResponse({ online: true, metrics: data }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }
});

/**
 * Send email data to DualShield FastAPI backend
 */
async function handleEmailScan(emailData) {
  const response = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      sender: emailData.sender || "",
      sender_name: emailData.sender_name || "",
      reply_to: emailData.reply_to || "",
      subject: emailData.subject || "",
      body: emailData.body || "",
      headers: emailData.headers || { SPF: "none", DKIM: "none", DMARC: "none" },
      attachments: emailData.attachments || []
    })
  });

  if (!response.ok) {
    throw new Error(`Server returned HTTP ${response.status}`);
  }

  const verdict = await response.json();
  
  // Store last scan in local extension storage
  chrome.storage.local.set({ lastScan: verdict });
  
  return verdict;
}

/**
 * Client-Side Heuristic Fallback Engine
 * Runs directly in browser if backend server is not running
 */
function runClientSideHeuristics(emailData) {
  let score = 0;
  const rules = [];
  const sender = (emailData.sender || "").toLowerCase();
  const subject = (emailData.subject || "").toLowerCase();
  const body = (emailData.body || "").toLowerCase();
  const attachments = emailData.attachments || [];

  // 1. Phishing / Typosquatting checks
  if (sender.includes("paypa1") || sender.includes("micros0ft") || sender.includes("arnazon")) {
    score += 45;
    rules.push({ rule_id: "CLIENT_TYPOSQUATTING", description: "Lookalike typosquatted domain detected", score_points: 45 });
  }

  // 2. Raw IP link checks
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(body)) {
    score += 35;
    rules.push({ rule_id: "CLIENT_RAW_IP_URL", description: "Raw IP address link target detected", score_points: 35 });
  }

  // 3. Dangerous attachments
  for (const att of attachments) {
    if (/\.(exe|scr|vbs|bat|js)$/i.test(att) || /\.[a-z0-9]+\.(exe|scr)$/i.test(att)) {
      score += 50;
      rules.push({ rule_id: "CLIENT_MALWARE_ATTACHMENT", description: `Dangerous executable attachment: ${att}`, score_points: 50 });
    }
  }

  // 4. Urgency & Credential Theft
  if (/(account suspended|immediate action|verify your credentials|confirm password|within 24 hours)/i.test(`${subject} ${body}`)) {
    score += 30;
    rules.push({ rule_id: "CLIENT_URGENCY_PHISHING", description: "Urgent scare tactics or credential request detected", score_points: 30 });
  }

  let action = "ALLOWED";
  let threatLevel = "SAFE";
  let reason = "Email passed client heuristic security baseline.";

  if (score >= 60) {
    action = "BLOCKED";
    threatLevel = "CRITICAL";
    reason = "High heuristic risk detected: potential phishing or malware threat.";
  } else if (score >= 25) {
    action = "NOTIFIED";
    threatLevel = "SUSPICIOUS";
    reason = "Suspicious attributes detected. Exercise caution before clicking links.";
  }

  return {
    action: action,
    threat_level: threatLevel,
    primary_reason: reason,
    layer1_report: { score: score, triggered_rules: rules, risk_tier: threatLevel },
    layer2_report: { spam_probability: score > 50 ? 0.85 : 0.20, classification: score > 50 ? "SPAM" : "HAM" },
    timestamp: new Date().toLocaleTimeString()
  };
}
