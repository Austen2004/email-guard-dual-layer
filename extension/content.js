/**
 * DualShield Chrome Extension - Content Script for Gmail (mail.google.com)
 * Observes open emails in Gmail, sends them for Dual-Layer inspection,
 * and injects safety warning banners directly into the Gmail interface.
 */

console.log("[DualShield] Gmail Threat & Spam Guard loaded.");

let currentEmailId = null;

// Initialize observer to watch for opened emails in Gmail
function initGmailObserver() {
  const observer = new MutationObserver(() => {
    checkForOpenEmail();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

/**
 * Detect if an email thread or message is currently open in Gmail
 */
function checkForOpenEmail() {
  // Gmail selectors for email container and message body
  const emailBodyElem = document.querySelector(".a3s.aiL, .adn .ii.gt");
  if (!emailBodyElem) return;

  // Find the message container
  const messageContainer = emailBodyElem.closest(".adn, .adn.ads, [role='listitem'], .gs") || emailBodyElem.parentElement;
  if (!messageContainer) return;

  // Avoid re-scanning if already processed
  if (messageContainer.querySelector(".dualshield-banner-container")) return;

  // Extract email metadata
  const emailData = extractGmailData(messageContainer);
  if (!emailData || !emailData.subject && !emailData.body) return;

  // Prevent repeated scans of the exact same message
  const signature = `${emailData.sender}_${emailData.subject}_${emailData.body.slice(0, 50)}`;
  if (currentEmailId === signature) return;
  currentEmailId = signature;

  console.log("[DualShield] Inspecting open email:", emailData.subject, "from:", emailData.sender);

  // Show "Scanning..." placeholder banner
  injectScanningPlaceholder(messageContainer);

  // Request scan from DualShield service worker / backend
  chrome.runtime.sendMessage(
    { type: "SCAN_EMAIL", payload: emailData },
    (response) => {
      if (response && response.success) {
        injectVerdictBanner(messageContainer, response.data, response.isFallback);
      } else {
        removePlaceholder(messageContainer);
      }
    }
  );
}

/**
 * Extract sender, subject, body, links, and attachments from Gmail DOM
 */
function extractGmailData(container) {
  // 1. Subject (usually in h2.hP or top container)
  const subjectElem = document.querySelector("h2.hP, .ha h2");
  const subject = subjectElem ? subjectElem.innerText.trim() : "No Subject";

  // 2. Sender Name and Email
  const senderElem = container.querySelector("span[email], span.gD, .go");
  let sender = "";
  let senderName = "";

  if (senderElem) {
    sender = senderElem.getAttribute("email") || senderElem.innerText.trim();
    senderName = senderElem.getAttribute("name") || senderElem.innerText.trim();
  } else {
    const rawFrom = container.querySelector(".gE, .iw");
    if (rawFrom) sender = rawFrom.innerText.trim();
  }

  // 3. Body text
  const bodyElem = container.querySelector(".a3s.aiL, .ii.gt");
  const body = bodyElem ? bodyElem.innerText.trim() : "";

  // 4. Attachments
  const attachmentElems = container.querySelectorAll(".aZo, .aQH span, span[download_url]");
  const attachments = [];
  attachmentElems.forEach(el => {
    const name = el.innerText || el.getAttribute("download_url") || "";
    if (name) attachments.push(name.trim());
  });

  return {
    sender: sender || "unknown@sender.com",
    sender_name: senderName,
    subject: subject,
    body: body,
    attachments: attachments,
    headers: { SPF: "none", DKIM: "none", DMARC: "none" }
  };
}

/**
 * Inject visual "Scanning..." badge
 */
function injectScanningPlaceholder(container) {
  removePlaceholder(container);
  const placeholder = document.createElement("div");
  placeholder.className = "dualshield-banner-container dualshield-banner-scanning";
  placeholder.innerHTML = `
    <div class="dualshield-content">
      <span class="dualshield-spinner">🛡️</span>
      <span>DualShield: Scanning email through Two-Layer Defense (Heuristics + ML)...</span>
    </div>
  `;
  container.insertBefore(placeholder, container.firstChild);
}

function removePlaceholder(container) {
  const existing = container.querySelector(".dualshield-banner-container");
  if (existing) existing.remove();
}

/**
 * Inject the DualShield Safety / Warning / Clean Banner into Gmail
 */
function injectVerdictBanner(container, verdict, isFallback = false) {
  removePlaceholder(container);

  const banner = document.createElement("div");
  const action = verdict.action || "ALLOWED";
  const reason = verdict.primary_reason || "";
  const l1Score = verdict.layer1_report ? verdict.layer1_report.score : 0;
  const l2Prob = verdict.layer2_report ? Math.round(verdict.layer2_report.spam_probability * 100) : 0;

  banner.className = `dualshield-banner-container dualshield-banner-${action.toLowerCase()}`;

  let icon = "🛡️";
  let title = "DUALSHIELD SECURITY ALERT";
  let badgeColor = "#ef4444";

  if (action === "BLOCKED") {
    icon = "🚨";
    title = "DUALSHIELD BLOCKED: HIGH-RISK THREAT DETECTED";
    badgeColor = "#dc2626";
  } else if (action === "NOTIFIED") {
    icon = "⚠️";
    title = "DUALSHIELD WARNING: PROCEED WITH CAUTION";
    badgeColor = "#d97706";
  } else {
    icon = "✅";
    title = "VERIFIED SAFE BY DUALSHIELD";
    badgeColor = "#16a34a";
  }

  banner.innerHTML = `
    <div class="dualshield-banner-inner">
      <div class="dualshield-header">
        <div class="dualshield-title-wrap">
          <span class="dualshield-icon">${icon}</span>
          <span class="dualshield-title">${title}</span>
          <span class="dualshield-badge" style="background-color: ${badgeColor};">${action}</span>
          ${isFallback ? '<span class="dualshield-offline-tag">Local Heuristics</span>' : ''}
        </div>
        <span class="dualshield-close-btn" onclick="this.closest('.dualshield-banner-container').remove();">&times;</span>
      </div>
      <div class="dualshield-body">
        <p class="dualshield-reason"><strong>Analysis:</strong> ${reason}</p>
        <div class="dualshield-metrics-row">
          <span class="dualshield-metric-pill">Layer 1 (Heuristics): <strong>${l1Score} / 100</strong></span>
          <span class="dualshield-metric-pill">Layer 2 (ML Spam Prob): <strong>${l2Prob}%</strong></span>
          <span class="dualshield-metric-pill">Threat Level: <strong>${verdict.threat_level || 'NORMAL'}</strong></span>
        </div>
        ${action === 'NOTIFIED' ? `
          <ul class="dualshield-tips">
            <li>Verify the sender's real address before replying.</li>
            <li>Do not click unexpected links or download attachments.</li>
            <li>Legitimate companies never ask for passwords or 2FA codes via email.</li>
          </ul>
        ` : ''}
      </div>
    </div>
  `;

  // Insert at the top of the message container
  container.insertBefore(banner, container.firstChild);
}

// Start watching when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initGmailObserver);
} else {
  initGmailObserver();
}
