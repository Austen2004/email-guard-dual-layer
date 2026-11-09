/**
 * DualShield Chrome Extension - Popup Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  checkBackendStatus();
  loadLastScan();

  // Button: Scan Current Gmail Email
  document.getElementById("btn-scan-current").addEventListener("click", () => {
    scanActiveTab();
  });

  // Button: Open Full Web Dashboard
  document.getElementById("btn-open-dashboard").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://127.0.0.1:8000" });
  });
});

/**
 * Check if DualShield Python FastAPI backend is online
 */
function checkBackendStatus() {
  const statusPill = document.getElementById("status-indicator");
  const statusText = document.getElementById("status-text");

  chrome.runtime.sendMessage({ type: "CHECK_SERVER_STATUS" }, (response) => {
    if (response && response.online) {
      statusPill.className = "status-pill status-online";
      statusText.textContent = "Server Online";
    } else {
      statusPill.className = "status-pill status-offline";
      statusText.textContent = "Local Heuristics";
    }
  });
}

/**
 * Load and display the most recent email scan from storage
 */
function loadLastScan() {
  chrome.storage.local.get(["lastScan"], (result) => {
    if (result && result.lastScan) {
      displayVerdict(result.lastScan);
    }
  });
}

/**
 * Trigger active tab scan
 */
function scanActiveTab() {
  const btn = document.getElementById("btn-scan-current");
  btn.innerText = "Scanning Active Email...";
  btn.disabled = true;

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      btn.innerText = "⚡ Scan Open Gmail Email";
      btn.disabled = false;
      return;
    }

    const currentTab = tabs[0];
    if (!currentTab.url || !currentTab.url.includes("mail.google.com")) {
      alert("Please open Gmail (mail.google.com) and click on an email to scan it.");
      btn.innerText = "⚡ Scan Open Gmail Email";
      btn.disabled = false;
      return;
    }

    // Execute extraction script on tab
    chrome.scripting.executeScript({
      target: { tabId: currentTab.id },
      func: () => {
        const bodyElem = document.querySelector(".a3s.aiL, .adn .ii.gt");
        const subjectElem = document.querySelector("h2.hP, .ha h2");
        const senderElem = document.querySelector("span[email], span.gD");

        return {
          sender: senderElem ? (senderElem.getAttribute("email") || senderElem.innerText) : "",
          sender_name: senderElem ? (senderElem.getAttribute("name") || senderElem.innerText) : "",
          subject: subjectElem ? subjectElem.innerText : "",
          body: bodyElem ? bodyElem.innerText : ""
        };
      }
    }, (results) => {
      btn.innerText = "⚡ Scan Open Gmail Email";
      btn.disabled = false;

      if (results && results[0] && results[0].result) {
        const emailData = results[0].result;
        if (!emailData.subject && !emailData.body) {
          alert("No open email detected on this Gmail tab. Please click to open an email first.");
          return;
        }

        chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload: emailData }, (resp) => {
          if (resp && resp.success) {
            displayVerdict(resp.data);
          }
        });
      }
    });
  });
}

/**
 * Render verdict in popup UI
 */
function displayVerdict(verdict) {
  const verdictBox = document.getElementById("last-verdict-box");
  const verdictBadge = document.getElementById("verdict-badge");
  const breakdown = document.getElementById("breakdown-section");
  const l1ScoreText = document.getElementById("l1-score");
  const l1BarFill = document.getElementById("l1-bar-fill");
  const l2ProbText = document.getElementById("l2-prob");
  const l2BarFill = document.getElementById("l2-bar-fill");
  const reasonText = document.getElementById("verdict-reason-text");

  const action = verdict.action || "ALLOWED";
  verdictBadge.textContent = action;

  if (action === "BLOCKED") {
    verdictBadge.className = "badge badge-blocked";
  } else if (action === "NOTIFIED") {
    verdictBadge.className = "badge badge-notified";
  } else {
    verdictBadge.className = "badge badge-allowed";
  }

  breakdown.classList.remove("hidden");

  // Layer 1
  const l1Score = verdict.layer1_report ? verdict.layer1_report.score : 0;
  l1ScoreText.textContent = `${l1Score} / 100`;
  l1BarFill.style.width = `${Math.min(100, l1Score)}%`;
  l1BarFill.className = `fill ${l1Score >= 60 ? 'fill-rose' : (l1Score >= 35 ? 'fill-amber' : 'fill-green')}`;

  // Layer 2
  const l2Prob = verdict.layer2_report ? Math.round(verdict.layer2_report.spam_probability * 100) : 0;
  l2ProbText.textContent = `${l2Prob}%`;
  l2BarFill.style.width = `${Math.min(100, l2Prob)}%`;
  l2BarFill.className = `fill ${l2Prob >= 70 ? 'fill-rose' : (l2Prob >= 40 ? 'fill-amber' : 'fill-cyan')}`;

  reasonText.textContent = verdict.primary_reason || "Analyzed by DualShield Two-Layer Engine.";

  verdictBox.innerHTML = `
    <div style="font-size: 11.5px; color: #cbd5e1; padding: 4px 0;">
      <div><strong>Verdict:</strong> ${action} (${verdict.threat_level || 'NORMAL'})</div>
      <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Inspected at: ${verdict.timestamp || new Date().toLocaleTimeString()}</div>
    </div>
  `;
}
