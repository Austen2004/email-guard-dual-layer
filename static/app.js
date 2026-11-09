/**
 * DualShield Email Guard - Frontend Application Logic
 */

let sampleEmails = [];
let currentMailboxFolder = 'inbox';
let allInboxItems = [];
let allQuarantineItems = [];
let allNotifications = [];
let activeMailboxItem = null;

// Initialize on page load
document.addEventListener("DOMContentLoaded", async () => {
    await loadSamples();
    await refreshMetrics();
    await refreshMailbox();
    await loadRules();

    // Auto-select first sample email for instant demo
    if (sampleEmails.length > 0) {
        document.getElementById("sample-select").value = sampleEmails[0].id;
        loadSelectedSample();
        analyzeCurrentEmail();
    }
});

// Switch Main Navigation Tabs
function switchTab(tabName) {
    document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
    document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));

    const targetSection = document.getElementById(`tab-${tabName}`);
    const targetBtn = document.getElementById(`tab-btn-${tabName}`);

    if (targetSection) targetSection.classList.remove("hidden");
    if (targetBtn) targetBtn.classList.add("active");

    if (tabName === 'inbox') {
        refreshMailbox();
    } else if (tabName === 'analytics') {
        refreshMetrics();
    } else if (tabName === 'rules') {
        loadRules();
    }
}

// -------------------------------------------------------------
// Sample Email Loader & Form Handling
// -------------------------------------------------------------
async function loadSamples() {
    try {
        const res = await fetch("/api/samples");
        sampleEmails = await res.json();
        const select = document.getElementById("sample-select");
        select.innerHTML = '<option value="">-- Choose a Demo Scenario --</option>';

        sampleEmails.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.id;
            opt.textContent = `[${s.category}] ${s.label}`;
            select.appendChild(opt);
        });
    } catch (err) {
        console.error("Failed to load sample emails:", err);
    }
}

function loadSelectedSample() {
    const id = document.getElementById("sample-select").value;
    const sample = sampleEmails.find(s => s.id === id);
    if (!sample) return;

    document.getElementById("email-sender").value = sample.sender || "";
    document.getElementById("email-sender-name").value = sample.sender_name || "";
    document.getElementById("email-reply-to").value = sample.reply_to || "";
    document.getElementById("email-subject").value = sample.subject || "";
    document.getElementById("email-body").value = sample.body || "";

    const headers = sample.headers || {};
    document.getElementById("email-spf").value = headers.SPF || "none";
    document.getElementById("email-dkim").value = headers.DKIM || "none";
    document.getElementById("email-dmarc").value = headers.DMARC || "none";

    document.getElementById("email-attachments").value = (sample.attachments || []).join(", ");
}

function getFormData() {
    const rawAtt = document.getElementById("email-attachments").value;
    const attachments = rawAtt.split(",").map(a => a.trim()).filter(a => a.length > 0);

    return {
        sender: document.getElementById("email-sender").value.trim(),
        sender_name: document.getElementById("email-sender-name").value.trim(),
        reply_to: document.getElementById("email-reply-to").value.trim(),
        subject: document.getElementById("email-subject").value.trim(),
        body: document.getElementById("email-body").value.trim(),
        headers: {
            SPF: document.getElementById("email-spf").value,
            DKIM: document.getElementById("email-dkim").value,
            DMARC: document.getElementById("email-dmarc").value
        },
        attachments: attachments
    };
}

// -------------------------------------------------------------
// Core Scanner Action
// -------------------------------------------------------------
async function analyzeCurrentEmail() {
    const payload = getFormData();
    if (!payload.sender || !payload.subject) {
        alert("Please provide at least a Sender and Subject.");
        return;
    }

    const btn = document.getElementById("btn-scan");
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="animate-spin mr-2">⚙️</span> Analyzing...`;
    btn.disabled = true;

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const verdict = await res.json();
        renderScanResults(verdict);

        // Show toast notification if present
        if (verdict.user_notification) {
            showToast(verdict.user_notification);
        }

    } catch (err) {
        console.error("Scan failed:", err);
        alert("Error analyzing email. Check backend logs.");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function deliverToSimulatedInbox() {
    const payload = getFormData();
    try {
        const res = await fetch("/api/simulate-receive", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        renderScanResults(data.verdict);
        if (data.verdict.user_notification) {
            showToast(data.verdict.user_notification);
        }
        await refreshMailbox();
        await refreshMetrics();
    } catch (err) {
        console.error("Simulation failed:", err);
    }
}

// -------------------------------------------------------------
// Render Inspection Results
// -------------------------------------------------------------
function renderScanResults(v) {
    const vCard = document.getElementById("verdict-card");
    const vIcon = document.getElementById("verdict-icon-box");
    const vBadge = document.getElementById("verdict-badge");
    const vThreat = document.getElementById("verdict-threat-tag");
    const vTitle = document.getElementById("verdict-title");
    const vReason = document.getElementById("verdict-reason");
    const vTime = document.getElementById("verdict-time");

    vCard.classList.remove("hidden", "bg-rose-950/40", "border-rose-700", "bg-amber-950/40", "border-amber-700", "bg-emerald-950/40", "border-emerald-700");

    if (v.action === "BLOCKED") {
        vCard.classList.add("bg-rose-950/40", "border-rose-700");
        vIcon.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-rose-500/20 text-rose-400";
        vIcon.textContent = "🛡️";
        vBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-600 text-white";
        vBadge.textContent = "BLOCKED & QUARANTINED";
        vThreat.textContent = `Threat Level: ${v.threat_level}`;
        vTitle.textContent = "Dangerous Email Intercepted";
    } else if (v.action === "NOTIFIED") {
        vCard.classList.add("bg-amber-950/40", "border-amber-700");
        vIcon.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-amber-500/20 text-amber-400";
        vIcon.textContent = "⚠️";
        vBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-600 text-white";
        vBadge.textContent = "NOTIFIED & WARNING INJECTED";
        vThreat.textContent = `Threat Level: ${v.threat_level}`;
        vTitle.textContent = "Suspicious Email Flagged";
    } else {
        vCard.classList.add("bg-emerald-950/40", "border-emerald-700");
        vIcon.className = "w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-emerald-500/20 text-emerald-400";
        vIcon.textContent = "✅";
        vBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-600 text-white";
        vBadge.textContent = "ALLOWED / VERIFIED SAFE";
        vThreat.textContent = `Threat Level: ${v.threat_level}`;
        vTitle.textContent = "Clean Email Delivered";
    }

    vReason.textContent = v.primary_reason;
    vTime.textContent = v.timestamp;

    // --- Render Layer 1 ---
    const l1 = v.layer1_report;
    const l1Score = l1.score || 0;
    document.getElementById("l1-score-text").textContent = `${l1Score} / 100`;
    const l1Bar = document.getElementById("l1-progress-bar");
    l1Bar.style.width = `${l1Score}%`;

    if (l1Score >= 60) {
        l1Bar.className = "h-full bg-rose-500 rounded-full transition-all duration-500";
    } else if (l1Score >= 35) {
        l1Bar.className = "h-full bg-amber-500 rounded-full transition-all duration-500";
    } else {
        l1Bar.className = "h-full bg-emerald-500 rounded-full transition-all duration-500";
    }

    const l1Badge = document.getElementById("l1-badge");
    l1Badge.textContent = l1.risk_tier || "CLEAN";
    l1Badge.className = `px-2 py-0.5 text-xs font-bold rounded ${
        l1.risk_tier === 'CRITICAL' ? 'bg-rose-900 text-rose-300' :
        l1.risk_tier === 'HIGH' ? 'bg-rose-800 text-rose-200' :
        l1.risk_tier === 'MEDIUM' ? 'bg-amber-900 text-amber-200' :
        l1.risk_tier === 'LOW' ? 'bg-slate-700 text-slate-300' :
        'bg-emerald-900 text-emerald-300'
    }`;

    document.getElementById("l1-hardblock-flag").textContent = `HardBlock: ${l1.is_hard_block ? 'TRUE' : 'False'}`;

    const rulesList = document.getElementById("l1-rules-list");
    rulesList.innerHTML = "";
    if (l1.triggered_rules && l1.triggered_rules.length > 0) {
        l1.triggered_rules.forEach(r => {
            const div = document.createElement("div");
            div.className = "p-2 rounded bg-slate-900/90 border border-slate-700/60";
            div.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="font-bold text-slate-200">${r.rule_id}</span>
                    <span class="px-1.5 py-0.2 text-[10px] rounded font-bold ${
                        r.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400' :
                        r.severity === 'HIGH' ? 'bg-rose-900/60 text-rose-300' :
                        'bg-amber-950 text-amber-300'
                    }">+${r.score_points} pts</span>
                </div>
                <p class="text-[11px] text-slate-400 mt-0.5">${r.description}</p>
            `;
            rulesList.appendChild(div);
        });
    } else {
        rulesList.innerHTML = `<p class="text-emerald-400 text-xs">✓ No heuristic or blacklist violations triggered.</p>`;
    }

    // --- Render Layer 2 (ML) ---
    const l2 = v.layer2_report;
    const spamProb = Math.round((l2.spam_probability || 0) * 100);
    document.getElementById("l2-prob-text").textContent = `${spamProb}%`;
    const l2Bar = document.getElementById("l2-progress-bar");
    l2Bar.style.width = `${spamProb}%`;

    if (spamProb >= 70) {
        l2Bar.className = "h-full bg-rose-500 rounded-full transition-all duration-500";
    } else if (spamProb >= 40) {
        l2Bar.className = "h-full bg-amber-500 rounded-full transition-all duration-500";
    } else {
        l2Bar.className = "h-full bg-cyan-500 rounded-full transition-all duration-500";
    }

    const l2Badge = document.getElementById("l2-badge");
    l2Badge.textContent = `${l2.classification || 'HAM'} (${Math.round(l2.confidence || 0)}%)`;
    l2Badge.className = `px-2 py-0.5 text-xs font-bold rounded ${
        l2.classification === 'SPAM' ? 'bg-rose-900 text-rose-300' : 'bg-cyan-900 text-cyan-300'
    }`;
    document.getElementById("l2-confidence-text").textContent = `Confidence: ${Math.round(l2.confidence || 0)}%`;

    // Explainable AI Tokens
    const spamTokensContainer = document.getElementById("l2-spam-tokens");
    spamTokensContainer.innerHTML = "";
    if (l2.top_spam_features && l2.top_spam_features.length > 0) {
        l2.top_spam_features.forEach(t => {
            const chip = document.createElement("span");
            chip.className = "px-2 py-0.5 rounded-full bg-rose-950/80 border border-rose-800 text-rose-300";
            chip.textContent = `${t.token} (+${t.weight})`;
            spamTokensContainer.appendChild(chip);
        });
    } else {
        spamTokensContainer.innerHTML = `<span class="text-slate-500 italic text-[11px]">None</span>`;
    }

    const hamTokensContainer = document.getElementById("l2-ham-tokens");
    hamTokensContainer.innerHTML = "";
    if (l2.top_ham_features && l2.top_ham_features.length > 0) {
        l2.top_ham_features.forEach(t => {
            const chip = document.createElement("span");
            chip.className = "px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-300";
            chip.textContent = `${t.token} (-${t.weight})`;
            hamTokensContainer.appendChild(chip);
        });
    } else {
        hamTokensContainer.innerHTML = `<span class="text-slate-500 italic text-[11px]">None</span>`;
    }

    // --- Gmail User Preview Injected HTML ---
    const preview = document.getElementById("gmail-injected-preview");
    if (v.sanitized_email && v.sanitized_email.html_with_banner) {
        preview.innerHTML = v.sanitized_email.html_with_banner;
    } else {
        preview.innerHTML = `
            ${v.injected_banner_html || ''}
            <div class="text-slate-800 whitespace-pre-wrap">${document.getElementById("email-body").value}</div>
        `;
    }
}

// -------------------------------------------------------------
// Toast Notification (Simulated Gmail Alert)
// -------------------------------------------------------------
function showToast(notif) {
    const toast = document.getElementById("gmail-toast");
    const title = document.getElementById("toast-title");
    const body = document.getElementById("toast-body");
    const badge = document.getElementById("toast-badge");
    const iconWrap = document.getElementById("toast-icon-wrapper");

    title.textContent = notif.title;
    body.textContent = notif.body;

    if (notif.urgency === "CRITICAL") {
        badge.textContent = "CRITICAL ALERT";
        badge.className = "text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider bg-rose-600 text-white";
        iconWrap.className = "w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-rose-500/20 text-rose-400 text-xl";
        iconWrap.textContent = "🚨";
    } else if (notif.urgency === "WARNING") {
        badge.textContent = "SECURITY WARNING";
        badge.className = "text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider bg-amber-600 text-white";
        iconWrap.className = "w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-amber-500/20 text-amber-400 text-xl";
        iconWrap.textContent = "⚠️";
    } else {
        badge.textContent = "INFO";
        badge.className = "text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider bg-cyan-600 text-white";
        iconWrap.className = "w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-cyan-500/20 text-cyan-400 text-xl";
        iconWrap.textContent = "ℹ️";
    }

    toast.classList.remove("translate-y-[-150%]", "opacity-0");
    toast.classList.add("translate-y-0", "opacity-100");

    setTimeout(() => {
        dismissToast();
    }, 6000);
}

function dismissToast() {
    const toast = document.getElementById("gmail-toast");
    toast.classList.add("translate-y-[-150%]", "opacity-0");
    toast.classList.remove("translate-y-0", "opacity-100");
}

// -------------------------------------------------------------
// Simulated Gmail Mailbox Tabs & Viewer
// -------------------------------------------------------------
async function refreshMailbox() {
    try {
        const [inboxRes, quarRes, notifRes] = await Promise.all([
            fetch("/api/inbox"),
            fetch("/api/quarantine"),
            fetch("/api/notifications")
        ]);

        allInboxItems = await inboxRes.json();
        allQuarantineItems = await quarRes.json();
        allNotifications = await notifRes.json();

        document.getElementById("folder-count-inbox").textContent = allInboxItems.length;
        document.getElementById("folder-count-quarantine").textContent = allQuarantineItems.length;
        document.getElementById("folder-count-notifications").textContent = allNotifications.length;
        document.getElementById("badge-inbox-count").textContent = allInboxItems.length;

        renderMailboxList();
    } catch (err) {
        console.error("Failed refreshing mailbox:", err);
    }
}

function filterMailbox(folder) {
    currentMailboxFolder = folder;
    document.querySelectorAll(".folder-btn").forEach(b => b.classList.remove("active"));
    const btn = document.getElementById(`folder-btn-${folder}`);
    if (btn) btn.classList.add("active");
    renderMailboxList();
}

function renderMailboxList() {
    const list = document.getElementById("mailbox-list");
    list.innerHTML = "";

    let items = [];
    if (currentMailboxFolder === 'inbox') items = allInboxItems;
    else if (currentMailboxFolder === 'quarantine') items = allQuarantineItems;
    else if (currentMailboxFolder === 'notifications') items = allNotifications;

    if (items.length === 0) {
        list.innerHTML = `<div class="p-6 text-center text-slate-500 text-xs italic">Folder is empty.</div>`;
        return;
    }

    if (currentMailboxFolder === 'notifications') {
        items.forEach((n, idx) => {
            const div = document.createElement("div");
            div.className = "p-3 rounded-xl bg-slate-800/80 border border-slate-700/80 mb-2 cursor-default";
            div.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="text-[11px] font-bold text-amber-400">${n.urgency}</span>
                    <span class="text-[10px] text-slate-500">${n.timestamp}</span>
                </div>
                <h4 class="text-xs font-semibold text-white mt-1">${n.title}</h4>
                <p class="text-[11px] text-slate-300 mt-1">${n.body}</p>
            `;
            list.appendChild(div);
        });
        return;
    }

    items.forEach(item => {
        const div = document.createElement("div");
        div.className = `p-3 rounded-xl border cursor-pointer transition-all ${
            activeMailboxItem && activeMailboxItem.id === item.id 
                ? 'bg-slate-800 border-cyan-500 shadow-lg' 
                : 'bg-slate-800/50 hover:bg-slate-800/90 border-slate-700/60'
        }`;
        div.onclick = () => selectMailboxItem(item);

        let badgeHtml = '';
        if (item.action === 'BLOCKED') {
            badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">BLOCKED</span>`;
        } else if (item.action === 'NOTIFIED') {
            badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">WARNING</span>`;
        } else {
            badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">SAFE</span>`;
        }

        div.innerHTML = `
            <div class="flex items-center justify-between mb-1">
                <span class="text-xs font-bold text-slate-200 truncate max-w-[170px]">${item.sender_name || item.sender}</span>
                ${badgeHtml}
            </div>
            <div class="text-xs font-medium text-white truncate">${item.subject}</div>
            <p class="text-[11px] text-slate-400 truncate mt-1">${item.original_body.slice(0, 70)}...</p>
        `;
        list.appendChild(div);
    });

    if (!activeMailboxItem && items.length > 0) {
        selectMailboxItem(items[0]);
    }
}

function selectMailboxItem(item) {
    activeMailboxItem = item;
    renderMailboxList(); // update active highlight

    const viewer = document.getElementById("mailbox-detail-view");
    viewer.innerHTML = `
        <div class="space-y-4">
            <div class="border-b border-slate-700/80 pb-3">
                <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-400">Date: ${item.timestamp}</span>
                    <span class="px-2.5 py-0.5 rounded-full text-xs font-bold ${
                        item.action === 'BLOCKED' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        item.action === 'NOTIFIED' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }">${item.action}</span>
                </div>
                <h3 class="text-base font-bold text-white mt-2">${item.subject}</h3>
                <div class="text-xs text-slate-300 mt-1">
                    <strong>From:</strong> ${item.sender_name ? `${item.sender_name} &lt;${item.sender}&gt;` : item.sender}
                </div>
                ${item.reply_to ? `<div class="text-xs text-slate-400"><strong>Reply-To:</strong> ${item.reply_to}</div>` : ''}
            </div>

            <!-- Injected Banner / Email Content -->
            <div class="bg-white text-slate-900 rounded-xl p-4 text-xs font-sans shadow">
                ${item.html_with_banner ? item.html_with_banner : `
                    <div class="whitespace-pre-wrap">${item.body_with_banner || item.original_body}</div>
                `}
            </div>

            <!-- Security Audit Card -->
            <div class="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 text-xs">
                <span class="font-bold text-slate-300">🛡️ DualShield Layer Audit Breakdown:</span>
                <div class="grid grid-cols-2 gap-2 text-[11px]">
                    <div class="p-2 bg-slate-900 rounded border border-slate-800">
                        <span class="text-emerald-400 font-semibold">Layer 1 Heuristic Score:</span>
                        <div class="text-slate-200">${item.layer1_score} / 100 (${item.layer1_rules.length} rule hits)</div>
                    </div>
                    <div class="p-2 bg-slate-900 rounded border border-slate-800">
                        <span class="text-cyan-400 font-semibold">Layer 2 ML Spam Prob:</span>
                        <div class="text-slate-200">${Math.round(item.layer2_spam_prob * 100)}%</div>
                    </div>
                </div>
                <p class="text-[11px] text-slate-400 italic">${item.primary_reason}</p>
            </div>
        </div>
    `;
}

async function resetMailbox() {
    try {
        await fetch("/api/inbox/reset", { method: "POST" });
        await refreshMailbox();
        await refreshMetrics();
        alert("Simulated mailbox reset to default demo dataset.");
    } catch (err) {
        console.error("Failed reset:", err);
    }
}

// -------------------------------------------------------------
// Threat Metrics
// -------------------------------------------------------------
async function refreshMetrics() {
    try {
        const res = await fetch("/api/metrics");
        const m = await res.json();
        document.getElementById("stat-total").textContent = m.total_scanned || 0;
        document.getElementById("stat-blocked").textContent = m.blocked_count || 0;
        document.getElementById("stat-notified").textContent = m.notified_count || 0;
        document.getElementById("stat-allowed").textContent = m.allowed_count || 0;
    } catch (err) {
        console.error("Failed loading metrics:", err);
    }
}

async function triggerModelRetrain() {
    const btn = document.getElementById("btn-retrain");
    const status = document.getElementById("retrain-status");
    btn.disabled = true;
    btn.textContent = "Training...";
    status.textContent = "Fitting TF-IDF vectorizer and calibrating Logistic Regression...";

    try {
        const res = await fetch("/api/train", { method: "POST" });
        const data = await res.json();
        status.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Retrain Complete! Accuracy: ${(data.accuracy * 100).toFixed(1)}% on ${data.samples_count} email samples.</span>`;
    } catch (err) {
        status.textContent = "Error retraining model.";
    } finally {
        btn.disabled = false;
        btn.textContent = "↺ Retrain Model";
    }
}

// -------------------------------------------------------------
// Rules & Blacklist Manager
// -------------------------------------------------------------
async function loadRules() {
    try {
        const res = await fetch("/api/rules");
        const rules = await res.json();

        const blContainer = document.getElementById("blacklist-chips");
        blContainer.innerHTML = "";
        rules.blacklist.forEach(d => {
            const chip = document.createElement("span");
            chip.className = "px-2.5 py-1 rounded-lg text-xs bg-rose-950 text-rose-300 border border-rose-800 font-mono";
            chip.textContent = d;
            blContainer.appendChild(chip);
        });

        const wlContainer = document.getElementById("whitelist-chips");
        wlContainer.innerHTML = "";
        rules.whitelist.forEach(d => {
            const chip = document.createElement("span");
            chip.className = "px-2.5 py-1 rounded-lg text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono";
            chip.textContent = d;
            wlContainer.appendChild(chip);
        });
    } catch (err) {
        console.error("Failed loading rules:", err);
    }
}

async function addBlacklistDomain() {
    const input = document.getElementById("input-new-blacklist");
    const domain = input.value.trim();
    if (!domain) return;

    try {
        const res = await fetch("/api/rules/blacklist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain })
        });
        if (res.ok) {
            input.value = "";
            await loadRules();
        }
    } catch (err) {
        console.error("Failed adding domain to blacklist:", err);
    }
}
