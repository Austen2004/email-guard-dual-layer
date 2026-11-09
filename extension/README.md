# 🛡️ DualShield Gmail Guard - Chrome & Edge Extension

This browser extension directly integrates **DualShield's Two-Layer Spam & Threat Defense** into **Gmail (`mail.google.com`)**.

---

## 🌟 What the Extension Does in Gmail

1. **Automatic Inspection:** Whenever you click and open any email in Gmail, DualShield reads the sender, subject, body, links, and attachments.
2. **Two-Layer Security Scan:** Inspects the email using Layer 1 (Traditional Heuristics) + Layer 2 (Machine Learning Model).
3. **Direct In-Page Safety Banners:**
   - **🚨 BLOCKED Threat:** Displays a prominent red alert banner warning that the email is malicious (phishing, malware, crypto scam).
   - **⚠️ NOTIFIED Warning:** Injects an amber warning banner (`PROCEED WITH CAUTION`) with safety tips.
   - **✅ ALLOWED Safe:** Injects a discreet green badge (`Verified Safe by DualShield`).
4. **Extension Toolbar Popup:** Click the DualShield shield icon in your browser toolbar to see the live score breakdown, Layer 1 vs. Layer 2 meters, and backend server status.

---

## 🚀 How to Install in Chrome or Edge (30 Seconds)

### Step 1: Open Extension Settings in Your Browser
- In **Google Chrome**, open:
  ```
  chrome://extensions/
  ```
- In **Microsoft Edge**, open:
  ```
  edge://extensions/
  ```

### Step 2: Enable "Developer mode"
- In the top-right corner of the Extensions page, toggle **Developer mode** to **ON**.

### Step 3: Load the Extension
1. Click the button that says **"Load unpacked"**.
2. In the folder picker dialog, select this folder:
   ```
   C:\Users\willf\.gemini\antigravity\scratch\email-guard-dual-layer\extension
   ```
3. Click **Select Folder**.

🎉 **Done!** DualShield is now installed and active in your browser!

---

## 🧪 How to Test It

1. Make sure your DualShield backend server is running:
   ```powershell
   cd C:\Users\willf\.gemini\antigravity\scratch\email-guard-dual-layer
   python app.py
   ```
2. Open **[Gmail](https://mail.google.com)** in your browser.
3. Open any email in your inbox.
4. You will see the **DualShield Safety Banner** appear at the top of the email!
5. Click the DualShield shield icon in your Chrome toolbar to view the live Layer 1 and Layer 2 breakdown.
