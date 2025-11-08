# 🪝 Phishing Hook — AI Gmail Scanner

**Detect phishing emails instantly with AI-powered analysis.**  
Phishing Hook helps protect your inbox by analyzing suspicious emails directly in Gmail. Using Google Gemini AI and VirusTotal threat data, it gives you a clear risk score, a short summary, and reasons behind the decision — all within seconds.

---

## 🔍 What It Does
- ✅ **Scans the currently open Gmail email** — just click “Scan” while viewing a message.  
- ✅ **Analyzes email content and embedded links** using AI and VirusTotal.  
- ✅ **Provides a Phishing Score (0–100)** to indicate how risky an email might be.  
- ✅ **Explains its reasoning** in plain language — no tech jargon.  
- ✅ **Runs privately** — no accounts, logins, or tracking.

---

## 🧠 Powered by AI
Phishing Hook uses **Google Gemini AI** to evaluate:
- The sender’s identity and domain credibility  
- The tone, structure, and intent of the email  
- Any suspicious or malicious links flagged by VirusTotal  
- Common phishing patterns such as urgency, fake verification, or password-reset requests

Together, this produces a smart, explainable phishing analysis — not just a yes/no result.

---

## 📨 How to Use
1. **Open any email** in Gmail (not the inbox view).  
2. **Click the Phishing Hook icon** in your Chrome toolbar.  
3. **Press “Scan.”**  
   - The extension extracts the email’s text, sender, and links, and sends them securely to the AI backend for analysis.  
4. Within a few seconds you’ll see:  
   - **Score:** 0–100 likelihood of phishing.  
   - **Digest:** A concise AI summary.  
   - **Reasons:** Two key factors behind the score.

> 💡 *Tip:* If you see “Please click on a specific email to scan,” open a single message first — the inbox listing cannot be scanned.

---

## ⚙️ Technical Details
- **Backend:** Flask + Google Gemini + VirusTotal API  
- **Frontend:** Chrome Extension (Manifest V3)  
- All API keys and AI processing are handled securely on the backend (not in the extension).  
- No personal data is stored or sold.

---

## ⚠️ Disclaimer
Phishing Hook provides AI-based analysis for **educational and informational purposes only.**  
Always use personal judgment before clicking links or opening attachments.

---

If you’d like, I can also:
- produce a short `README.md` header snippet for the GitHub repo front page, or  
- generate a concise privacy policy HTML you can host for the Chrome Web Store.
