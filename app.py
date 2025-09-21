# app.py
import os
import re
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # dev: allow all origins; restrict in production

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# Optional imports (guarded) to allow local testing without keys installed
try:
    import google.generativeai as genai
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
except Exception:
    genai = None

try:
    import vt
except Exception:
    vt = None


def extract_domains_from_links(links):
    domains = set()
    for l in links:
        try:
            # simple domain extraction
            m = re.search(r"https?://([^/]+)", l)
            if m:
                domains.add(m.group(1).lower())
        except Exception:
            pass
    return list(domains)


def vt_check_links(links):
    """Return summary list for each link. If VT not available, return placeholder."""
    if not links:
        return []
    if not (vt and VT_API_KEY):
        # fallback: return unknown status
        return [{"link": l, "last_analysis_stats": {}} for l in links]

    client = vt.Client(VT_API_KEY)
    reviews = []
    try:
        for link in links:
            try:
                url_id = vt.url_id(link)
                obj = client.get_object(f"/urls/{url_id}")
                stats = getattr(obj, "last_analysis_stats", {})
                reviews.append({"link": link, "last_analysis_stats": stats})
            except Exception as e:
                reviews.append({"link": link, "error": str(e)})
    finally:
        client.close()
    return reviews


def call_gemini_prompt(prompt):
    """Call Gemini if available; otherwise return a deterministic fallback."""
    if genai:
        try:
            model = genai.GenerativeModel("gemini-2.0-flash")
            resp = model.generate_content(prompt)
            return resp.text.strip()
        except Exception as e:
            return f"(Gemini error: {e})"
    # fallback: short deterministic message
    return "Gemini not configured. Fallback analysis: basic heuristics applied."


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "note": "POST JSON to /scan"})


@app.route("/scan", methods=["POST"])
def scan():
    """
    Expected JSON:
    {
      "subject": "...",
      "sender": "...",
      "senderEmail": "...",
      "text": "...",
      "html": "...",
      "links": ["https://..."]
    }
    """
    data = request.get_json(force=True) or {}
    subject = data.get("subject", "")
    sender = data.get("sender", "")
    sender_email = data.get("senderEmail", "")
    text = data.get("text", "")
    html = data.get("html", "")
    links = data.get("links", []) or []

    # Basic sanitization
    text = re.sub(r"=\w{1,2}", "", text)

    # VirusTotal checks (if possible)
    vt_reviews = vt_check_links(links)

    # Use sender_email if present, else sender
    receiver_email = sender_email or sender

    # --- NEW PROMPT ---
    prompt = f"""
Using the email "{receiver_email}", analyze the name and domain to determine who they are (ex. personal, corporate account, etc.). 
This is the receiver of the email. Then determine their potentially valuable assets (ex. passwords, capital, corporate secrets or access, etc.), 
and what vectors a possible attacker could use to reach them (ex. compromised email, email list, etc.). 
This email address had an email sent to them which they suspect of being a phishing email. The suspected email is attached to the end of this prompt, with the sender being "{sender_email or sender}".
Keep in mind that the sender could be an automated account of a legit website, such as coorperations like Google, Github, Amazon. etc. Use the analysis of the receiver (persona, assets, attack vectors), the following email contents, 
and a list of VirusTotal reviews of the attached links to determine the likelihood of the email being a phishing attempt. 
The report should be in one concise, 5 sentence paragraph, and include a score from 0 to 100 with 0 being no likely phishing attempt and 100 being a definite threat.

Email Contents: {json.dumps(text)}
VirusTotal Analysis: {json.dumps(vt_reviews)}
"""

    # Call Gemini
    ai_text = call_gemini_prompt(prompt)

    # Attempt to parse score from text
    digest = ai_text
    score = None
    reasons = []

    m = re.search(r'(\b[0-9]{1,3}\b)(?=\s*(?:$|%|score))', ai_text)
    if m:
        try:
            score = int(m.group(1))
            score = max(0, min(100, score))
        except Exception:
            score = None

    # Heuristic fallback
    if score is None:
        malicious_hits = 0
        for r in vt_reviews:
            stats = r.get("last_analysis_stats") or {}
            malicious_hits += stats.get("malicious", 0) + stats.get("suspicious", 0)

        if malicious_hits == 0:
            score = 15
            reasons.append("no VirusTotal malicious hits")
        elif malicious_hits < 3:
            score = 60
            reasons.append("some VirusTotal engines flagged links")
        else:
            score = 90
            reasons.append("multiple VirusTotal engines flagged links")

        # Suspicious word heuristics
        suspicious_words = ["verify", "password", "account", "login", "urgent", "verify your", "confirm"]
        if any(w in text.lower() for w in suspicious_words):
            reasons.append("suspicious wording (request for credentials / urgent action)")

        # Domain mismatch heuristic
        domains = extract_domains_from_links(links)
        if domains and sender_email:
            sender_domain = ""
            m2 = re.search(r"@([^\s>]+)", sender_email)
            if m2:
                sender_domain = m2.group(1).lower()
            mismatch = any((d != sender_domain and sender_domain and d) for d in domains)
            if mismatch:
                reasons.append("sender domain does not match link domain(s)")

    if not reasons:
        reasons = ["heuristic: no obvious indicators detected"]

    # Final result
    result = {
        "digest": ai_text,
        "score": score,
        "reasons": reasons,
        "explain": f"Checked {len(links)} links; VT engines present: {'yes' if (vt and VT_API_KEY) else 'no'}; Gemini present: {'yes' if genai else 'no'}"
    }

    return jsonify(result)


if __name__ == "__main__":
    # dev server
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
