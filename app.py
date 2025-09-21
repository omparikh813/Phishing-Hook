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

    # Compose prompt asking for structured JSON output (score, digest, reasons)
    prompt = f"""
You are a helpful email security assistant. The receiver is "{sender_email or sender}".
Given the email subject and contents and the VirusTotal link analysis below, produce a JSON object with keys:
- digest: a concise 1-paragraph summary (approx 3-5 sentences)
- score: integer 0-100 (0 = safe, 100 = definite phishing)
- reasons: array of short reasons/indicators (e.g. "suspicious link", "attachment flagged", "spoofed sender")
Do not include any other keys.

Subject: "{subject}"
Email Text: {json.dumps(text)}
Links: {json.dumps(links)}
VirusTotal: {json.dumps(vt_reviews)}
"""

    ai_text = call_gemini_prompt(prompt)

    # Attempt to parse JSON out of ai_text (model may return plain text)
    digest = ai_text
    score = None
    reasons = []

    # crude attempt: find a trailing integer score in the text
    m = re.search(r'(\b[0-9]{1,3}\b)(?=\s*(?:$|%|score))', ai_text)
    if m:
        try:
            score = int(m.group(1))
            score = max(0, min(100, score))
        except Exception:
            score = None

    # Heuristic fallback when Gemini not present or didn't return score
    if score is None:
        malicious_hits = 0
        for r in vt_reviews:
            stats = r.get("last_analysis_stats") or {}
            malicious_hits += stats.get("malicious", 0) + stats.get("suspicious", 0)
        # simple mapping
        if malicious_hits == 0:
            score = 15
            reasons.append("no VirusTotal malicious hits")
        elif malicious_hits < 3:
            score = 60
            reasons.append("some VirusTotal engines flagged links")
        else:
            score = 90
            reasons.append("multiple VirusTotal engines flagged links")

        # Add heuristics for suspicious words
        suspicious_words = ["verify", "password", "account", "login", "urgent", "verify your", "confirm"]
        if any(w in text.lower() for w in suspicious_words):
            reasons.append("suspicious wording (request for credentials / urgent action)")

        # domain mismatch heuristic
        domains = extract_domains_from_links(links)
        if domains and sender_email:
            # compare sender domain to link domains
            sender_domain = ""
            m2 = re.search(r"@([^\s>]+)", sender_email)
            if m2:
                sender_domain = m2.group(1).lower()
            mismatch = any((d != sender_domain and sender_domain and d) for d in domains)
            if mismatch:
                reasons.append("sender domain does not match link domain(s)")

    # Ensure reasons is not empty
    if not reasons:
        reasons = ["heuristic: no obvious indicators detected"]

    # Final result: try to present the Gemini digest if available, else fallback
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
