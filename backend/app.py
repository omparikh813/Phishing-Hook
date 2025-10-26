# app.py
import os
import re
import json
import time
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from dotenv import load_dotenv
from google import genai
import vt

load_dotenv()

app = Flask(__name__)

# --- Environment Setup ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")
EXTENSION_ORIGIN = os.environ.get("CHROME_EXTENSION_ORIGIN")  # e.g. chrome-extension://abcdefghijklmnop

# --- CORS Setup ---
# In production: restrict to Chrome Extension origin
# In local dev: allow localhost access
if EXTENSION_ORIGIN:
    CORS(app, origins=[EXTENSION_ORIGIN])
else:
    CORS(app, origins=["http://127.0.0.1:5000", "http://localhost:5000"])

# --- Optional Imports ---
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


# --- VirusTotal Link Check ---
def vt_check_links(links):
    """Return summary list for each link; submit unscanned links for analysis."""
    if not links:
        return []

    if not (vt and VT_API_KEY):
        return [{"link": l, "last_analysis_stats": {}} for l in links]

    client = vt.Client(VT_API_KEY)
    reviews = []
    try:
        for link in links:
            try:
                url_id = vt.url_id(link)
                obj = client.get_object(f"/urls/{url_id}")
                reviews.append({"link": link, "last_analysis_stats": getattr(obj, "last_analysis_stats", {})})
            except vt.error.APIError as e:
                # Link not found, submit for analysis
                try:
                    submission = client.scan_url(link)
                    time.sleep(1)
                    obj = client.get_object(f"/urls/{vt.url_id(link)}")
                    reviews.append({"link": link, "last_analysis_stats": getattr(obj, "last_analysis_stats", {})})
                except Exception as sub_e:
                    reviews.append({"link": link, "error": f"{str(e)}; submission failed: {str(sub_e)}"})
            except Exception as e:
                reviews.append({"link": link, "error": str(e)})
    finally:
        client.close()
    return reviews


# --- Gemini AI Function ---
def call_gemini_prompt(prompt):
    if genai:
        try:
            model = genai.GenerativeModel("gemini-2.0-flash")
            resp = model.generate_content(prompt)
            return resp.text.strip()
        except Exception as e:
            return f"(Gemini error: {e})"
    return "Gemini not configured. Fallback analysis applied."


# --- Routes ---
@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "note": "POST JSON to /scan"})


@app.route("/scan", methods=["POST"])
def scan():
    # --- Origin Security Check ---
    if EXTENSION_ORIGIN:
        origin = request.headers.get("Origin")
        if origin != EXTENSION_ORIGIN:
            abort(403)

    data = request.get_json(force=True) or {}
    subject = data.get("subject", "")
    sender = data.get("sender", "")
    sender_email = data.get("senderEmail", "")
    text = data.get("text", "")
    links = data.get("links", []) or []

    text = re.sub(r"=\w{1,2}", "", text)

    # VirusTotal analysis
    vt_reviews = vt_check_links(links)
    vt_reviews = [r for r in vt_reviews if not ('error' in r and 'NotFoundError' in r['error'])]

    receiver_email = sender_email or sender

    # --- Gemini prompt ---
    prompt = f"""
Using the email "{receiver_email}", analyze the name and domain to determine who they are (ex. personal, corporate account, etc.). 
Then determine their potentially valuable assets and possible attack vectors. The email contents and VirusTotal analysis are provided below.
A link should only be considered malicious if more than 10% of vendors report it as suspicious or malicious.

Email Contents: {json.dumps(text)}
VirusTotal Analysis: {json.dumps(vt_reviews)}

Output format:
Score: [0–100]
Digest: [3 sentences]
Reasons: [2 major reasons]
"""

    ai_text = call_gemini_prompt(prompt)

    # Clean AI output
    digest_clean = re.sub(r'^Score:\s*\d{1,3}', '', ai_text, flags=re.MULTILINE).strip()

    # Parse score
    num = re.search(r'Score: (\d{1,3})', ai_text)
    score = int(num.group(1)) if num else "No score given"

    return jsonify({"result": digest_clean, "score": score})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=not bool(EXTENSION_ORIGIN)  # disable debug if running in production
    )
