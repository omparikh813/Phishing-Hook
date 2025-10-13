# app.py
import os
import re
import json
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # dev: allow all origins

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

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
                    # We can optionally wait briefly for the scan to complete
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


def call_gemini_prompt(prompt):
    if genai:
        try:
            model = genai.GenerativeModel("gemini-2.0-flash")
            resp = model.generate_content(prompt)
            return resp.text.strip()
        except Exception as e:
            return f"(Gemini error: {e})"
    return "Gemini not configured. Fallback analysis applied."


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "note": "POST JSON to /scan"})


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True) or {}
    subject = data.get("subject", "")
    sender = data.get("sender", "")
    sender_email = data.get("senderEmail", "")
    text = data.get("text", "")
    links = data.get("links", []) or []

    text = re.sub(r"=\w{1,2}", "", text)

    # VirusTotal analysis with submission for new links
    vt_reviews = vt_check_links(links)

    receiver_email = sender_email or sender

    # --- Gemini prompt ---
    prompt = f"""
Using the email "{receiver_email}", analyze the name and domain to determine who they are (ex. personal, corporate account, etc.). 
This is the receiver of the email. Then determine their potentially valuable assets (ex. passwords, capital, corporate secrets or access, etc.), 
and what vectors a possible attacker could use to reach them (ex. compromised email, email list, etc.). 
This email address had an email sent to them which they suspect of being a phishing email. The suspected email is attached to the end of this prompt, with the sender being "{sender_email or sender}".
Keep in mind that the sender could be an automated account of a legit website, such as corporations like Google, Github, Amazon, etc. Use the analysis of the receiver (persona, assets, attack vectors), the following email contents, 
and a list of VirusTotal reviews of the attached links to determine the likelihood of the email being a phishing attempt. 

Email Contents: {json.dumps(text)}
VirusTotal Analysis: {json.dumps(vt_reviews)}

The Output should be formatted as such with no additional text:
Score: [a score from 0 to 100 with 0 being no likely phishing attempt and 100 being a definite threat.]

Digest: [3 sentence summary]

Reasons: [2 major reasons for the score, 1 sentence explaining each one]
"""

    ai_text = call_gemini_prompt(prompt)

    # Digest is raw Gemini output
    digest_clean = re.sub(r'^Score:\s*\d{1,3}', '', ai_text, flags=re.MULTILINE)
    digest_clean = digest_clean.strip()

    #Parse score from Gemini
    num = re.search(r'Score: (\d{1,3})', ai_text)
    score = int(num.group(1)) if num else "No score given"

    return jsonify({"result": digest_clean, "score": score})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
