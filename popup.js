// popup.js
const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status") || document.createElement("div");
const resultEl = document.getElementById("result") || document.createElement("div");
const backendInput = document.getElementById("backendUrl");

const DEFAULT_BACKEND = "http://localhost:5000/scan";
if (backendInput) backendInput.value = localStorage.getItem("ph_backend") || DEFAULT_BACKEND;

if (backendInput) {
  backendInput.addEventListener("change", () => {
    localStorage.setItem("ph_backend", backendInput.value);
  });
}

function setStatus(msg) {
  if (statusEl) statusEl.innerText = msg;
}

function setResult(msg) {
  if (resultEl) resultEl.innerText = msg;
}

// Main click handler
scanBtn.addEventListener("click", async () => {
  setStatus("Extracting email from page...");
  setResult("");
  scanBtn.disabled = true;

  try {
    // find active tab in current window
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab) throw new Error("No active tab found.");

    // Send a message to the content script to extract the email. Content script must be injected via manifest.
    const response = await chrome.tabs.sendMessage(tab.id, { action: "getEmailContent" });

    // If sendMessage returns undefined (e.g., content script not injected), fallback to executeScript
    let emailData = response;
    if (!emailData) {
      // fallback: execute script to call the exposed builder (less preferred)
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          // This runs in page context; try to use exposed helper
          try {
            if (window.__phishingHook && window.__phishingHook.buildEmailPayload) {
              return window.__phishingHook.buildEmailPayload();
            } else {
              // naive fallback - attempt to find main selectors
              const subj = document.querySelector("h2.hP") || document.querySelector("h2");
              const from = document.querySelector(".gD") || document.querySelector(".go");
              const body = document.querySelector("div.a3s");
              const html = body ? body.innerHTML : "";
              const text = body ? body.innerText : "";
              return {
                subject: subj ? subj.innerText : "",
                sender: from ? (from.getAttribute("email") || from.innerText) : "",
                senderEmail: from ? (from.getAttribute("email") || "") : "",
                text,
                html,
                links: Array.from((body && body.querySelectorAll) ? body.querySelectorAll("a[href]") : []).map(a => a.href)
              };
            }
          } catch (e) {
            return { error: "Extraction fallback failed: " + String(e) };
          }
        }
      });
      emailData = results && results[0] && results[0].result;
    }

    if (!emailData) throw new Error("No email data returned from content script.");

    if (emailData.error) {
      setStatus("Error extracting email");
      setResult(emailData.error);
      scanBtn.disabled = false;
      return;
    }

    setStatus("Sending email to backend for analysis...");

    const backendUrl = (backendInput && backendInput.value.trim()) || localStorage.getItem("ph_backend") || DEFAULT_BACKEND;

    const payload = {
      subject: emailData.subject || "",
      sender: emailData.sender || "",
      senderEmail: emailData.senderEmail || "",
      text: emailData.text || "",
      html: emailData.html || "",
      links: emailData.links || []
    };

    const res = await fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`Server responded ${res.status} ${txt}`);
    }

    const json = await res.json();
    setStatus("Analysis complete");
    // Display structured output if available
    if (json.digest || json.score || json.reasons) {
      let out = "";
      if (json.digest) out += `Digest:\n${json.digest}\n\n`;
      if (json.score !== undefined) out += `Score: ${json.score}\n\n`;
      if (json.reasons && Array.isArray(json.reasons)) out += `Reasons:\n- ${json.reasons.join("\n- ")}\n\n`;
      if (json.explain) out += `Details: ${json.explain}\n`;
      setResult(out);
    } else {
      setResult(JSON.stringify(json, null, 2));
    }
  } catch (err) {
    console.error("Scan error:", err);
    setStatus("Error");
    setResult("Failed to reach backend or extract message. See console for details.\n\n" + String(err));
  } finally {
    scanBtn.disabled = false;
  }
});
