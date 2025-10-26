const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const scoreEl = document.getElementById("score");
const backendInput = document.getElementById("backendUrl");

const DEFAULT_BACKEND = "http://127.0.0.1:5000/scan";

// Initialize backend input
if (backendInput) backendInput.value = localStorage.getItem("ph_backend") || DEFAULT_BACKEND;
if (backendInput) {
  backendInput.addEventListener("change", () => {
    localStorage.setItem("ph_backend", backendInput.value);
  });
}

// UI helpers
function setStatus(msg) { statusEl.innerText = msg; }
function setResult(msg) { resultEl.innerText = msg; }
function setScore(value) {
  scoreEl.innerText = value;
  let color = "#999"; // neutral
  if (value >= 75) color = "#d93025"; // red
  else if (value >= 40) color = "#f9ab00"; // yellow
  else if (value >= 0) color = "#34a853"; // green
  scoreEl.style.backgroundColor = color;
}

// Try sending message to content script
async function extractEmail(tabId) {
  try {
    return await chrome.tabs.sendMessage(tabId, { action: "getEmailContent" });
  } catch (e) {
    console.warn("Content script not reachable, using fallback.", e);
    return await fallbackExtraction(tabId);
  }
}

// Fallback extraction using scripting API
async function fallbackExtraction(tabId) {
  const results = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      try {
        if (window.__phishingHook && window.__phishingHook.buildEmailPayload) {
          return window.__phishingHook.buildEmailPayload();
        }
        const subj = document.querySelector("h2.hP") || document.querySelector("h2");
        const from = document.querySelector(".gD") || document.querySelector(".go");
        const body = document.querySelector("div.a3s");
        const html = body ? body.innerHTML : "";
        const text = body ? body.innerText : "";
        const links = Array.from((body && body.querySelectorAll) ? body.querySelectorAll("a[href]") : []).map(a => a.href);
        return {
          subject: subj ? subj.innerText : "",
          sender: from ? (from.getAttribute("email") || from.innerText) : "",
          senderEmail: from ? (from.getAttribute("email") || "") : "",
          text,
          html,
          links
        };
      } catch (err) {
        return { error: "Fallback extraction failed: " + String(err) };
      }
    }
  });
  return results?.[0]?.result;
}

// Main scan handler
scanBtn.addEventListener("click", async () => {
  setStatus("Extracting email...");
  setResult("");
  setScore("--");
  scanBtn.disabled = true;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error("No active tab found");
    if (!tab.url.includes("mail.google.com")) {
      throw new Error("Not a Gmail tab. Open a Gmail message to scan.");
    }

    // Extract email content
    let emailData = await extractEmail(tab.id);
    if (!emailData || emailData.error) {
      throw new Error(emailData?.error || "Failed to extract email content");
    }

    setStatus("Analyzing email...");

    const backendUrl = backendInput?.value.trim() || localStorage.getItem("ph_backend") || DEFAULT_BACKEND;
    const res = await fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(emailData)
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`Server responded ${res.status} ${txt}`);
    }

    const data = await res.json();
    setResult(data.result || "No result from backend");
    setScore(data.score ?? "--");
    setStatus("Analysis complete");

  } catch (err) {
    console.error("Scan error:", err);
    setStatus("Error");
    setResult(err.message || "Failed to reach backend or extract message");
    setScore("--");
  } finally {
    scanBtn.disabled = false;
  }
});
