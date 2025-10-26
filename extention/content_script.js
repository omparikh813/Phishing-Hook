// content_script.js
// Runs on Gmail pages (manifest must include matches for https://mail.google.com/*).
// Listens for popup requests and returns parsed email info.

(function () {
  // Helper: get the Gmail message element(s)
  function findEmailElements() {
    // Gmail uses .a3s for the message body container, .hP for subject, .gD for the sender element.
    const subjectEl = document.querySelector("h2.hP") || document.querySelector("h2");
    const fromEl = document.querySelector(".gD") || document.querySelector(".gB") || document.querySelector(".go");
    // message body container (may exist multiple times for threaded messages)
    const bodyEl = document.querySelector("div.a3s") || document.querySelector("div[role='listitem'] div.a3s");
    return { subjectEl, fromEl, bodyEl };
  }

  // Extract links from HTML and text (catch both anchor hrefs and plaintext URLs)
  function extractLinksFromHtmlAndText(html, text) {
    const links = new Set();

    if (html) {
      const temp = document.createElement("div");
      temp.innerHTML = html;
      const anchors = temp.querySelectorAll("a[href]");
      anchors.forEach(a => {
        try {
          if (a.href) links.add(a.href);
        } catch (e) {
          // ignore malformed urls
        }
      });
    }

    if (text) {
      // regex to find http(s) links in plaintext
      const regex = /https?:\/\/[^\s)>\]]+/gi;
      const matches = text.match(regex) || [];
      matches.forEach(m => links.add(m));
    }

    return Array.from(links);
  }

  // Build the payload to send back to popup
  function buildEmailPayload() {
    const { subjectEl, fromEl, bodyEl } = findEmailElements();

    if (!bodyEl) {
      return { error: "Could not find message body on this page. Open a single email view in Gmail." };
    }

    const rawHtml = bodyEl.innerHTML || "";
    const visibleText = bodyEl.innerText || "";
    let sender = "";
    let senderEmail = "";

    if (fromEl) {
      sender = fromEl.innerText || "";
      // try to pull email attribute
      senderEmail = fromEl.getAttribute && (fromEl.getAttribute("email") || fromEl.getAttribute("data-email")) || "";
    }

    const subject = subjectEl ? subjectEl.innerText || "" : "";

    const links = extractLinksFromHtmlAndText(rawHtml, visibleText);

    return {
      subject,
      sender,
      senderEmail,
      text: visibleText,
      html: rawHtml,
      links
    };
  }

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request && request.action === "getEmailContent") {
      const payload = buildEmailPayload();
      sendResponse(payload);
      // synchronous response; no need to return true
    }
  });

  // Optional: expose a global for debugging in console
  window.__phishingHook = { buildEmailPayload };
})();
