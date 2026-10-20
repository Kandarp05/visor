// ui/popup.js — Phase 1 shell
// Just confirms the popup JS loads and the service worker is reachable.
// Phase 6 will replace this with live feature-vector rendering.

const statusEl = document.getElementById('status');

async function init() {
  try {
    // Ask the background worker if it's alive (it responds to all messages
    // in Phase 1 with { ok: true })
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      statusEl.innerHTML = '<span class="pending">⚠ No active tab found.</span>';
      return;
    }

    statusEl.innerHTML = `
      <span class="ok">✓ Background worker reachable</span><br/>
      <br/>
      <b>Active tab:</b><br/>
      <code style="font-size:0.75rem;word-break:break-all">${tab.url}</code><br/>
      <br/>
      <span style="color:#475569;font-size:0.75rem">
        Phase 2+ will show the live feature vector here.
      </span>
    `;
  } catch (err) {
    statusEl.innerHTML = `<span style="color:#f87171">Error: ${err.message}</span>`;
  }
}

init();
