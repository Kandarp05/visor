// content.js — Phase 1 skeleton
// Injected into every page at document_start (via manifest content_scripts).
// At document_idle we re-run DOM checks via a DOMContentLoaded listener.
//
// NOTE: Content scripts cannot use ES module imports. Constants are inlined.
//
// PHASE 1 SELF-TEST: Open DevTools on any page → Console → filter "Visor".
// You should see:
//   [Visor content] INJECTED document_start  readyState=loading
//   [Visor content] DOM ready                readyState=interactive (or complete)
// The first line must always precede the second.
// Also check that a [MSG] received log appears in the background service
// worker console, confirming the message bridge is alive.

// Inlined from lib/constants.js (content scripts can't use ES imports)
const VISOR_VERSION = '0.1.0';

(function visorContentMain() {
  // Guard: don't run in extension pages themselves
  if (location.protocol === 'chrome-extension:') return;

  const tabUrl = location.href;

  // ── document_start ────────────────────────────────────────────────────────
  console.log('[Visor content] INJECTED document_start', {
    readyState: document.readyState,   // should always be "loading" here
    url: tabUrl,
    timestamp: Date.now(),
  });

  // Phase 2+: window.open will be wrapped here (BiTB defence).
  // Left as a clearly marked placeholder so the hook point is visible.
  // PLACEHOLDER_WINDOW_OPEN_WRAP

  // ── document_idle / DOM ready ─────────────────────────────────────────────
  function onDomReady() {
    console.log('[Visor content] DOM ready', {
      readyState: document.readyState,  // "interactive" or "complete"
      url: tabUrl,
      timestamp: Date.now(),
    });

    // Phase 3+: tier2_dom.js feature extraction runs here.
    // PLACEHOLDER_TIER2_SCAN

    // Ping the background worker to prove the message bridge works
    chrome.runtime.sendMessage(
      {
        type: 'PHASE1_PING',
        payload: {
          url: tabUrl,
          readyState: document.readyState,
          timestamp: Date.now(),
        },
      },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn('[Visor content] sendMessage error:', chrome.runtime.lastError.message);
          return;
        }
        console.log('[Visor content] background replied:', response);
      }
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onDomReady, { once: true });
  } else {
    // Script injected into an already-loaded document (e.g. extension reinstall)
    onDomReady();
  }
})();
