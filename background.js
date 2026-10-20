// background.js — service worker
// Single entry point. Registers Tier 1 listeners, owns the message bus,
// and (Phase 5+) runs gating logic.
//
// All top-level listener registrations must be synchronous — MV3 requirement.

import { VISOR_VERSION, MSG } from './lib/constants.js';
import { init as initTier1 }  from './feature_extractor/tier1_network.js';
import { getVector, deleteVector } from './feature_extractor/session_state.js';

console.log(`[Visor] background service worker started — v${VISOR_VERSION}`);

// ── Tier 1: network feature extraction (registers its own listeners) ──────
initTier1();

// ── Tab cleanup ───────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  deleteVector(tabId).catch(() => {});
  console.log('[Visor] tab removed, vector deleted', { tabId });
});

// ── Message bus (content script → background) ─────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  switch (message.type) {

    // ── Phase 1 liveness ping ─────────────────────────────────────────────
    case MSG.PHASE1_PING:
      console.log('[Visor] PHASE1_PING from', sender.tab?.url);
      sendResponse({ ok: true });
      break;

    // ── Phase 3: Tier 2 DOM features merged into session vector ───────────
    case MSG.TIER2_FEATURES:
      if (!tabId) { sendResponse({ ok: false }); break; }
      import('./feature_extractor/session_state.js').then(({ updateVector }) =>
        updateVector(tabId, message.payload)
      ).then(() => sendResponse({ ok: true }))
       .catch(() => sendResponse({ ok: false }));
      return true; // async

    // ── Phase 5: Form submit — classify and respond ────────────────────────
    case MSG.FORM_SUBMIT:
      if (!tabId) { sendResponse({ verdict: 'safe', score: 0, module: 'none' }); break; }
      handleFormSubmit(tabId, sendResponse);
      return true; // async

    // ── Phase 5: BiTB — window.open intercepted ───────────────────────────
    case MSG.BITB_WINDOW_OPEN:
      if (!tabId) { sendResponse({ block: false }); break; }
      handleBitbOpen(tabId, sendResponse);
      return true; // async

    // ── Phase 5: Clickjacking — suspicious iframe detected ────────────────
    case MSG.IFRAME_SUSPICIOUS:
      if (!tabId) { sendResponse({ block: false }); break; }
      handleIframeSuspicious(tabId, sendResponse);
      return true; // async

    default:
      sendResponse({ ok: false, error: `Unknown message type: ${message.type}` });
  }
});

// ── Phase 5 gating handlers (stubs until models/interface.js exists) ──────
// These are defined here so the message switch above compiles cleanly.
// They import the model interface lazily so Phase 2–4 work without models/.

async function handleFormSubmit(tabId, sendResponse) {
  try {
    const vector  = await getVector(tabId);
    const { classifyAll } = await import('./models/interface.js');
    const results = classifyAll(vector);
    const hit     = results.find((r) => r.verdict === 'suspicious');
    sendResponse(hit ?? { verdict: 'safe', score: 0, module: 'none' });
  } catch (e) {
    console.warn('[Visor] classify error (models not yet built?):', e.message);
    sendResponse({ verdict: 'safe', score: 0, module: 'none' });
  }
}

async function handleBitbOpen(tabId, sendResponse) {
  try {
    const vector = await getVector(tabId);
    const { classifyBitb } = await import('./models/interface.js');
    const result = classifyBitb(vector);
    sendResponse({ block: result.verdict === 'suspicious', ...result });
  } catch {
    sendResponse({ block: false });
  }
}

async function handleIframeSuspicious(tabId, sendResponse) {
  try {
    const vector = await getVector(tabId);
    const { classifyClickjacking } = await import('./models/interface.js');
    const result = classifyClickjacking(vector);
    sendResponse({ block: result.verdict === 'suspicious', ...result });
  } catch {
    sendResponse({ block: false });
  }
}
