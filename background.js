// background.js: service worker
// Single entry point. Registers Tier 1 listeners, owns the message bus,
// and runs gating logic.
//
// All imports in service workers must be static (dynamic import() fails in MV3 SW).

import { VISOR_VERSION, MSG } from './lib/constants.js';
import { init as initTier1 }  from './feature_extractor/tier1_network.js';
import { getVector, updateVector, deleteVector } from './feature_extractor/session_state.js';
import { homographFeatures } from './feature_extractor/homograph.js';
import { classifyAll, classifyBitb, classifyClickjacking, IMPLEMENTED_MODULES } from './models/interface.js';
import { classify as classifyHomograph } from './models/homograph_model.js';
import { projectToAllowlist, HOMOGRAPH_FEATURE_ALLOWLIST } from './lib/model_feature_allowlist.js';

console.log(`[Visor] background service worker started (v${VISOR_VERSION})`);

export async function isVisorEnabled() {
  try {
    const s = await chrome.storage.local.get('visor_enabled');
    return s.visor_enabled !== false;
  } catch {
    return true;
  }
}

// ── Tier 1: network feature extraction (registers its own listeners) ──────
initTier1();

// ── Tab cleanup ───────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  deleteVector(tabId).catch(() => {});
  console.log('[TAB] removed', { tabId });
});

// ── Test / debug hook ────────────────────────────────────────────────────
// The service-worker global scope cannot use dynamic import() (per spec), so the
// classifier is exposed here for the end-to-end test and for debugging from the
// DevTools console. The models are statically imported above.
globalThis.visorClassify = (vector) => classifyAll(vector);
globalThis.visorGetVector = (tabId) => getVector(tabId);

/**
 * Analyse a hostname with the homograph module.
 *
 * The homograph attack is a property of the domain name, so this works on any
 * hostname: there is no live homograph site to navigate to in the testbed.
 * Exposed for the end-to-end test and for the DevTools console.
 */
globalThis.visorAnalyzeHost = (hostname) => {
  const r = homographFeatures(hostname);
  if (!r) return null;
  const vector = { ...r.features, homograph_impersonates: r.target || null };
  const projected = projectToAllowlist(vector, HOMOGRAPH_FEATURE_ALLOWLIST);
  return {
    hostname,
    unicodeHost: r.unicodeHost,
    features: r.features,
    impersonates: r.target || null,
    result: classifyHomograph(projected),
  };
};

async function checkHomographForTab(tabId, url) {
  if (!tabId) return null;
  if (!(await isVisorEnabled())) return null;
  const vector = await getVector(tabId);
  if (vector?.homograph_bypassed) return null;

  let host = '';
  try {
    if (url) host = new URL(url).hostname;
  } catch {}
  if (!host && vector?.url) {
    try { host = new URL(vector.url).hostname; } catch {}
  }
  if (!host) return null;

  const analysis = globalThis.visorAnalyzeHost(host);
  if (analysis?.result?.verdict === 'suspicious') {
    return {
      block: true,
      module: 'homograph',
      score: analysis.result.score,
      impersonates: analysis.impersonates,
    };
  }
  return null;
}

// ── Message bus (content script → background) ─────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (message.type === MSG.PHASE1_PING) {
    console.log('[MSG] received from content script', { type: message.type, url: sender.tab?.url });
    checkHomographForTab(tabId, sender.tab?.url || sender.url)
      .then((hg) => {
        if (hg) {
          sendResponse({ ok: true, ...hg });
        } else {
          sendResponse({ ok: true });
        }
      })
      .catch(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === MSG.TIER2_FEATURES) {
    if (!tabId) {
      sendResponse({ ok: false });
      return false;
    }
    updateVector(tabId, message.payload)
      .then(async (v) => {
        console.log('[Visor] Tier 2 vector merged for tab', tabId, message.payload);
        const hg = await checkHomographForTab(tabId, sender.tab?.url || sender.url);
        if (hg) {
          sendResponse({ ok: !!v, ...hg });
        } else {
          sendResponse({ ok: !!v });
        }
      })
      .catch((err) => {
        console.error('[Visor] TIER2_FEATURES error:', err);
        sendResponse({ ok: false });
      });
    return true; // keep channel open for async response
  }

  if (message.type === MSG.BYPASS_HOMOGRAPH) {
    if (tabId) {
      updateVector(tabId, { homograph_bypassed: true }).catch(() => {});
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === MSG.FORM_SUBMIT) {
    if (!tabId) {
      sendResponse({ verdict: 'safe', score: 0, module: 'none' });
      return false;
    }
    handleFormSubmit(tabId, message.payload, sendResponse);
    return true;
  }

  if (message.type === MSG.BITB_WINDOW_OPEN) {
    if (!tabId) {
      sendResponse({ block: false });
      return false;
    }
    handleBitbOpen(tabId, sendResponse);
    return true;
  }

  if (message.type === MSG.IFRAME_SUSPICIOUS) {
    if (!tabId) {
      sendResponse({ block: false });
      return false;
    }
    handleIframeSuspicious(tabId, sendResponse);
    return true;
  }

  sendResponse({ ok: false, error: `Unknown message type: ${message.type}` });
  return false;
});

// ── Gating handlers ───────────────────────────────────────────────────────

async function handleFormSubmit(tabId, payload, sendResponse) {
  try {
    if (!(await isVisorEnabled())) {
      sendResponse({ verdict: 'safe', score: 0, module: 'none', disabled: true });
      return;
    }
    if (payload?.features && Object.keys(payload.features).length > 0) {
      await updateVector(tabId, payload.features);
    }
    const vector  = await getVector(tabId);
    const results = classifyAll(vector);
    const hit     = results.find((r) => {
      if (r.module === 'homograph' && vector?.homograph_bypassed) return false;
      return r.verdict === 'suspicious' && IMPLEMENTED_MODULES.includes(r.module);
    });
    console.log('[Visor] Form submit classified:', results.map((r) => `${r.module}=${r.score}`).join(' | '));
    if (!hit) {
      sendResponse({ verdict: 'safe', score: 0, module: 'none' });
      return;
    }
    // The homograph module can name the brand the host impersonates. That is
    // shown to the user, because it is what they have to act on.
    const impersonates = hit.module === 'homograph' && vector?.homograph_impersonates
      ? vector.homograph_impersonates : null;
    sendResponse({ block: true, ...hit, impersonates });
  } catch (e) {
    console.warn('[Visor] classify error:', e);
    sendResponse({ verdict: 'safe', score: 0, module: 'none' });
  }
}

async function handleBitbOpen(tabId, sendResponse) {
  try {
    if (!(await isVisorEnabled())) {
      sendResponse({ block: false, disabled: true });
      return;
    }
    const vector = await getVector(tabId);
    const result = classifyBitb(vector);
    // A placeholder module cannot block, even if it somehow returned suspicious.
    const block = result.verdict === 'suspicious' && IMPLEMENTED_MODULES.includes(result.module);
    sendResponse({ block, ...result });
  } catch (e) {
    console.warn('[Visor] bitb classify error:', e);
    sendResponse({ block: false });
  }
}

async function handleIframeSuspicious(tabId, sendResponse) {
  try {
    if (!(await isVisorEnabled())) {
      sendResponse({ block: false, disabled: true });
      return;
    }
    const vector = await getVector(tabId);
    const result = classifyClickjacking(vector);
    // A placeholder module cannot block, even if it somehow returned suspicious.
    const block = result.verdict === 'suspicious' && IMPLEMENTED_MODULES.includes(result.module);
    sendResponse({ block, ...result });
  } catch (e) {
    console.warn('[Visor] clickjacking classify error:', e);
    sendResponse({ block: false });
  }
}
