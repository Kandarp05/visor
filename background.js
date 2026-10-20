// background.js — Phase 1 skeleton
// Service worker: logs navigation/request/tab events to prove
// permissions and injection timing are correct before any feature
// extraction is wired in.
//
// PHASE 1 SELF-TEST: Open chrome://extensions → "Service Worker" →
// Inspect → Console. Every event below should appear in real time.
// Look for:
//   [NAV] onBeforeNavigate   — fires the moment you hit Enter in the URL bar
//   [NAV] onCommitted        — fires when the page starts loading
//   [NET] onCompleted        — fires for each resource request
//   [TAB] removed            — fires when you close a tab
// If all four appear, Phase 1 is done.

import { VISOR_VERSION } from './lib/constants.js';

console.log(`[Visor background] service worker started — v${VISOR_VERSION}`);

// ── Navigation events ──────────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only care about top-level navigations (frameId 0) for now
  if (details.frameId !== 0) return;
  console.log('[NAV] onBeforeNavigate', {
    tabId: details.tabId,
    url: details.url,
    navigationId: details.navigationId ?? '(unavailable in MV3)',
    timeStamp: details.timeStamp,
  });
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCommitted', {
    tabId: details.tabId,
    url: details.url,
    transitionType: details.transitionType,
    transitionQualifiers: details.transitionQualifiers,
  });
});

chrome.webNavigation.onDOMContentLoaded.addListener((details) => {
  if (details.frameId !== 0) return;
  console.log('[NAV] onDOMContentLoaded', {
    tabId: details.tabId,
    url: details.url,
  });
});

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  console.log('[NAV] onCompleted (page fully loaded)', {
    tabId: details.tabId,
    url: details.url,
  });
});

// ── Network events (observational only — no blocking) ──────────────────────

chrome.webRequest.onCompleted.addListener(
  (details) => {
    // Only log main_frame and sub_frame requests to avoid noise
    if (!['main_frame', 'sub_frame'].includes(details.type)) return;
    console.log('[NET] onCompleted', {
      tabId: details.tabId,
      url: details.url,
      statusCode: details.statusCode,
      type: details.type,
      responseHeaders: details.responseHeaders?.map((h) => h.name) ?? [],
    });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    console.log('[NET] onBeforeRedirect', {
      tabId: details.tabId,
      fromUrl: details.url,
      toUrl: details.redirectUrl,
      statusCode: details.statusCode,
    });
  },
  { urls: ['<all_urls>'] }
);

// ── Tab lifecycle ──────────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
  console.log('[TAB] removed', { tabId, ...removeInfo });
});

// ── Message bus (Phase 2+ content script messages will land here) ──────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[MSG] received from content script', {
    type: message.type,
    tabId: sender.tab?.id,
    url: sender.tab?.url,
    payload: message.payload,
  });
  sendResponse({ ok: true });
  return true; // keep channel open for async responses later
});
