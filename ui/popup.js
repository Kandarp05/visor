// ui/popup.js — minimal popup: a verdict, the module list, and a debug panel.
//
// The popup shows one thing: whether an attack was detected. Everything else
// (the feature vector, the raw model scores) lives behind the Debug toggle.
import { classifyAll, IMPLEMENTED_MODULES } from '../models/interface.js';

const REFRESH_INTERVAL_MS = 600;
const DEBUG_KEY = 'visor:debug';

// ── DOM refs ────────────────────────────────────────────────────────────────
const verdictBanner = document.getElementById('verdict-banner');
const verdictText   = document.getElementById('verdict-text');
const verdictSub    = document.getElementById('verdict-sub');
const featureList   = document.getElementById('feature-list');
const debugPanel    = document.getElementById('debug-panel');
const debugToggle   = document.getElementById('debug-toggle');
const debugScores   = document.getElementById('debug-scores');
const tabUrlEl      = document.getElementById('tab-url');

const scoreEls = {
  aitm:         document.getElementById('score-aitm'),
  bitb:         document.getElementById('score-bitb'),
  homograph:    document.getElementById('score-homograph'),
  clickjacking: document.getElementById('score-clickjacking'),
};

// ── Debug panel ──────────────────────────────────────────────────────────────

function renderDebugScores(results) {
  debugScores.innerHTML = results
    .map((r) => `<div>${r.module}: <strong>${(r.score ?? 0).toFixed(3)}</strong> — ${r.verdict}</div>`)
    .join('');
}

// ── Verdict ─────────────────────────────────────────────────────────────────

function renderVerdict(results) {
  // Only an implemented module may raise the "Threat detected" banner.
  const hit = results.find((r) => r.verdict === 'suspicious' && IMPLEMENTED_MODULES.includes(r.module));

  if (hit) {
    verdictBanner.className = 'suspicious';
    verdictText.textContent = 'Threat detected';
    verdictSub.textContent = `blocked at the point of harm — ${hit.module.toUpperCase()}`;
  } else {
    verdictBanner.className = 'safe';
    verdictText.textContent = 'No threats detected';
    verdictSub.textContent = 'this page looks safe';
  }

  // AiTM and the homograph module are implemented; the rest are placeholders.
  for (const m of ['aitm', 'homograph']) {
    const r = results.find((x) => x.module === m);
    const flagged = r?.verdict === 'suspicious';
    scoreEls[m].textContent = flagged ? 'Detected' : 'Not detected';
    scoreEls[m].className = `state ${flagged ? 'flagged' : 'clear'}`;
  }
  for (const m of ['bitb', 'clickjacking']) {
    scoreEls[m].textContent = 'Work in progress';
    scoreEls[m].className = 'state wip';
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

async function render() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    tabUrlEl.textContent = new URL(tab.url).hostname;

    const vector = await chrome.storage.session.get(`visor:tab:${tab.id}`);
    const fv = vector[`visor:tab:${tab.id}`] || {};
    const results = classifyAll(fv);

    renderVerdict(results);
    renderDebugScores(results);
  } catch (e) {
    console.error('[Visor popup] render error:', e);
  }
}

function initDebugToggle() {
  const isOpen = localStorage.getItem(DEBUG_KEY) === 'open';
  if (isOpen) debugPanel.classList.add('open');
  debugToggle.addEventListener('click', () => {
    const nowOpen = !debugPanel.classList.contains('open');
    debugPanel.classList.toggle('open');
    localStorage.setItem(DEBUG_KEY, nowOpen ? 'open' : 'closed');
  });
}

// ── Boot ────────────────────────────────────────────────────────────────────
render();
setInterval(render, REFRESH_INTERVAL_MS);
initDebugToggle();