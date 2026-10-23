// ui/popup.js: minimal popup interface with live telemetry and power control
import { classifyAll, IMPLEMENTED_MODULES } from '../models/interface.js';

const REFRESH_INTERVAL_MS = 750;
const DEBUG_KEY = 'visor:debug_open';

// DOM Elements
const verdictBanner = document.getElementById('verdict-banner');
const verdictText   = document.getElementById('verdict-text');
const verdictSub    = document.getElementById('verdict-sub');
const tabDomainEl   = document.getElementById('tab-domain');
const featureList   = document.getElementById('feature-list');
const debugPanel    = document.getElementById('debug-panel');
const debugToggle   = document.getElementById('debug-toggle');
const debugScores   = document.getElementById('debug-scores');
const tabUrlEl      = document.getElementById('tab-url');
const powerToggle   = document.getElementById('power-toggle');
const powerStatus   = document.getElementById('power-status');

const scoreEls = {
  aitm:         document.getElementById('score-aitm'),
  homograph:    document.getElementById('score-homograph'),
  bitb:         document.getElementById('score-bitb'),
  clickjacking: document.getElementById('score-clickjacking'),
};

const FEATURE_META = [
  ['identity_host_mismatch_header', 'Origin leak in headers'],
  ['ever_saw_identity_mismatch_header', 'Session origin leak'],
  ['n_identity_mismatch_header', 'Foreign origin count'],
  ['has_password_field', 'Password input present'],
  ['form_action_mismatch', 'Form destination mismatch'],
  ['redirect_hop_count', 'Redirect hops'],
  ['cross_origin_hop_count', 'Cross-origin hops'],
  ['n_third_party_requests', 'Third-party requests'],
  ['cookie_domain_mismatch', 'Cookie domain mismatch'],
  ['n_cookies', 'Stored cookie count'],
  ['is_punycode', 'Punycode encoded domain'],
  ['has_confusables', 'Confusable glyphs detected'],
  ['skeleton_similarity', 'Brand skeleton match'],
  ['has_hsts', 'HSTS security header'],
  ['protocol', 'Transport protocol'],
];

function formatValue(val) {
  if (val === null || val === undefined) {
    return { text: 'pending', cls: 'pending' };
  }
  if (typeof val === 'boolean') {
    return val
      ? { text: 'Yes', cls: 'bool-true' }
      : { text: 'No',  cls: 'bool-false' };
  }
  if (typeof val === 'number') {
    const text = Number.isInteger(val) ? String(val) : val.toFixed(3);
    return { text, cls: val > 0 ? 'accent' : '' };
  }
  return { text: String(val), cls: '' };
}

function renderFeatures(vector) {
  if (!vector || Object.keys(vector).length === 0) {
    featureList.innerHTML = `
      <div class="feature-row telemetry-row">
        <span class="tel-key">Status</span>
        <span class="tel-val pending">Awaiting page activity...</span>
      </div>
    `;
    return;
  }

  const rows = FEATURE_META.map(([key, label]) => {
    const { text, cls } = formatValue(vector[key]);
    return `
      <div class="feature-row telemetry-row">
        <span class="tel-key" title="${key}">${label}</span>
        <span class="tel-val ${cls}">${text}</span>
      </div>
    `;
  });
  featureList.innerHTML = rows.join('');
}

function renderDebugScores(results) {
  debugScores.innerHTML = results
    .map((r) => {
      const score = (r.score ?? 0).toFixed(3);
      const verdict = r.verdict === 'suspicious' ? 'flagged' : 'clear';
      return `<div>${r.module.toUpperCase()}: <strong>${score}</strong> (${verdict})</div>`;
    })
    .join('');
}

function renderVerdict(results, isEnabled) {
  if (!isEnabled) {
    verdictBanner.className = 'status-card paused';
    verdictText.textContent = 'Protection paused';
    verdictSub.textContent = 'Real-time threat interception is disabled.';

    scoreEls.aitm.textContent = 'Paused';
    scoreEls.aitm.className = 'badge off';
    scoreEls.homograph.textContent = 'Paused';
    scoreEls.homograph.className = 'badge off';
    scoreEls.bitb.textContent = 'Work in progress';
    scoreEls.bitb.className = 'badge future';
    scoreEls.clickjacking.textContent = 'Work in progress';
    scoreEls.clickjacking.className = 'badge future';
    return;
  }

  const hit = results.find((r) => r.verdict === 'suspicious' && IMPLEMENTED_MODULES.includes(r.module));

  if (hit) {
    verdictBanner.className = 'status-card suspicious';
    verdictText.textContent = 'Threat detected';
    if (hit.module === 'aitm') {
      verdictSub.textContent = 'AiTM reverse proxy relaying session traffic.';
    } else if (hit.module === 'homograph') {
      verdictSub.textContent = 'Homograph domain imitating a trusted brand.';
    } else {
      verdictSub.textContent = 'Suspicious trust-spoofing behavior identified.';
    }
  } else {
    verdictBanner.className = 'status-card safe';
    verdictText.textContent = 'No threats detected';
    verdictSub.textContent = 'Page verified safe across all active modules.';
  }

  for (const m of ['aitm', 'homograph']) {
    const r = results.find((x) => x.module === m);
    const flagged = r?.verdict === 'suspicious';
    scoreEls[m].textContent = flagged ? 'Detected' : 'Not detected';
    scoreEls[m].className = `badge ${flagged ? 'flagged' : 'clear'}`;
  }

  for (const m of ['bitb', 'clickjacking']) {
    scoreEls[m].textContent = 'Work in progress';
    scoreEls[m].className = 'badge future';
  }
}

async function render() {
  try {
    const config = await chrome.storage.local.get('visor_enabled');
    const isEnabled = config.visor_enabled !== false;

    powerToggle.checked = isEnabled;
    powerStatus.textContent = isEnabled ? 'Active' : 'Paused';

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    let host = 'Internal page';
    try {
      if (tab.url) {
        host = new URL(tab.url).hostname || 'Internal page';
      }
    } catch {}

    tabDomainEl.textContent = host;
    tabUrlEl.textContent = tab.url ? (tab.url.length > 40 ? tab.url.slice(0, 37) + '...' : tab.url) : 'No URL';
    tabUrlEl.title = tab.url || '';

    const key = `visor:tab:${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const vector = stored[key] || {};

    const results = classifyAll(vector);

    renderVerdict(results, isEnabled);
    renderFeatures(vector);
    renderDebugScores(results);
  } catch (e) {
    console.warn('[Visor popup] render error:', e);
  }
}

function initDebugToggle() {
  const isOpen = localStorage.getItem(DEBUG_KEY) === 'open';
  if (isOpen) {
    debugPanel.classList.add('open');
    debugToggle.setAttribute('aria-expanded', 'true');
  }
  debugToggle.addEventListener('click', () => {
    const nowOpen = !debugPanel.classList.contains('open');
    debugPanel.classList.toggle('open', nowOpen);
    debugToggle.setAttribute('aria-expanded', String(nowOpen));
    localStorage.setItem(DEBUG_KEY, nowOpen ? 'open' : 'closed');
  });
}

function initPowerToggle() {
  powerToggle.addEventListener('change', async () => {
    const isEnabled = powerToggle.checked;
    await chrome.storage.local.set({ visor_enabled: isEnabled });
    powerStatus.textContent = isEnabled ? 'Active' : 'Paused';
    render();
  });
}

// Boot
render();
initPowerToggle();
initDebugToggle();

const timer = setInterval(render, REFRESH_INTERVAL_MS);
window.addEventListener('unload', () => clearInterval(timer));

document.getElementById('refresh-btn').addEventListener('click', render);