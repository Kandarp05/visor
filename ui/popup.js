// ui/popup.js — minimal popup: a verdict, the module list, and a debug panel.
//
// The popup shows one thing: whether an attack was detected. Everything else
// (the feature vector, the raw model scores) lives behind the Debug toggle.
import { classifyAll } from '../models/interface.js';

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

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatValue(val) {
  if (val === null || val === undefined) return { text: 'pending', cls: 'pending' };
  if (val === true)   return { text: 'YES ⚠',  cls: 'true'   };
  if (val === false)  return { text: 'no',      cls: 'false'  };
  if (typeof val === 'number') return { text: String(val), cls: 'number' };
  if (Array.isArray(val))  return { text: val.length ? val.join(' → ') : '(none)', cls: 'number' };
  return { text: String(val), cls: 'number' };
}

/** Feature display order and friendly labels (debug view only). */
const FEATURE_META = [
  ['identity_host_mismatch_header', 'Origin leak (headers)'],
  ['n_identity_mismatch_header',   'Foreign origin hosts'],
  ['ever_saw_identity_mismatch_header', 'Origin leak (session)'],
  ['identity_host_mismatch',       'Origin leak (body)'],
  ['n_foreign_origin_headers',     'Foreign origin headers'],
  ['form_action_mismatch',         'Form action mismatch'],
  ['cookie_domain_mismatch',       'Cookie domain mismatch'],
  ['has_referer',                  'Arrived with referrer'],
  ['entry_path',                   'Entry path'],
  ['redirect_hop_count',           'Redirect hops'],
  ['cross_origin_hop_count',       'Cross-origin hops'],
  ['script_src_is_opaque_root_path','Opaque root script'],
  ['n_opaque_root_scripts',        'Opaque root scripts'],
  ['n_third_party_requests',       'Third-party requests'],
  ['third_party_ratio',            'Third-party ratio'],
  ['has_password_field',           'Password field'],
  ['n_password_fields',            'Password fields'],
  ['n_requests',                   'Requests'],
  ['n_hosts',                      'Hosts'],
  ['n_cached',                     'Cached responses'],
  ['n_cookies',                    'Cookies'],
  ['n_host_only_cookies',          'Host-only cookies'],
  ['has_iframe',                   'Has iframe'],
  ['iframe_overlap_viewport',      'Iframe overlay'],
];

// ── Debug panel ─────────────────────────────────────────────────────────────

let debugOpen = false;

async function loadDebugState() {
  try {
    const s = await chrome.storage.local.get(DEBUG_KEY);
    debugOpen = Boolean(s[DEBUG_KEY]);
  } catch {
    debugOpen = false;
  }
  applyDebugVisibility();
}

function applyDebugVisibility() {
  debugPanel.classList.toggle('open', debugOpen);
  debugToggle.setAttribute('aria-expanded', String(debugOpen));
}

debugToggle.addEventListener('click', async () => {
  debugOpen = !debugOpen;
  applyDebugVisibility();
  try {
    await chrome.storage.local.set({ [DEBUG_KEY]: debugOpen });
  } catch { /* storage unavailable — the panel still toggles for this session */ }
});

function renderFeatures(vector) {
  const rows = FEATURE_META.map(([key, label]) => {
    const { text, cls } = formatValue(vector[key]);
    return `<div class="feature-row">
      <span class="feature-name">${label}</span>
      <span class="feature-val ${cls}">${text}</span>
    </div>`;
  });
  featureList.innerHTML = rows.join('');
}

function renderDebugScores(results) {
  debugScores.innerHTML = results
    .map((r) => `<div>${r.module}: <strong>${(r.score ?? 0).toFixed(3)}</strong> — ${r.verdict}</div>`)
    .join('');
}

// ── Verdict ─────────────────────────────────────────────────────────────────

function renderVerdict(results) {
  const hit = results.find((r) => r.verdict === 'suspicious');

  if (hit) {
    verdictBanner.className = 'suspicious';
    verdictText.textContent = 'Threat detected';
    verdictSub.textContent = `blocked at the point of harm — ${hit.module.toUpperCase()}`;
  } else {
    verdictBanner.className = 'safe';
    verdictText.textContent = 'No threats detected';
    verdictSub.textContent = 'this page looks safe';
  }

  // AiTM is the only implemented module; the rest are placeholders.
  const aitm = results.find((r) => r.module === 'aitm');
  scoreEls.aitm.textContent = aitm?.verdict === 'suspicious' ? 'Detected' : 'Not detected';
  scoreEls.aitm.className = `state ${aitm?.verdict === 'suspicious' ? 'flagged' : 'clear'}`;
  for (const m of ['bitb', 'homograph', 'clickjacking']) {
    scoreEls[m].textContent = 'Work in progress';
    scoreEls[m].className = 'state wip';
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

async function render() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      verdictText.textContent = 'No active tab';
      return;
    }

    const url = tab.url ?? '';
    tabUrlEl.textContent = url.length > 42 ? url.slice(0, 39) + '…' : url;
    tabUrlEl.title = url;

    const key = `visor:tab:${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const vector = stored[key];

    if (!vector) {
      verdictBanner.className = 'loading';
      verdictText.textContent = 'Loading…';
      verdictSub.textContent = 'checking this page';
      featureList.innerHTML = `<div class="feature-row">
        <span class="feature-name">—</span>
        <span class="feature-val pending">waiting…</span>
      </div>`;
      return;
    }

    const results = classifyAll(vector);
    renderVerdict(results);
    renderFeatures(vector);
    renderDebugScores(results);

  } catch (err) {
    verdictText.textContent = 'Error';
    verdictSub.textContent = err.message;
    console.error('[Visor popup]', err);
  }
}

// ── Init ────────────────────────────────────────────────────────────────────

loadDebugState();
render();

// Auto-refresh so async fields (e.g. header-derived identity leaks) update live.
const timer = setInterval(render, REFRESH_INTERVAL_MS);

window.addEventListener('unload', () => clearInterval(timer));

document.getElementById('refresh-btn').addEventListener('click', render);
