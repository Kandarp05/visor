// ui/popup.js — live feature vector display with auto-refresh
import { classifyAll } from '../models/interface.js';

const REFRESH_INTERVAL_MS = 600;

// ── DOM refs ────────────────────────────────────────────────────────────────
const verdictBanner = document.getElementById('verdict-banner');
const verdictText   = document.getElementById('verdict-text');
const featureList   = document.getElementById('feature-list');
const tabUrlEl      = document.getElementById('tab-url');

const scoreEls = {
  aitm:        document.getElementById('score-aitm'),
  bitb:        document.getElementById('score-bitb'),
  homograph:   document.getElementById('score-homograph'),
  clickjacking:document.getElementById('score-clickjacking'),
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

/** Feature display order and friendly labels. Class-generic signals come first. */
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

function renderModuleScores(results) {
  for (const r of results) {
    const el = scoreEls[r.module];
    if (!el) continue;
    const pct = Math.round((r.score ?? 0) * 100);
    el.textContent = `${pct}%`;
    el.className = `score ${r.verdict}`;
  }
}

function renderVerdict(results) {
  const anySuspicious = results.some((r) => r.verdict === 'suspicious');
  verdictBanner.className = anySuspicious ? 'suspicious' : 'safe';
  verdictText.textContent = anySuspicious
    ? `⚠ Suspicious — ${results.filter(r => r.verdict === 'suspicious').map(r => r.module.toUpperCase()).join(', ')}`
    : '✓ No threats detected';
}

async function render() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      verdictText.textContent = 'No active tab';
      return;
    }

    // Show URL in footer (truncated)
    const url = tab.url ?? '';
    tabUrlEl.textContent = url.length > 45 ? url.slice(0, 42) + '…' : url;
    tabUrlEl.title = url;

    // Read feature vector from session storage
    const key = `visor:tab:${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const vector = stored[key];

    if (!vector) {
      verdictBanner.className = 'loading';
      verdictText.textContent = 'No data for this tab yet';
      featureList.innerHTML = `<div class="feature-row">
        <span class="feature-name" style="color:#475569">Navigate to a page to start extraction.</span>
      </div>`;
      return;
    }

    renderFeatures(vector);

    // Classify and show scores
    const results = classifyAll(vector);
    renderModuleScores(results);
    renderVerdict(results);

  } catch (err) {
    verdictText.textContent = `Error: ${err.message}`;
    console.error('[Visor popup]', err);
  }
}

// ── Init ─────────────────────────────────────────────────────────────────────

render();

// Auto-refresh so async fields (e.g. header-derived identity leaks) update live
const timer = setInterval(render, REFRESH_INTERVAL_MS);

// Stop refreshing when popup is closed
window.addEventListener('unload', () => clearInterval(timer));

// Manual refresh button
document.getElementById('refresh-btn').addEventListener('click', render);
