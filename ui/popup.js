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

/** Feature display order and friendly labels. */
const FEATURE_META = [
  ['redirect_hop_count',     'Redirect hops'],
  ['cross_origin_hop_count', 'Cross-origin hops'],
  ['redirect_chain',         'Redirect chain'],
  ['cookie_domain_mismatch', 'Cookie domain mismatch'],
  ['has_hsts',               'HSTS header'],
  ['has_csp',                'CSP header'],
  ['protocol',               'Protocol'],
  ['domain_age_days',        'Domain age (days)'],
  ['has_password_field',     'Password field'],
  ['form_action_mismatch',   'Form action mismatch'],
  ['has_iframe',             'Has iframe'],
  ['iframe_overlap_viewport','Iframe overlay'],
  ['identity_host_mismatch', 'Identity host mismatch'],
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

// Auto-refresh so domain_age_days and other async fields update live
const timer = setInterval(render, REFRESH_INTERVAL_MS);

// Stop refreshing when popup is closed
window.addEventListener('unload', () => clearInterval(timer));

// Manual refresh button
document.getElementById('refresh-btn').addEventListener('click', render);
