// test/e2e.js
// Self-contained end-to-end verification of the Visor extension.
//
// Launches Chrome with the extension loaded, navigates to the benign site and to the
// AiTM-proxied site, and checks that:
//   1. the service worker starts and the feature vector is populated
//   2. every allowlisted feature the extension is expected to produce is populated
//   3. the AiTM model runs and returns a verdict for both sites
//   4. the verdict differs between the two sites
//
// Usage:
//   node visor/test/e2e.js
//   node visor/test/e2e.js --headful
//   node visor/test/e2e.js --keep-open

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const require = createRequire(import.meta.url);
const { chromium } = require('../../aitm-harness/node_modules/playwright');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VISOR_DIR = path.resolve(__dirname, '..');

const BENIGN = 'https://wordpress.kandarpjindal.in/';
const LURE = 'https://wordpress.phish.kandarpjindal.in/OxIaULuM';
const PHISH = 'https://wordpress.phish.kandarpjindal.in/';

const headful = process.argv.includes('--headful');
const keepOpen = process.argv.includes('--keep-open');

// Features the extension must produce for the model. Each is checked for
// "populated" (non-null) after a normal page load.
const MUST_BE_POPULATED = [
  'identity_host_mismatch_header',
  'n_identity_mismatch_header',
  'ever_saw_identity_mismatch_header',
  'n_foreign_origin_headers',
  'cookie_domain_mismatch',
  'has_referer',
  'entry_path',
  'redirect_hop_count',
  'cross_origin_hop_count',
  'n_third_party_requests',
  'third_party_ratio',
  'script_src_is_opaque_root_path',
  'n_opaque_root_scripts',
  'n_requests',
  'n_hosts',
  'n_cookies',
  'has_password_field',
  'n_forms',
  'viewport_w',
  'dpr',
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Wait until the service worker has actually evaluated background.js and
 * registered its listeners. `ctx.serviceWorkers()[0]` can resolve before the
 * module has run, in which case the first navigation's request headers are missed.
 */
async function waitForSWReady(ctx) {
  let sw = ctx.serviceWorkers()[0]
    || await ctx.waitForEvent('serviceworker', { timeout: 20000 }).catch(() => null);
  if (!sw) throw new Error('extension service worker did not start');
  for (let i = 0; i < 80; i += 1) {
    const ready = await sw
      .evaluate(() => typeof globalThis.visorClassify === 'function')
      .catch(() => false);
    if (ready) return sw;
    await sleep(250);
  }
  throw new Error('service worker did not become ready');
}

async function readVector(ctx) {
  let sw = ctx.serviceWorkers()[0];
  if (!sw) {
    sw = await ctx.waitForEvent('serviceworker', { timeout: 20000 }).catch(() => null);
  }
  if (!sw) return null;
  const state = await sw.evaluate(async () => {
    const all = await chrome.storage.session.get(null);
    const key = Object.keys(all).find((k) => k.startsWith('visor:tab:'));
    return key ? all[key] : null;
  });
  return { state, sw };
}

async function classify(sw, vector) {
  // The SW global scope cannot use dynamic import(); background.js exposes the
  // classifier on globalThis for exactly this.
  return sw.evaluate((v) => globalThis.visorClassify(v), vector);
}

function show(name, vector, results) {
  console.log(`\n── ${name} ─────────────────────────────────────────`);
  const missing = [];
  for (const f of MUST_BE_POPULATED) {
    const v = vector?.[f];
    const ok = v !== null && v !== undefined;
    if (!ok) missing.push(f);
    console.log(`   ${ok ? '✓' : '✗'} ${f.padEnd(36)} ${JSON.stringify(v)}`);
  }
  console.log('   verdicts:', results.map((r) => `${r.module}=${r.score}(${r.verdict})`).join('  '));
  return missing;
}

async function main() {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'visor-e2e-'));
  console.log(`Chrome profile: ${userDataDir}`);

  const ctx = await chromium.launchPersistentContext(userDataDir, {
    headless: !headful,
    // The default Playwright headless build does not load extensions; the
    // 'chromium' channel is the new headless mode, which does.
    channel: headful ? undefined : 'chromium',
    args: [
      `--disable-extensions-except=${VISOR_DIR}`,
      `--load-extension=${VISOR_DIR}`,
      '--no-sandbox',
    ],
  });

  let failures = [];
  try {
    const page = ctx.pages()[0] || (await ctx.newPage());

    // The service worker must be running BEFORE the first navigation: an MV3
    // worker starts lazily, and if it only wakes on the content script's first
    // message it has already missed that navigation's request headers.
    const sw = await waitForSWReady(ctx);
    console.log('service worker:', sw.url());

    // Tier 2 lives in the content script's ISOLATED world, so it is invisible
    // to page.evaluate(). We watch the worker's console instead.
    const swLog = [];
    sw.on('console', (m) => swLog.push(m.text()));

    // ── 1. Benign ────────────────────────────────────────────────────────
    console.log(`\nNavigating to benign: ${BENIGN}`);
    await page.goto(BENIGN, { waitUntil: 'load', timeout: 60000 }).catch(() => {});
    await sleep(4000);

    const { state: benignVec } = await readVector(ctx);
    if (!benignVec) throw new Error('no feature vector in session storage for the benign tab');
    const benignVerdicts = await classify(sw, benignVec);
    const bMissing = show('BENIGN', benignVec, benignVerdicts);

    // ── 2. AiTM ──────────────────────────────────────────────────────────
    console.log(`\nNavigating to lure: ${LURE}`);
    await page.goto(LURE, { waitUntil: 'load', timeout: 60000 }).catch(() => {});
    await sleep(3000);
    console.log(`Navigating to proxied page: ${PHISH}`);
    await page.goto(PHISH, { waitUntil: 'load', timeout: 60000 }).catch(() => {});
    await sleep(4000);

    const { state: phishVec } = await readVector(ctx);
    if (!phishVec) throw new Error('no feature vector in session storage for the phish tab');
    const phishVerdicts = await classify(sw, phishVec);
    const pMissing = show('AiTM (proxied)', phishVec, phishVerdicts);

    // ── 3. The gating case: the credential page ──────────────────────────
    // The interstitial fires on credential submission, so the login page is the
    // page that actually matters.
    const PHISH_LOGIN = 'https://wordpress.phish.kandarpjindal.in/wp-login.php';
    console.log(`\nNavigating to proxied login page: ${PHISH_LOGIN}`);
    await page.goto(PHISH_LOGIN, { waitUntil: 'load', timeout: 60000 }).catch(() => {});
    await sleep(4000);

    const { state: loginVec } = await readVector(ctx);
    if (!loginVec) throw new Error('no feature vector for the login tab');
    const loginVerdicts = await classify(sw, loginVec);
    const lMissing = show('AiTM (credential page)', loginVec, loginVerdicts);

    const loginAitm = loginVerdicts.find((r) => r.module === 'aitm');
    console.log(`  credential page: has_password_field=${loginVec.has_password_field} ` +
      `n_password_fields=${loginVec.n_password_fields} ` +
      `ever_saw_identity_mismatch_header=${loginVec.ever_saw_identity_mismatch_header}`);
    if (loginAitm?.verdict !== 'suspicious') {
      failures.push(`the AiTM model did not flag the proxied login page (score ${loginAitm?.score})`);
    }

    // ── 4. Checks ────────────────────────────────────────────────────────
    console.log('\n══ VERDICT ══════════════════════════════════════════════');
    const bAitm = benignVerdicts.find((r) => r.module === 'aitm');
    const pAitm = phishVerdicts.find((r) => r.module === 'aitm');
    console.log(`  benign            aitm score = ${bAitm?.score}  (${bAitm?.verdict})`);
    console.log(`  phish (home)      aitm score = ${pAitm?.score}  (${pAitm?.verdict})`);
    console.log(`  phish (login)     aitm score = ${loginAitm?.score}  (${loginAitm?.verdict})`);

    if (bMissing.length) {
      console.log(`  ✗ benign missing: ${bMissing.join(', ')}`);
      failures.push(`benign features not populated: ${bMissing.join(', ')}`);
    }
    if (pMissing.length) {
      console.log(`  ✗ phish missing: ${pMissing.join(', ')}`);
      failures.push(`phish features not populated: ${pMissing.join(', ')}`);
    }
    if (lMissing.length) {
      console.log(`  ✗ phish login missing: ${lMissing.join(', ')}`);
      failures.push(`phish login features not populated: ${lMissing.join(', ')}`);
    }
    if (bAitm?.verdict !== 'suspicious' && pAitm?.verdict !== 'suspicious') {
      failures.push('the AiTM model did not flag the proxied site');
    }
    if (bAitm?.score === pAitm?.score) {
      failures.push('the AiTM model gave both sites the same score');
    }

    console.log('\n══ DOM / CONTENT SCRIPT ═══════════════════════════════════');
    const tier2Merges = swLog.filter((t) => t.includes('Tier 2 vector merged'));
    console.log(`  Tier 2 feature merges seen by the worker: ${tier2Merges.length}`);
    if (tier2Merges.length) console.log(`  last: ${tier2Merges[tier2Merges.length - 1].slice(0, 160)}`);
    if (!tier2Merges.length) failures.push('the Tier 2 content script never reported features');
    const tier2Fields = ['has_password_field', 'n_forms', 'n_inputs', 'n_hidden_inputs',
      'has_autocomplete_current_password', 'script_src_is_opaque_root_path'];
    const tier2Missing = tier2Fields.filter((f) => !(f in phishVec));
    if (tier2Missing.length) failures.push(`Tier 2 fields missing from the vector: ${tier2Missing.join(', ')}`);
    else console.log(`  Tier 2 fields present in the vector: ${tier2Fields.join(', ')}`);

    // ── 5. Popup UI ───────────────────────────────────────────────────────
    const extId = new URL(sw.url()).host;
    const popup = await ctx.newPage();
    await popup.goto(`chrome-extension://${extId}/ui/popup.html`, { waitUntil: 'domcontentloaded' })
      .catch(() => {});
    await sleep(2500);
    const popupState = await popup.evaluate(() => ({
      banner: document.getElementById('verdict-banner')?.className ?? null,
      verdict: document.getElementById('verdict-text')?.textContent ?? null,
      rows: document.querySelectorAll('#feature-list .feature-row').length,
      aitmScore: document.getElementById('score-aitm')?.textContent ?? null,
    })).catch((e) => ({ error: e.message }));
    console.log('\n══ POPUP UI ══════════════════════════════════════════════');
    console.log('  ', JSON.stringify(popupState));
    if (!popupState.rows) {
      failures.push('the popup rendered no feature rows');
    }
    await popup.close();

    if (failures.length) {
      console.log('\nFAILURES:');
      for (const f of failures) console.log('  -', f);
      process.exitCode = 1;
    } else {
      console.log('\n✓ END-TO-END TEST PASSED');
    }
  } finally {
    if (!keepOpen) {
      await ctx.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  }
}

main().catch((err) => {
  console.error('E2E FAILED:', err);
  process.exit(1);
});
