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

    // ── 4. The interstitial (the gate itself) ────────────────────────────
    // Submitting credentials on the proxied login page must raise the
    // interstitial, and the interstitial must name the attack without
    // disclosing the evidence behind it.
    const submitInfo = await page.evaluate(() => {
      const form = document.getElementById('loginform') || document.querySelector('form');
      const user = document.getElementById('user_login') || document.querySelector('input[type="text"]');
      const pass = document.getElementById('user_pass') || document.querySelector('input[type="password"]');
      if (user) user.value = 'testuser';
      if (pass) pass.value = 'NotARealPassword!1';
      // Click the submit button like a user would. A programmatic requestSubmit()
      // is deliberately blocked by the extension: the credential may only be sent
      // on an explicit user action.
      if (form) {
        const btn = form.querySelector('[type="submit"]') || form.querySelector('button');
        if (btn) btn.click();
      }
      else if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      return { formFound: !!form, passFound: !!pass };
    }).catch((e) => ({ error: e.message }));
    await sleep(2500);

    const interstitial = await page.evaluate(() => {
      const el = document.getElementById('__visor_interstitial');
      if (!el) return { present: false };
      const text = el.innerText || '';
      return {
        present: true,
        heading: el.querySelector('h1')?.textContent ?? '',
        text,
        hasBack: !!el.querySelector('#__visor_back'),
        hasProceed: !!el.querySelector('#__visor_proceed'),
        leaksReasons: /signal|feature|confidence|score/i.test(text),
      };
    }).catch((e) => ({ error: e.message }));
    console.log('\n══ INTERSTITIAL ══════════════════════════════════════════');
    console.log('   submit:', JSON.stringify(submitInfo));
    console.log('   ', JSON.stringify({
      present: interstitial.present,
      heading: interstitial.heading,
      hasBack: interstitial.hasBack,
      hasProceed: interstitial.hasProceed,
      leaksReasons: interstitial.leaksReasons,
    }));
    if (!interstitial.present) {
      failures.push('the interstitial did not appear on credential submission');
    } else {
      if (!/aitm/i.test(interstitial.heading || '')) {
        failures.push(`the interstitial does not name the attack (heading: "${interstitial.heading}")`);
      }
      if (interstitial.leaksReasons) {
        failures.push('the interstitial discloses the evidence behind the verdict');
      }
      if (!interstitial.hasBack || !interstitial.hasProceed) {
        failures.push('the interstitial is missing its Go back / Proceed anyway controls');
      }
    }
    // Dismiss it so the rest of the run is unaffected.
    await page.evaluate(() => document.getElementById('__visor_proceed')?.click()).catch(() => {});
    await sleep(500);

    // ── 5. Checks ────────────────────────────────────────────────────────
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

    // ── IDN homograph module ────────────────────────────────────────────
    // The homograph attack is a property of the DOMAIN NAME, so the module is
    // exercised through the service worker's host analyser. There is no live
    // homograph site in the testbed, and registering one is not the point.
    console.log('\n══ HOMOGRAPH MODULE ══════════════════════════════════════');
    const HG_CASES = [
      // Punycode host, unicode host, expected verdict, expected impersonated brand.
      ['xn--pple-43d.com', 'аpple.com', 'suspicious', 'apple.com'],
      ['xn--ggle-55da.com', 'gооgle.com', 'suspicious', 'google.com'],
      ['xn--80ak6aa92e.com', 'login.аррӏе.com', 'suspicious', 'apple.com'],
      ['www.apple.com', 'www.apple.com', 'safe', null],
      ['xn--bcher-kva.de', 'bücher.de', 'safe', null],
      ['xn--e1afmkfd.xn--p1ai', 'пример.рф', 'safe', null],
      ['paypa1.com', 'paypa1.com', 'safe', null],
      ['wordpress.kandarpjindal.in', 'wordpress.kandarpjindal.in', 'safe', null],
      ['xn--blombrg-fya7i.com', 'blöombérg.com', 'suspicious', 'bloomberg.com'],
      ['xn--unlistd-dhg.com', 'unlistеd.com', 'suspicious', null],
    ];
    for (const [puny, uni, wantVerdict, wantBrand] of HG_CASES) {
      const r = await sw.evaluate((h) => globalThis.visorAnalyzeHost(h), puny);
      if (!r) {
        failures.push(`the homograph analyser returned nothing for ${puny}`);
        continue;
      }
      const got = r.result.verdict;
      const brand = r.impersonates || null;
      const ok = got === wantVerdict && brand === wantBrand;
      console.log(`   ${ok ? '✓' : '✗'} ${puny.padEnd(30)} ${got.padEnd(11)} p=${r.result.score.toFixed(3)} ${brand || '-'}`);
      if (got !== wantVerdict) {
        failures.push(`${uni}: expected ${wantVerdict}, got ${got}`);
      }
      if (brand !== wantBrand) {
        failures.push(`${uni}: expected to impersonate ${wantBrand}, got ${brand}`);
      }
    }

    // The six features must be present in the extension's vector.
    const hgVec = await sw.evaluate(async () => {
      const all = await chrome.storage.session.get(null);
      const key = Object.keys(all).find((k) => k.startsWith('visor:tab:'));
      const v = key ? all[key] : {};
      return {
        is_punycode: v.is_punycode,
        mixed_script_flag: v.mixed_script_flag,
        whole_script_confusable_violation: v.whole_script_confusable_violation,
        confusable_char_ratio: v.confusable_char_ratio,
        skeleton_exact_match: v.skeleton_exact_match,
        skeleton_similarity: v.skeleton_similarity,
      };
    });
    console.log('   vector:', JSON.stringify(hgVec));
    for (const k of ['is_punycode', 'mixed_script_flag', 'whole_script_confusable_violation',
                     'confusable_char_ratio', 'skeleton_exact_match', 'skeleton_similarity']) {
      if (!(k in hgVec) || hgVec[k] === undefined || hgVec[k] === null) {
        failures.push(`the extension vector does not carry ${k}`);
      }
    }

    // ── Homograph Navigation Blocking ────────────────────────────────────
    console.log('\n══ HOMOGRAPH NAVIGATION BLOCKING ══════════════════════════');
    const hgPage = await ctx.newPage();
    try {
      await hgPage.route('https://xn--blombrg-fya7i.com/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'text/html',
          body: '<html><body><h1>Bloomberg News Lookalike</h1><form action="/login"><input type="password" name="p"><button type="submit">Log in</button></form></body></html>',
        });
      });
      console.log('Navigating to homograph site: https://xn--blombrg-fya7i.com/');
      await hgPage.goto('https://xn--blombrg-fya7i.com/', { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      await sleep(1500);

      const navBlocked = await hgPage.evaluate(() => {
        const el = document.getElementById('__visor_interstitial');
        if (!el) return { present: false };
        return {
          present: true,
          heading: el.querySelector('h1')?.textContent ?? '',
          text: el.innerText || '',
          hasProceed: !!el.querySelector('#__visor_proceed'),
        };
      });
      console.log('   navigation block interstitial:', JSON.stringify(navBlocked));
      if (!navBlocked.present) {
        failures.push('the homograph module did not block the user upon navigating to a homograph site');
      } else {
        if (!/homograph/i.test(navBlocked.heading || '')) {
          failures.push(`the interstitial did not name homograph (got: "${navBlocked.heading}")`);
        }
        if (!/bloomberg\.com/i.test(navBlocked.text || '')) {
          failures.push('the interstitial did not show the impersonated target (bloomberg.com)');
        }
      }

      // Test proceed anyway on homograph
      await hgPage.evaluate(() => document.getElementById('__visor_proceed')?.click()).catch(() => {});
      await sleep(600);
      const afterProceed = await hgPage.evaluate(() => !document.getElementById('__visor_interstitial'));
      console.log('   interstitial dismissed after Proceed anyway:', afterProceed);
      if (!afterProceed) {
        failures.push('clicking Proceed anyway did not dismiss the homograph interstitial');
      }
    } finally {
      await hgPage.close().catch(() => {});
    }

    // ── Placeholder-module guard ──────────────────────────────────────────
    // The stub models must always return 'safe' — they must never gate the page.
    // The exact case that fired this bug: a benign vector with cookie_domain_mismatch
    // must NOT produce any suspicious verdict from the PLACEHOLDER modules.
    const guard = await sw.evaluate(async () => {
      const all = await chrome.storage.session.get(null);
      const key = Object.keys(all).find((k) => k.startsWith('visor:tab:'));
      const v = key ? all[key] : {};
      // Inject cookie_domain_mismatch to reproduce the exact case that fired.
      return { ...v, cookie_domain_mismatch: true };
    });
    const results = await classify(sw, guard);
    // Placeholders must always be 'safe'.
    for (const m of ['bitb', 'clickjacking']) {
      const r = results.find((r) => r.module === m);
      if (r && r.verdict !== 'safe') {
        failures.push(`placeholder module ${m} returned ${r.verdict} (score ${r.score}), expected 'safe'`);
      }
    }
    // The real models may legitimately flag this vector (it has no identity match).
    // That is correct behaviour — we only assert that placeholders don't gate.

    console.log('\n══ DOM / CONTENT SCRIPT ═══════════════════════════════════');    const tier2Merges = swLog.filter((t) => t.includes('Tier 2 vector merged'));
    console.log(`  Tier 2 feature merges seen by the worker: ${tier2Merges.length}`);
    if (tier2Merges.length) console.log(`  last: ${tier2Merges[tier2Merges.length - 1].slice(0, 160)}`);
    if (!tier2Merges.length) failures.push('the Tier 2 content script never reported features');
    const tier2Fields = ['has_password_field', 'n_forms', 'n_inputs', 'n_hidden_inputs',
      'has_autocomplete_current_password', 'script_src_is_opaque_root_path'];
    const tier2Missing = tier2Fields.filter((f) => !(f in phishVec));
    if (tier2Missing.length) failures.push(`Tier 2 fields missing from the vector: ${tier2Missing.join(', ')}`);
    else console.log(`  Tier 2 fields present in the vector: ${tier2Fields.join(', ')}`);

    // ── 5. Popup UI ───────────────────────────────────────────────────────
    // The popup is opened as a tab here, so it would otherwise read *itself*
    // as the active tab. Stub chrome.tabs.query to point at the phish tab, the
    // way a real browser popup reads the page the user is on.
    const extId = new URL(sw.url()).host;
    const phishTabId = await sw.evaluate(async () => {
      const tabs = await chrome.tabs.query({});
      return tabs.find((t) => t.url && t.url.includes('phish.kandarpjindal.in'))?.id ?? null;
    });
    if (!phishTabId) throw new Error('could not find the phish tab id');

    const popup = await ctx.newPage();
    await popup.addInitScript((tabId) => {
      try {
        Object.defineProperty(chrome, 'tabs', {
          value: {
            query: async (info) => (info && info.active)
              ? [{ id: tabId, url: 'https://wordpress.phish.kandarpjindal.in/' }]
              : [],
          },
          configurable: true,
        });
      } catch (e) { window.__stubError = e.message; }
    }, phishTabId);
    await popup.goto(`chrome-extension://${extId}/ui/popup.html`, { waitUntil: 'domcontentloaded' })
      .catch(() => {});
    await sleep(2500);
    const popupState = await popup.evaluate(() => ({
      banner: document.getElementById('verdict-banner')?.className ?? null,
      verdict: document.getElementById('verdict-text')?.textContent ?? null,
      aitm: document.getElementById('score-aitm')?.textContent ?? null,
      bitb: document.getElementById('score-bitb')?.textContent ?? null,
      homograph: document.getElementById('score-homograph')?.textContent ?? null,
      clickjacking: document.getElementById('score-clickjacking')?.textContent ?? null,
      debugHidden: !document.getElementById('debug-panel')?.classList.contains('open'),
      featureRows: document.querySelectorAll('#feature-list .feature-row').length,
    })).catch((e) => ({ error: e.message }));
    console.log('\n══ POPUP UI ══════════════════════════════════════════════');
    console.log('  ', JSON.stringify(popupState));

    if (popupState.debugHidden !== true) {
      failures.push('the debug panel is not hidden by default');
    }
    if (!/threat detected/i.test(popupState.verdict || '')) {
      failures.push(`the popup did not report the threat (verdict: "${popupState.verdict}")`);
    }
    if (!/detected/i.test(popupState.aitm || '')) {
      failures.push(`the AiTM row does not show "Detected" (got "${popupState.aitm}")`);
    }
    if (!/detected/i.test(popupState.homograph || '')) {
      failures.push(`the homograph row does not show a verdict (got "${popupState.homograph}")`);
    }
    for (const m of ['bitb', 'clickjacking']) {
      if (!/work in progress/i.test(popupState[m] || '')) {
        failures.push(`the ${m} row does not say "Work in progress"`);
      }
    }

    // The debug toggle must reveal the feature vector.
    await popup.click('#debug-toggle').catch(() => {});
    await sleep(400);
    const afterToggle = await popup.evaluate(() => ({
      open: document.getElementById('debug-panel')?.classList.contains('open'),
      rows: document.querySelectorAll('#feature-list .feature-row').length,
    })).catch(() => ({}));
    console.log('   after debug toggle:', JSON.stringify(afterToggle));
    if (!afterToggle.open || !afterToggle.rows) {
      failures.push('the debug toggle did not reveal the feature vector');
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
