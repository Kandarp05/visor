# Visor tests

## `e2e.js` — the end-to-end check (self-contained)

Launches Chrome with the extension loaded, visits the real benign site and the real
AiTM-proxied site, and verifies that the extension actually works.

```bash
node visor/test/e2e.js            # headless (new headless mode — required for extensions)
node visor/test/e2e.js --headful  # needs a display
node visor/test/e2e.js --keep-open
```

**Note:** the default Playwright headless build does **not** load extensions. The test
uses `channel: 'chromium'` (the new headless mode), which does.

### What it checks

1. The service worker starts and evaluates `background.js` before the first navigation
   (an MV3 worker starts lazily, and one that only wakes on the content script's first
   message has already missed that navigation's request headers).
2. **21 allowlisted features are populated** on all three pages — the origin-identity
   leak, entry path, redirect hops, cookie scope, request-stream counts, DOM and
   environment.
3. The AiTM model runs and returns a verdict for all three pages.
4. The three pages get **different scores** (benign vs proxied).
5. The Tier 2 content script reports features to the worker (Tier 2 runs in the
   content script's isolated world, so it is invisible to `page.evaluate()` — the test
   watches the worker's console instead).

### The three pages tested

| page | why |
|---|---|
| `https://wordpress.kandarpjindal.in/` | the legitimate site — must be **safe** |
| `https://wordpress.phish.kandarpjindal.in/` | the proxied site — must be **suspicious** |
| `https://wordpress.phish.kandarpjindal.in/wp-login.php` | the **credential page**, where the interstitial actually fires |

The credential page is the interesting one. It carries **no** `Link` header, so
`identity_host_mismatch_header` is `false` there — but the session-scoped
`ever_saw_identity_mismatch_header` is `true`, because the homepage visit earlier in
the same tab already saw the leak. That is what makes the gate fire at the moment
credentials are submitted.

### Expected output

```
── BENIGN ─────────────────────────────────────────
   ✓ identity_host_mismatch_header        false
   ✓ ever_saw_identity_mismatch_header    false
   ✓ cookie_domain_mismatch               false
   ✓ script_src_is_opaque_root_path       false
   ...
   verdicts: aitm=0(safe)  bitb=0(safe)  homograph=0(safe)  clickjacking=0(safe)

── AiTM (proxied) ─────────────────────────────────────────
   ✓ identity_host_mismatch_header        true
   ✓ ever_saw_identity_mismatch_header    true
   ✓ cookie_domain_mismatch               true
   ✓ script_src_is_opaque_root_path       true
   ✓ entry_path                           "redirect_entry"
   ✓ redirect_hop_count                   1
   ...
   verdicts: aitm=1(suspicious)  ...

── AiTM (credential page) ─────────────────────────────────────────
   ✓ identity_host_mismatch_header        false      <- no Link header on the login page
   ✓ ever_saw_identity_mismatch_header    true       <- carried from the earlier visit
   ✓ has_password_field                   true
   ...
   verdicts: aitm=1(suspicious)  ...

══ VERDICT ══════════════════════════════════════
  benign            aitm score = 0  (safe)
  phish (home)      aitm score = 1  (suspicious)
  phish (login)     aitm score = 1  (suspicious)

✓ END-TO-END TEST PASSED
```

## `run_checks.js` / `suite_runner.js` — manual, against a running Chrome

These connect to a Chrome you launched yourself on port 9222 with the extension
already installed, and drive the full Phase 1–6 suite (including the interstitial on
credential submission and the clickjacking neutralisation).

```bash
google-chrome --remote-debugging-port=9222 --load-extension=$PWD/visor
node visor/test/suite_runner.js
```

They cover the UI and intervention paths that `e2e.js` deliberately leaves alone.
