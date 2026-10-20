// feature_extractor/tier2_dom.js
// Tier 2 DOM feature extraction — runs as a content script.
// Loaded before content.js via manifest content_scripts ordering.
// Defines window.__visorTier2 so content.js can call it.
//
// Runs in two passes:
//   document_start  → wraps window.open (BiTB intercept)
//   document_idle   → scans settled DOM for all other features

(function defineTier2() {
  'use strict';

  // Guard: don't run in extension pages
  if (location.protocol === 'chrome-extension:') return;

  // ── Helpers ────────────────────────────────────────────────────────────

  /** True if the element's bounding rect covers ≥50% of the viewport area. */
  function coversViewport(el) {
    const r = el.getBoundingClientRect();
    const vw = window.innerWidth  || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    const overlapW = Math.min(r.right, vw)  - Math.max(r.left, 0);
    const overlapH = Math.min(r.bottom, vh) - Math.max(r.top, 0);
    if (overlapW <= 0 || overlapH <= 0) return false;
    const overlapArea = overlapW * overlapH;
    const viewportArea = vw * vh;
    return overlapArea / viewportArea >= 0.5;
  }

  /** Return numeric z-index (or 0 if auto/none). */
  function effectiveZIndex(el) {
    const z = parseInt(window.getComputedStyle(el).zIndex, 10);
    return isNaN(z) ? 0 : z;
  }

  /** Extract hostname from a URL string, null on failure. */
  function hostname(urlStr) {
    try { return new URL(urlStr).hostname.toLowerCase(); } catch { return null; }
  }

  /** Extract identity marker hosts from the settled DOM. */
  function identityHosts() {
    const hosts = new Set();

    // <link rel="canonical">
    const canonical = document.querySelector('link[rel="canonical"]');
    if (canonical?.href) {
      const h = hostname(canonical.href);
      if (h) hosts.add(h);
    }

    // OpenGraph og:url
    const og = document.querySelector('meta[property="og:url"]');
    if (og?.content) {
      const h = hostname(og.content);
      if (h) hosts.add(h);
    }

    // JSON-LD @id on Thing/@graph
    document.querySelectorAll('script[type="application/ld+json"]').forEach((s) => {
      try {
        const data = JSON.parse(s.textContent);
        const check = (obj) => {
          if (!obj || typeof obj !== 'object') return;
          if (obj['@id']) { const h = hostname(obj['@id']); if (h) hosts.add(h); }
          if (obj.url)    { const h = hostname(obj.url);    if (h) hosts.add(h); }
          if (Array.isArray(obj['@graph'])) obj['@graph'].forEach(check);
        };
        check(data);
      } catch { /* malformed JSON-LD — ignore */ }
    });

    return [...hosts];
  }

  // ── document_start: window.open wrap (BiTB) ───────────────────────────
  // Must run before any page script to intercept fake popup creation.

  const _originalOpen = window.open.bind(window);
  window.open = function visorOpenWrap(...args) {
    const targetUrl = args[0] ?? '';
    console.log('[Visor Tier2] window.open intercepted', { url: targetUrl });

    // Send to background; response tells us whether to block
    chrome.runtime.sendMessage(
      { type: 'BITB_WINDOW_OPEN', payload: { url: targetUrl } },
      (response) => {
        if (chrome.runtime.lastError) return;
        if (response?.block) {
          console.warn('[Visor Tier2] window.open BLOCKED (BiTB verdict: suspicious)');
          // Don't call _originalOpen — popup suppressed
        } else {
          _originalOpen(...args);
        }
      }
    );
    // Return null synchronously; the real popup (if allowed) opens async.
    // This means scripts that rely on the popup handle synchronously will break,
    // which is an acceptable trade-off for security.
    return null;
  };

  // ── document_idle: full DOM scan ─────────────────────────────────────

  function scanDOM() {
    const pageHost = location.hostname.toLowerCase();
    const features = {};

    // ── Password fields & form action mismatch ──────────────────────────
    const passwordFields = [...document.querySelectorAll('input[type="password"]')];
    features.has_password_field = passwordFields.length > 0;
    features.form_action_mismatch = false;

    const formsWithPassword = new Set(
      passwordFields.map((f) => f.closest('form')).filter(Boolean)
    );

    for (const form of formsWithPassword) {
      const actionHost = hostname(form.action || location.href);
      if (actionHost && actionHost !== pageHost) {
        features.form_action_mismatch = true;
        break;
      }
    }

    // ── Iframes (clickjacking signals) ──────────────────────────────────
    const iframes = [...document.querySelectorAll('iframe')];
    features.has_iframe = iframes.length > 0;
    features.iframe_overlap_viewport = false;

    for (const iframe of iframes) {
      const style   = window.getComputedStyle(iframe);
      const opacity = parseFloat(style.opacity ?? '1');
      const zIdx    = effectiveZIndex(iframe);
      const pos     = style.position;

      // Suspicious iframe: positioned, high z-index OR low opacity, large coverage
      const isSuspicious =
        (pos === 'fixed' || pos === 'absolute') &&
        (zIdx > 10 || opacity < 0.1) &&
        coversViewport(iframe);

      if (isSuspicious) {
        features.iframe_overlap_viewport = true;
        break;
      }
    }

    // ── Identity host mismatch (homograph/AiTM signal) ──────────────────
    const iHosts = identityHosts();
    features.identity_host_mismatch =
      iHosts.length > 0 && iHosts.some((h) => h !== pageHost);

    return { features, formsWithPassword: [...formsWithPassword] };
  }

  // ── Form submit listener (installed at document_idle) ─────────────────

  let _pendingForm = null; // reference kept for "Proceed anyway" button

  function installFormListeners(formsWithPassword) {
    for (const form of formsWithPassword) {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        _pendingForm = form;

        chrome.runtime.sendMessage({ type: 'FORM_SUBMIT', payload: {} }, (response) => {
          if (chrome.runtime.lastError) {
            // Background unreachable — let it through
            _pendingForm?.submit();
            _pendingForm = null;
            return;
          }
          if (response?.verdict === 'suspicious') {
            // content.js showInterstitial reads window.__visorPendingForm
            window.__visorPendingForm = _pendingForm;
            window.__visorShowInterstitial(response);
          } else {
            _pendingForm?.submit();
            _pendingForm = null;
          }
        });
      }, { once: false });
    }
  }

  // ── Public surface (called by content.js at document_idle) ───────────

  window.__visorTier2 = {
    /**
     * Run the full DOM scan, post features to background, install submit
     * listeners. Returns the raw feature object.
     */
    run() {
      const { features, formsWithPassword } = scanDOM();

      chrome.runtime.sendMessage(
        { type: 'TIER2_FEATURES', payload: features },
        () => { if (chrome.runtime.lastError) {} }
      );

      // Clickjacking: send IFRAME_SUSPICIOUS if we detected a suspicious iframe
      if (features.iframe_overlap_viewport) {
        chrome.runtime.sendMessage(
          { type: 'IFRAME_SUSPICIOUS', payload: {} },
          (response) => {
            if (chrome.runtime.lastError) return;
            if (response?.block) {
              // Disable pointer events on all suspicious iframes
              document.querySelectorAll('iframe').forEach((fr) => {
                fr.style.pointerEvents = 'none';
              });
              console.warn('[Visor Tier2] Clickjacking iframes neutralized');
            }
          }
        );
      }

      if (features.has_password_field) {
        installFormListeners(formsWithPassword);
      }

      return features;
    },
  };
})();
