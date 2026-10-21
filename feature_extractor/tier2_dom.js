// feature_extractor/tier2_dom.js
// Tier 2 DOM feature extraction — runs as a content script.
// Loaded before content.js via manifest content_scripts ordering.
// Defines window.__visorTier2 so content.js can call it.

(function defineTier2() {
  if (location.protocol === 'chrome-extension:') return;

  try {
    // ── Helpers ────────────────────────────────────────────────────────────

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

    function effectiveZIndex(el) {
      const z = parseInt(window.getComputedStyle(el).zIndex, 10);
      return isNaN(z) ? 0 : z;
    }

    function hostname(urlStr) {
      try {
        return new URL(urlStr, location.href).hostname.toLowerCase();
      } catch {
        return null;
      }
    }

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

      // WordPress / CMS API and shortlinks
      const apiLinks = document.querySelectorAll('link[rel*="api.w.org"], link[rel="shortlink"], link[rel="alternate"]');
      apiLinks.forEach((l) => {
        if (l.href) {
          const h = hostname(l.href);
          if (h) hosts.add(h);
        }
      });

      // <base href="...">
      const baseEl = document.querySelector('base[href]');
      if (baseEl?.href) {
        const h = hostname(baseEl.href);
        if (h) hosts.add(h);
      }

      // JSON-LD @id or url
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
        } catch {
          // ignore invalid json-ld
        }
      });

      return [...hosts];
    }

    // ── BiTB listener from MAIN world ─────────────────────────────────────
    function handleBitbAttempt(targetUrl) {
      console.log('[Visor Tier2] window.open intercepted', { url: targetUrl });
      chrome.runtime.sendMessage(
        { type: 'BITB_WINDOW_OPEN', payload: { url: targetUrl } },
        (response) => {
          if (chrome.runtime.lastError) return;
          if (response?.block) {
            document.documentElement.setAttribute('data-visor-bitb-block', 'true');
            console.warn('[Visor Tier2] window.open BLOCKED (BiTB suspicious)');
            if (typeof window.__visorShowInterstitial === 'function') {
              window.__visorShowInterstitial({
                module: 'bitb',
                score: response.score || 0.8,
                verdict: 'suspicious',
              });
            }
          }
        }
      );
    }

    window.addEventListener('__visor_bitb_attempt', (e) => {
      handleBitbAttempt(e.detail?.url ?? '');
    });

    // ── Credential field matching (D5) ───────────────────────────────────
    function isElementVisible(el) {
      if (!el) return false;
      if (el.type === 'hidden') return false;
      if (el.offsetParent !== null) return true;
      const rects = el.getClientRects();
      return rects && rects.length > 0;
    }

    function isCredentialInputField(el) {
      if (!el || el.tagName !== 'INPUT') return false;
      if (!isElementVisible(el)) return false;

      const rawType = (el.getAttribute('type') || 'text').toLowerCase();
      const allowedTypes = new Set(['password', 'text', 'email', 'tel', 'number']);
      if (!allowedTypes.has(rawType)) return false;

      const autocomplete = (el.getAttribute('autocomplete') || '').toLowerCase();
      const name = (el.getAttribute('name') || '').toLowerCase();
      const id = (el.getAttribute('id') || '').toLowerCase();

      // 1. Password input
      if (rawType === 'password' || autocomplete.includes('password')) return true;

      // 2. Email input
      if (rawType === 'email' || autocomplete.includes('email') || name.includes('email') || id.includes('email')) return true;

      // 3. Username / login input (only visible, matching specific username/login tokens)
      if (
        autocomplete.includes('username') ||
        name === 'username' || name === 'user' || name === 'login' ||
        name.startsWith('user_') || name.startsWith('login_') ||
        id === 'username' || id === 'user' || id === 'login'
      ) {
        return true;
      }

      // 4. 2FA / OTP / Authcode (covers authcode, otp, 2fa, one-time-code)
      if (
        autocomplete.includes('one-time-code') ||
        name.includes('auth') || name.includes('otp') ||
        id.includes('auth') || id.includes('otp')
      ) {
        return true;
      }

      return false;
    }

    // Expose for unit verification
    window.__visorIsCredentialInputField = isCredentialInputField;
    window.__visorIsElementVisible = isElementVisible;

    // ── DOM scan ──────────────────────────────────────────────────────────

    function scanDOM() {
      const pageHost = location.hostname.toLowerCase();
      const features = {};

      // Password fields strictly: input[type="password"] or autocomplete containing password
      const passwordFields = [
        ...document.querySelectorAll('input[type="password"], input[autocomplete*="password" i]'),
      ];
      features.has_password_field = passwordFields.length > 0;
      features.n_password_fields = passwordFields.length;
      features.has_autocomplete_current_password = passwordFields.some((f) =>
        (f.getAttribute('autocomplete') || '').toLowerCase().includes('current-password')
      );

      // Credential-bearing forms: forms containing visible human-typed credential inputs (D5)
      const allInputs = [...document.querySelectorAll('input')];
      const credInputs = allInputs.filter(isCredentialInputField);
      const credentialForms = new Set(
        credInputs.map((f) => f.closest('form')).filter(Boolean)
      );

      // Form counts and structure
      features.n_forms = document.forms.length;
      features.n_inputs = document.querySelectorAll('input').length;
      features.n_hidden_inputs = document.querySelectorAll('input[type="hidden"]').length;
      features.form_action_mismatch = false;

      for (const form of credentialForms) {
        const actionHost = hostname(form.action || location.href);
        if (actionHost && actionHost !== pageHost) {
          features.form_action_mismatch = true;
          break;
        }
      }

      // Iframes (clickjacking signals)
      const iframes = [...document.querySelectorAll('iframe')];
      features.has_iframe = iframes.length > 0;
      features.iframe_overlap_viewport = false;

      for (const iframe of iframes) {
        try {
          const style   = window.getComputedStyle(iframe);
          const opacity = parseFloat(style.opacity ?? '1');
          const zIdx    = effectiveZIndex(iframe);
          const pos     = style.position;

          const isSuspicious =
            (pos === 'fixed' || pos === 'absolute') &&
            (zIdx > 10 || opacity < 0.1) &&
            coversViewport(iframe);

          if (isSuspicious) {
            features.iframe_overlap_viewport = true;
            break;
          }
        } catch {
          // ignore iframe read error
        }
      }

      // Identity host mismatch (homograph/AiTM signal)
      const iHosts = identityHosts();
      features.identity_host_mismatch =
        iHosts.length > 0 && iHosts.some((h) => h !== pageHost);

      // ── Opaque root-path scripts (class-generic) ─────────────────────────
      // A proxy that injects a session-bound bootstrap script typically serves it
      // from a root-relative opaque path the legitimate origin does not serve.
      // The *shape* generalises across kits; a raw script count does not.
      const OPAQUE_ROOT_SCRIPT = /\/[0-9a-f]{32,64}\.js$/;
      const scriptSrcs = [...document.querySelectorAll('script[src]')].map((s) => {
        const raw = s.getAttribute('src') || '';
        let path = raw;
        try { path = new URL(raw, location.href).pathname; } catch {}
        return path;
      });
      const opaqueScripts = scriptSrcs.filter((p) => OPAQUE_ROOT_SCRIPT.test(p));
      features.script_src_is_opaque_root_path = opaqueScripts.length > 0;
      features.n_opaque_root_scripts = opaqueScripts.length;

      // Storage keys
      try {
        features.localStorage_keys = Object.keys(localStorage);
      } catch {
        features.localStorage_keys = [];
      }
      try {
        features.sessionStorage_keys = Object.keys(sessionStorage);
      } catch {
        features.sessionStorage_keys = [];
      }

      // Environment & display
      features.character_set = document.characterSet || document.charset || null;
      features.viewport_w = window.innerWidth || document.documentElement.clientWidth;
      features.viewport_h = window.innerHeight || document.documentElement.clientHeight;
      features.dpr = window.devicePixelRatio || 1;

      // Navigation Timing breakdown (E1 & E4)
      try {
        const navEntries = performance.getEntriesByType('navigation');
        if (navEntries && navEntries.length > 0) {
          const nav = navEntries[0];
          // dns_ms: pooled connection reports 0, fresh reports duration
          features.dns_ms = (nav.domainLookupEnd >= 0 && nav.domainLookupStart >= 0)
            ? Math.max(0, nav.domainLookupEnd - nav.domainLookupStart)
            : 0.0;

          // connect_ms: pooled connection reports 0, fresh reports duration
          features.connect_ms = (nav.connectEnd >= 0 && nav.connectStart >= 0)
            ? Math.max(0, nav.connectEnd - nav.connectStart)
            : 0.0;

          // ssl_ms:
          // pooled HTTPS connection (secureConnectionStart === 0) -> 0.0
          // fresh TLS handshake (secureConnectionStart > 0) -> connectEnd - secureConnectionStart
          // plain HTTP -> null (genuinely not applicable)
          const isHttps = location.protocol === 'https:';
          if (isHttps) {
            features.ssl_ms = (nav.secureConnectionStart > 0 && nav.connectEnd >= nav.secureConnectionStart)
              ? Math.max(0, nav.connectEnd - nav.secureConnectionStart)
              : 0.0;
          } else {
            features.ssl_ms = null;
          }

          features.ttfb_ms = (nav.responseStart >= 0 && nav.requestStart >= 0)
            ? Math.max(0, nav.responseStart - nav.requestStart)
            : 0.0;

          features.download_ms = (nav.responseEnd >= 0 && nav.responseStart >= 0)
            ? Math.max(0, nav.responseEnd - nav.responseStart)
            : 0.0;

          if (nav.domInteractive >= 0) {
            features.dom_interactive_ms = Math.max(0, nav.domInteractive);
          }
          if (nav.domContentLoadedEventEnd >= 0) {
            features.dom_content_loaded_ms = Math.max(0, nav.domContentLoadedEventEnd);
          }
          if (nav.loadEventEnd >= 0) {
            features.load_event_ms = Math.max(0, nav.loadEventEnd);
          }
        }

        // Connection reuse derivation from Resource Timing entries (E1)
        const resEntries = performance.getEntriesByType('resource') || [];
        let freshHandshakes = 0;
        if (navEntries && navEntries.length > 0) {
          const nav = navEntries[0];
          if (nav.connectEnd > 0 && (nav.domainLookupEnd > nav.domainLookupStart || nav.connectEnd > nav.connectStart)) {
            freshHandshakes++;
          }
        }
        for (const res of resEntries) {
          if (res.connectEnd > 0 && (res.domainLookupEnd > res.domainLookupStart || res.connectEnd > res.connectStart)) {
            freshHandshakes++;
          }
        }
        const totalRequests = (navEntries && navEntries.length > 0 ? 1 : 0) + resEntries.length;
        const reuseRatio = totalRequests > 0 ? (1.0 - (freshHandshakes / totalRequests)) : 0.0;
        features.n_new_connections = freshHandshakes;
        features.connection_reuse_ratio = parseFloat(reuseRatio.toFixed(3));
      } catch (e) {
        // performance timing access failed
      }

      return { features, credentialForms: [...credentialForms] };
    }

    // ── Form submit listener ─────────────────────────────────────────────

    let _pendingForm = null;
    let _submitting = false;
    const attachedForms = new WeakSet();

    function installFormListeners(credentialForms) {
      for (const form of credentialForms) {
        if (attachedForms.has(form)) continue;
        attachedForms.add(form);

        form.addEventListener('submit', (event) => {
          if (_submitting) return; // allow actual submit through

          event.preventDefault();
          event.stopPropagation();
          _pendingForm = form;

          // Fresh scan at the exact moment of submit to capture any last-millisecond DOM changes
          const fresh = scanDOM();
          window.__visorLastFeatures = fresh.features;

          chrome.runtime.sendMessage({ type: 'FORM_SUBMIT', payload: { features: fresh.features } }, (response) => {
            if (chrome.runtime.lastError || !response) {
              _submitting = true;
              _pendingForm?.submit();
              _submitting = false;
              _pendingForm = null;
              return;
            }

            if (response.verdict === 'suspicious') {
              window.__visorPendingForm = _pendingForm;
              if (typeof window.__visorShowInterstitial === 'function') {
                window.__visorShowInterstitial(response);
              } else {
                alert(`[Visor Warning] Phishing detected (${response.module.toUpperCase()}). Submission blocked.`);
              }
            } else {
              _submitting = true;
              _pendingForm?.submit();
              _submitting = false;
              _pendingForm = null;
            }
          });
        }, true);
      }
    }

    // ── Public surface ───────────────────────────────────────────────────

    window.__visorTier2 = {
      run() {
        const { features, credentialForms } = scanDOM();

        chrome.runtime.sendMessage(
          { type: 'TIER2_FEATURES', payload: features },
          () => {
            if (chrome.runtime.lastError) {
              // message ignored if port closed
            }
          }
        );

        if (features.iframe_overlap_viewport) {
          chrome.runtime.sendMessage(
            { type: 'IFRAME_SUSPICIOUS', payload: {} },
            (response) => {
              if (chrome.runtime.lastError) return;
              if (response?.block) {
                const iframes = [...document.querySelectorAll('iframe')];
                let count = 0;
                for (const fr of iframes) {
                  try {
                    const style = window.getComputedStyle(fr);
                    const opacity = parseFloat(style.opacity ?? '1');
                    const zIdx = effectiveZIndex(fr);
                    const pos = style.position;
                    if ((pos === 'fixed' || pos === 'absolute') && (zIdx > 10 || opacity < 0.1) && coversViewport(fr)) {
                      fr.style.pointerEvents = 'none';
                      fr.setAttribute('data-visor-clickjack-neutralized', 'true');
                      count++;
                    }
                  } catch {}
                }
                console.warn(`[Visor Tier2] Clickjacking neutralized: disabled pointer-events on ${count} overlay iframe(s)`);
              }
            }
          );
        }

        if (credentialForms.length > 0) {
          installFormListeners(credentialForms);
        }

        return features;
      },
    };

    console.log('[Visor Tier2] initialized successfully');
  } catch (err) {
    console.error('[Visor Tier2] init error:', err);
  }
})();
