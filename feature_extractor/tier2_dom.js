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

    // ── document_start: window.open wrap (BiTB) ───────────────────────────
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

    try {
      const _originalOpen = window.open.bind(window);
      window.open = function visorOpenWrap(...args) {
        handleBitbAttempt(args[0] ?? '');
        if (document.documentElement.getAttribute('data-visor-bitb-block') === 'true') {
          console.warn('[Visor Tier2] window.open BLOCKED (BiTB suspicious)');
          return null;
        }
        return _originalOpen(...args);
      };
    } catch (e) {
      console.warn('[Visor Tier2] Failed to wrap window.open:', e);
    }

    // ── DOM scan ──────────────────────────────────────────────────────────

    function scanDOM() {
      const pageHost = location.hostname.toLowerCase();
      const features = {};

      // ── Password fields & form action mismatch ──────────────────────────
      const passwordFields = [
        ...document.querySelectorAll('input[type="password"], input[name*="pass" i], input[autocomplete*="password" i]'),
      ];
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

      // ── Identity host mismatch (homograph/AiTM signal) ──────────────────
      const iHosts = identityHosts();
      features.identity_host_mismatch =
        iHosts.length > 0 && iHosts.some((h) => h !== pageHost);

      return { features, formsWithPassword: [...formsWithPassword] };
    }

    // ── Form submit listener ─────────────────────────────────────────────

    let _pendingForm = null;
    let _submitting = false;
    const attachedForms = new WeakSet();

    function installFormListeners(formsWithPassword) {
      for (const form of formsWithPassword) {
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
        const { features, formsWithPassword } = scanDOM();

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

        if (features.has_password_field) {
          installFormListeners(formsWithPassword);
        }

        return features;
      },
    };

    console.log('[Visor Tier2] initialized successfully');
  } catch (err) {
    console.error('[Visor Tier2] init error:', err);
  }
})();
