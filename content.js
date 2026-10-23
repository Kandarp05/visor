// content.js: main content script orchestrator
// Loaded after feature_extractor/tier2_dom.js (see manifest).
// Responsibilities:
//   document_start -> nothing extra (tier2_dom.js already ran)
//   document_idle  -> call __visorTier2.run(), expose showInterstitial

(function visorContentMain() {
  'use strict';
  if (location.protocol === 'chrome-extension:') return;

  // Inlined from lib/constants.js (content scripts cannot use ES imports)
  const VISOR_VERSION = '0.1.0';

  console.log('[Visor content] INJECTED document_start', {
    readyState: document.readyState,
    url: location.href,
  });

  // T1.7 ping message
  try {
    chrome.runtime.sendMessage({ type: 'PHASE1_PING' }, (res) => {
      if (chrome.runtime.lastError) return;
      if (res?.block && res?.module === 'homograph') {
        showInterstitial(res);
      }
    });
  } catch (e) {}

  // ── Interstitial ────────────────────────────────────────────────────────
  // Called by tier2_dom.js via window.__visorShowInterstitial(verdict).
  // Renders a full-viewport overlay, blocking further interaction.
  //
  // It names the attack and nothing else. The evidence behind the verdict is
  // not disclosed here (see the popup Debug panel for that).
  //
  // One exception: when the homograph module names the brand the host
  // impersonates, that fact is shown, because it is what the user has to act
  // on ("this is not the site you think it is"). It is a reference-list match,
  // not a model confidence.

  // Escape text before it goes into the overlay's markup.
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  function showInterstitial(verdict) {
    document.getElementById('__visor_interstitial')?.remove();

    const overlay = document.createElement('div');
    overlay.id = '__visor_interstitial';

    const module = verdict.module ?? 'unknown';
    const impersonates = (module === 'homograph' && typeof verdict.impersonates === 'string')
      ? verdict.impersonates : null;

    let heading = 'Suspicious activity detected';
    let detail = 'Visor intercepted this action to safeguard your session.';

    if (module === 'aitm') {
      heading = 'AiTM session relay detected';
      detail = 'This website is operating as an unauthorized intermediary proxy. Submitting passwords or verification codes here may expose your credentials and active session tokens.';
    } else if (module === 'homograph') {
      heading = 'Homograph lookalike domain detected';
      if (impersonates) {
        detail = `This web address uses lookalike foreign characters to imitate <strong>${escapeHtml(impersonates)}</strong>. It is not the authentic website.`;
      } else {
        detail = 'This web address contains deceptive confusable characters and does not match the genuine site.';
      }
    } else if (module === 'bitb') {
      heading = 'Simulated popup window detected';
      detail = 'This page has rendered a fake browser window designed to mimic an external authentication service.';
    } else if (module === 'clickjacking') {
      heading = 'Hidden interactive layer detected';
      detail = 'This page contains transparent interface overlays designed to redirect your clicks.';
    }

    overlay.innerHTML = `
      <div id="__visor_box">
        <div class="__visor_header">
          <span class="__visor_pill">Security Warning</span>
        </div>
        <h1>${heading}</h1>
        <p class="__visor_desc">${detail}</p>
        <div id="__visor_actions">
          <button id="__visor_back">Back to safety</button>
          <button id="__visor_proceed">Continue anyway (unsafe)</button>
        </div>
        <div class="__visor_footer">
          Protected by Visor
        </div>
      </div>
    `;

    const style = document.createElement('style');
    style.textContent = `
      #__visor_interstitial {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(10, 12, 16, 0.92);
        backdrop-filter: blur(4px);
        display: flex; align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        padding: 20px;
        box-sizing: border-box;
      }
      #__visor_box {
        background: #121316;
        border: 1px solid #27272a;
        border-top: 3px solid #dc2626;
        border-radius: 8px;
        padding: 28px 28px 24px;
        max-width: 480px;
        width: 100%;
        text-align: left;
        color: #e4e4e7;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
        box-sizing: border-box;
      }
      #__visor_box .__visor_pill {
        display: inline-block;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #f87171;
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        margin-bottom: 14px;
      }
      #__visor_box h1 {
        color: #ffffff;
        font-size: 1.15rem;
        font-weight: 600;
        line-height: 1.35;
        letter-spacing: -0.01em;
        margin: 0 0 10px;
      }
      #__visor_box .__visor_desc {
        color: #a1a1aa;
        font-size: 0.88rem;
        line-height: 1.5;
        margin: 0 0 22px;
      }
      #__visor_box .__visor_desc strong {
        color: #ffffff;
        font-weight: 600;
      }
      #__visor_actions {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      #__visor_back {
        background: #2563eb;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        padding: 9px 16px;
        cursor: pointer;
        font-size: 0.85rem;
        font-weight: 500;
        transition: background 0.15s ease;
      }
      #__visor_back:hover {
        background: #1d4ed8;
      }
      #__visor_proceed {
        background: transparent;
        color: #71717a;
        border: 1px solid #27272a;
        border-radius: 6px;
        padding: 9px 14px;
        cursor: pointer;
        font-size: 0.82rem;
        transition: color 0.15s ease, border-color 0.15s ease;
      }
      #__visor_proceed:hover {
        border-color: #3f3f46;
        color: #e4e4e7;
      }
      #__visor_box .__visor_footer {
        margin-top: 20px;
        padding-top: 14px;
        border-top: 1px solid #1f2024;
        font-size: 0.75rem;
        color: #52525b;
      }
    `;
    overlay.prepend(style);

    // Button handlers
    overlay.querySelector('#__visor_back').addEventListener('click', () => {
      history.back();
    });
    overlay.querySelector('#__visor_proceed').addEventListener('click', () => {
      overlay.remove();
      try {
        chrome.runtime.sendMessage({ type: 'BYPASS_HOMOGRAPH' }, () => {
          if (chrome.runtime.lastError) {}
        });
      } catch (e) {}
      const form = window.__visorPendingForm;
      const submitter = window.__visorPendingSubmitter || null;
      if (form) {
        window.__visorPendingForm = null;
        window.__visorPendingSubmitter = null;
        if (typeof window.__visorNativeSubmit === 'function') {
          window.__visorNativeSubmit(form, submitter);
        } else {
          try {
            if (submitter && typeof form.requestSubmit === 'function') {
              form.requestSubmit(submitter);
            } else {
              HTMLFormElement.prototype.submit.call(form);
            }
          } catch (e) {
            console.warn('[Visor] could not submit form', e);
          }
        }
      }
    });

    document.documentElement.appendChild(overlay);
  }

  // Expose so tier2_dom.js can call it
  window.__visorShowInterstitial = showInterstitial;

  // ── document_idle: run Tier 2 scan ─────────────────────────────────────

  function onDomReady() {
    console.log('[Visor content] DOM ready, running Tier 2 scan', {
      url: location.href,
      readyState: document.readyState,
    });

    if (typeof window.__visorTier2?.run === 'function') {
      const features = window.__visorTier2.run();
      window.__visorLastFeatures = features; // used by interstitial for display
      console.log('[Visor content] Tier 2 features:', features);
    } else {
      console.warn('[Visor content] __visorTier2 not defined (tier2_dom.js missing?)');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onDomReady, { once: true });
    window.addEventListener('load', onDomReady, { once: true });
  } else {
    onDomReady();
  }

  // Backup scans for SPAs / dynamic script renders
  setTimeout(onDomReady, 500);
  setTimeout(onDomReady, 1500);

  // Continuous extraction: Watch for dynamic DOM additions, attribute updates (e.g. style/type changes)
  try {
    let debounceTimer = null;
    function triggerScan(delay = 250) {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(onDomReady, delay);
    }

    const observer = new MutationObserver(() => triggerScan(250));
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['type', 'action', 'style', 'class', 'href', 'src'],
    });

    // Window resize & scroll keep iframe viewport coverage live
    window.addEventListener('resize', () => triggerScan(300), { passive: true });
    window.addEventListener('scroll', () => triggerScan(300), { passive: true });

    // Focus listener to bind dynamically revealed login forms immediately upon interaction
    document.addEventListener('focusin', (e) => {
      if (typeof window.__visorIsCredentialInputField === 'function') {
        if (window.__visorIsCredentialInputField(e.target)) {
          onDomReady();
        }
      } else if (e.target.matches?.('input[type="password"], input[autocomplete*="password" i]')) {
        onDomReady();
      }
    }, { passive: true });
  } catch (e) {
    // ignore observer errors if any
  }
})();
