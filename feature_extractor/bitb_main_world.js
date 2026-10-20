// feature_extractor/bitb_main_world.js
// Runs in the webpage's MAIN world at document_start.
// Wraps window.open to intercept BiTB fake popups before page scripts can execute.

(function initBitbMainWorld() {
  try {
    const _originalOpen = window.open.bind(window);

    window.open = function visorOpenWrap(...args) {
      const targetUrl = args[0] ?? '';
      console.log('[Visor MAIN] window.open intercepted:', targetUrl);

      // Dispatch event to the isolated world content script
      window.dispatchEvent(
        new CustomEvent('__visor_bitb_attempt', {
          detail: { url: targetUrl },
        })
      );

      // If already blocked or marked suspicious by Visor
      if (document.documentElement.getAttribute('data-visor-bitb-block') === 'true') {
        console.warn('[Visor MAIN] window.open BLOCKED (BiTB suspicious)');
        return null;
      }

      return _originalOpen(...args);
    };

    console.log('[Visor MAIN] BiTB window.open guard installed');
  } catch (e) {
    console.warn('[Visor MAIN] Failed to install window.open guard:', e);
  }
})();
