// test/run_checks.js
// Automated verification across Phase 1 to Phase 6 on the live Chrome browser.

const PORT = 9222;

async function fetchJson(endpoint) {
  const res = await fetch(`http://127.0.0.1:${PORT}${endpoint}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function sendCdp(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1000000);
    const handler = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.id === id) {
          ws.removeEventListener('message', handler);
          if (data.error) reject(data.error);
          else resolve(data.result);
        }
      } catch (e) {
        reject(e);
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  console.log('Connecting to your active Chrome browser at port ' + PORT + '...');
  const targets = await fetchJson('/json');
  console.log(`✓ Connected. Found ${targets.length} targets.`);

  // Find the primary page tab
  const pageTarget = targets.find((t) => t.type === 'page' && !t.url.startsWith('devtools:'));
  if (!pageTarget) throw new Error('No open web page tab found in Chrome');
  console.log(`Using tab: "${pageTarget.title}" (${pageTarget.url})`);

  const pageWs = new WebSocket(pageTarget.webSocketDebuggerUrl);
  await new Promise((r) => pageWs.addEventListener('open', r, { once: true }));
  await sendCdp(pageWs, 'Page.enable');
  await sendCdp(pageWs, 'Runtime.enable');

  pageWs.addEventListener('message', (msg) => {
    const data = JSON.parse(msg.data);
    if (data.method === 'Runtime.consoleAPICalled') {
      const text = (data.params.args || []).map(a => a.value ?? a.description ?? JSON.stringify(a)).join(' ');
      console.log('  [Page Console]', text);
    }
  });

  // ── PHASE 1 & 2: Navigate to WordPress Benign ──────────────────────────
  console.log('\n======================================================');
  console.log('TEST 1: Benign Site (https://wordpress.kandarpjindal.in/)');
  console.log('======================================================');
  console.log('Navigating tab to https://wordpress.kandarpjindal.in/ ...');
  await sendCdp(pageWs, 'Page.navigate', { url: 'https://wordpress.kandarpjindal.in/' });
  
  console.log('Waiting 5s for network capture, rdap/crt.sh lookup, and DOM scan...');
  await sleep(5000);

  // Check Visor Service Worker
  const updatedTargets = await fetchJson('/json');
  const sw = updatedTargets.find((t) => t.type === 'service_worker' && (t.url.includes('pahjjpdfenijcdopoeiffoocdhdgdiln') || t.url.includes('background.js')));
  
  if (!sw) {
    console.log('Service worker not currently awake, checking extensions list in chrome://extensions...');
  } else {
    console.log('✓ Visor Service Worker active:', sw.url);
    const swWs = new WebSocket(sw.webSocketDebuggerUrl);
    await new Promise((r) => swWs.addEventListener('open', r, { once: true }));
    
    // Read session storage
    const storageRes = await sendCdp(swWs, 'Runtime.evaluate', {
      expression: 'chrome.storage.session.get(null)',
      awaitPromise: true,
      returnByValue: true,
    });
    console.log('\n--- Live Feature Vector in Session Storage ---');
    console.dir(storageRes?.result?.value, { depth: null });
    swWs.close();
  }

  // ── PHASE 3 & 4: Check DOM scan directly on the page ──────────────────
  console.log('\n--- Checking Tier 2 DOM Execution in Page Context ---');
  const domEval = await sendCdp(pageWs, 'Runtime.evaluate', {
    expression: `
      (() => {
        return {
          readyState: document.readyState,
          hasTier2: typeof window.__visorTier2 !== 'undefined',
          lastFeatures: window.__visorLastFeatures || null,
          passwordInputs: document.querySelectorAll('input[type="password"]').length,
          allInputs: Array.from(document.querySelectorAll('input')).map(i => ({ type: i.type, name: i.name })),
        };
      })()
    `,
    returnByValue: true,
  });
  console.log('DOM Evaluation result:', domEval?.result?.value);

  // ── TEST 2: Navigate to Phishing Site ──────────────────────────────────
  console.log('\n======================================================');
  console.log('TEST 2: Phishing Site (https://wordpress.phish.kandarpjindal.in/)');
  console.log('======================================================');
  console.log('Navigating tab to https://wordpress.phish.kandarpjindal.in/ ...');
  await sendCdp(pageWs, 'Page.navigate', { url: 'https://wordpress.phish.kandarpjindal.in/' });
  
  console.log('Waiting 5s for network capture and DOM scan on phish site...');
  await sleep(5000);

  if (sw) {
    const swWs = new WebSocket(sw.webSocketDebuggerUrl);
    await new Promise((r) => swWs.addEventListener('open', r, { once: true }));
    const storageRes = await sendCdp(swWs, 'Runtime.evaluate', {
      expression: 'chrome.storage.session.get(null)',
      awaitPromise: true,
      returnByValue: true,
    });
    console.log('\n--- Phishing Site Feature Vector in Session Storage ---');
    console.dir(storageRes?.result?.value, { depth: null });

    // Also run classifier evaluation
    const classifyRes = await sendCdp(swWs, 'Runtime.evaluate', {
      expression: `
        (async () => {
          const { getVector } = await import('./feature_extractor/session_state.js');
          const { classifyAll } = await import('./models/interface.js');
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          const vec = tab ? await getVector(tab.id) : null;
          return { vec, verdicts: vec ? classifyAll(vec) : null };
        })()
      `,
      awaitPromise: true,
      returnByValue: true,
    });
    console.log('\n--- Classifier Verdict Output for Phishing Tab ---');
    console.dir(classifyRes?.result?.value, { depth: null });

    swWs.close();
  }

  pageWs.close();
  console.log('\n✓ Checks completed.');
}

main().catch(console.error);
