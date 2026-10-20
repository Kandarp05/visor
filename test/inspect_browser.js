// test/inspect_browser.js
// Connects to Chrome via remote debugging (port 9222) to inspect Visor live.
// Usage: node test/inspect_browser.js

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

async function main() {
  console.log('Connecting to Chrome at 127.0.0.1:' + PORT + '...');
  let targets;
  try {
    targets = await fetchJson('/json');
  } catch (err) {
    console.error('❌ Could not connect to Chrome on port 9222.');
    console.error('Please launch Chrome with:');
    console.error('   google-chrome-stable --remote-debugging-port=9222\n');
    process.exit(1);
  }

  console.log(`✓ Connected. Found ${targets.length} open targets.`);

  // Find Visor service worker
  const sw = targets.find((t) => t.type === 'service_worker' && (t.url.includes('visor') || t.url.includes('pahjjpdfenijcdopoeiffoocdhdgdiln')));
  if (!sw) {
    console.log('⚠ Visor service worker is currently idle or not found.');
    console.log('All targets:');
    targets.forEach((t) => console.log(`  - [${t.type}] ${t.title || t.url}`));
  } else {
    console.log('✓ Found Visor Service Worker:', sw.url);
    const ws = new WebSocket(sw.webSocketDebuggerUrl);
    await new Promise((r) => ws.addEventListener('open', r, { once: true }));

    // Read session storage
    const storageRes = await sendCdp(ws, 'Runtime.evaluate', {
      expression: 'chrome.storage.session.get(null)',
      awaitPromise: true,
      returnByValue: true,
    });

    console.log('\n--- Live chrome.storage.session ---');
    console.dir(storageRes?.result?.value, { depth: null });
    ws.close();
  }

  // Print open web pages and their URLs
  const pages = targets.filter((t) => t.type === 'page' && !t.url.startsWith('devtools:'));
  console.log('\n--- Active Browser Tabs ---');
  pages.forEach((p, idx) => console.log(`  [${idx + 1}] ${p.title} (${p.url})`));
}

main().catch(console.error);
