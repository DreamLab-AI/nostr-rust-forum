import { chromium } from 'playwright';

const BASE = 'https://dreamlab-ai.com';
const RELAY = 'wss://dreamlab-nostr-relay.solitary-paper-764d.workers.dev';
const AUTH_API = 'https://dreamlab-auth-api.solitary-paper-764d.workers.dev';
const POD_API = 'https://dreamlab-pod-api.solitary-paper-764d.workers.dev';
const SEARCH_API = 'https://dreamlab-search-api.solitary-paper-764d.workers.dev';

const results = [];
function log(test, status, detail = '') {
  const icon = status === 'PASS' ? '✅' : status === 'WARN' ? '⚠️' : '❌';
  results.push({ test, status, detail });
  console.log(`${icon} ${test}${detail ? ': ' + detail : ''}`);
}

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: '/nix/store/68h63fg3qyv62lkvmqpkdk8g8qnldzhp-chromium-147.0.7727.137/bin/chromium',
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    userAgent: 'nostr-bbs-e2e-smoke/1.0',
  });
  const page = await context.newPage();

  // Collect console errors
  const consoleErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  // Collect failed network requests
  const networkErrors = [];
  page.on('requestfailed', req => {
    networkErrors.push(`${req.method()} ${req.url()} → ${req.failure()?.errorText}`);
  });

  try {
    // ─── TEST 1: Homepage loads ───
    console.log('\n═══ TEST 1: Homepage Load ═══');
    const resp = await page.goto(BASE, { waitUntil: 'networkidle', timeout: 30000 });
    if (resp.ok()) {
      log('Homepage load', 'PASS', `HTTP ${resp.status()}`);
    } else {
      log('Homepage load', 'FAIL', `HTTP ${resp.status()}`);
    }

    // Check page title
    const title = await page.title();
    log('Page title', title ? 'PASS' : 'WARN', title || 'empty');

    // ─── TEST 2: Key UI elements ───
    console.log('\n═══ TEST 2: UI Elements ═══');
    await page.screenshot({ path: '/tmp/e2e-01-homepage.png', fullPage: false });

    // Check for main content areas
    const bodyText = await page.textContent('body');
    const hasLoginArea = bodyText.includes('Log') || bodyText.includes('Sign') || bodyText.includes('Connect');
    log('Login/auth UI present', hasLoginArea ? 'PASS' : 'WARN', hasLoginArea ? 'found auth controls' : 'no auth controls visible');

    // ─── TEST 3: Navigation ───
    console.log('\n═══ TEST 3: Navigation ═══');
    const links = await page.$$eval('a[href]', els => els.map(e => ({ href: e.getAttribute('href'), text: e.textContent.trim().slice(0, 40) })));
    const internalLinks = links.filter(l => l.href && (l.href.startsWith('/') || l.href.startsWith(BASE)));
    log('Internal links found', internalLinks.length > 0 ? 'PASS' : 'WARN', `${internalLinks.length} links`);
    internalLinks.slice(0, 5).forEach(l => console.log(`  → ${l.href} (${l.text})`));

    // ─── TEST 4: WebSocket relay connection ───
    console.log('\n═══ TEST 4: WebSocket Relay ═══');
    const wsResult = await page.evaluate(async (relayUrl) => {
      return new Promise((resolve) => {
        const ws = new WebSocket(relayUrl);
        const timeout = setTimeout(() => { ws.close(); resolve({ connected: false, error: 'timeout' }); }, 5000);
        ws.onopen = () => {
          ws.send(JSON.stringify(['REQ', 'smoke', { kinds: [0, 1, 40], limit: 3 }]));
        };
        const events = [];
        ws.onmessage = (e) => {
          const msg = JSON.parse(e.data);
          if (msg[0] === 'EVENT') events.push(msg[2].kind);
          if (msg[0] === 'EOSE') {
            clearTimeout(timeout);
            ws.close();
            resolve({ connected: true, events: events.length, kinds: [...new Set(events)] });
          }
        };
        ws.onerror = (e) => { clearTimeout(timeout); resolve({ connected: false, error: 'ws error' }); };
      });
    }, RELAY);

    if (wsResult.connected) {
      log('Relay WebSocket', 'PASS', `${wsResult.events} events, kinds: [${wsResult.kinds}]`);
    } else {
      log('Relay WebSocket', 'FAIL', wsResult.error);
    }

    // ─── TEST 5: Auth API CORS from browser context ───
    console.log('\n═══ TEST 5: Auth API ═══');
    const authResult = await page.evaluate(async (authUrl) => {
      try {
        const r = await fetch(authUrl + '/health');
        const body = await r.json();
        return { ok: r.ok, status: r.status, body };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }, AUTH_API);

    if (authResult.ok) {
      log('Auth API health (from browser)', 'PASS', JSON.stringify(authResult.body));
    } else {
      log('Auth API health (from browser)', authResult.error?.includes('CORS') ? 'WARN' : 'FAIL', authResult.error || `HTTP ${authResult.status}`);
    }

    // Auth challenge endpoint
    const challengeResult = await page.evaluate(async (authUrl) => {
      try {
        const r = await fetch(authUrl + '/auth/challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pubkey: '0000000000000000000000000000000000000000000000000000000000000000' }),
        });
        return { status: r.status, ok: r.ok };
      } catch (e) {
        return { error: e.message };
      }
    }, AUTH_API);

    if (challengeResult.status) {
      log('Auth challenge endpoint', challengeResult.status < 500 ? 'PASS' : 'FAIL', `HTTP ${challengeResult.status}`);
    } else {
      log('Auth challenge endpoint', 'WARN', challengeResult.error);
    }

    // ─── TEST 6: Pod API health from browser ───
    console.log('\n═══ TEST 6: Pod API ═══');
    const podResult = await page.evaluate(async (podUrl) => {
      try {
        const r = await fetch(podUrl + '/health');
        const body = await r.json();
        return { ok: r.ok, status: r.status, features: body.features?.length };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }, POD_API);

    if (podResult.ok) {
      log('Pod API health (from browser)', 'PASS', `${podResult.features} features`);
    } else {
      log('Pod API health (from browser)', 'WARN', podResult.error || `HTTP ${podResult.status}`);
    }

    // ─── TEST 7: Search API from browser ───
    console.log('\n═══ TEST 7: Search API ═══');
    const searchResult = await page.evaluate(async (searchUrl) => {
      try {
        const r = await fetch(searchUrl + '/health');
        const body = await r.json();
        return { ok: r.ok, status: r.status, vectors: body.totalVectors };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }, SEARCH_API);

    if (searchResult.ok) {
      log('Search API health (from browser)', 'PASS', `${searchResult.vectors} vectors indexed`);
    } else {
      log('Search API health (from browser)', 'WARN', searchResult.error || `HTTP ${searchResult.status}`);
    }

    // Search query test
    const searchQueryResult = await page.evaluate(async (searchUrl) => {
      try {
        const r = await fetch(searchUrl + '/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'test', limit: 3 }),
        });
        const body = await r.json();
        return { ok: r.ok, status: r.status, results: body.results?.length ?? body.length ?? 0 };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }, SEARCH_API);

    if (searchQueryResult.ok || searchQueryResult.status < 500) {
      log('Search query', 'PASS', `${searchQueryResult.results} results, HTTP ${searchQueryResult.status}`);
    } else {
      log('Search query', 'WARN', searchQueryResult.error || `HTTP ${searchQueryResult.status}`);
    }

    // ─── TEST 8: Navigate key routes ───
    console.log('\n═══ TEST 8: Route Navigation ═══');
    const routes = ['/channels', '/calendar', '/settings', '/admin'];
    for (const route of routes) {
      try {
        const navResp = await page.goto(BASE + route, { waitUntil: 'domcontentloaded', timeout: 15000 });
        const status = navResp?.status() || 0;
        const pageBody = await page.textContent('body').catch(() => '');
        const has404 = pageBody.includes('404') || pageBody.includes('not found');
        if (status === 200 && !has404) {
          log(`Route ${route}`, 'PASS', `HTTP ${status}`);
        } else if (status === 200 && has404) {
          log(`Route ${route}`, 'WARN', 'client-side 404');
        } else {
          log(`Route ${route}`, 'FAIL', `HTTP ${status}`);
        }
      } catch (e) {
        log(`Route ${route}`, 'WARN', e.message.slice(0, 60));
      }
    }

    // Take screenshot of admin page
    await page.screenshot({ path: '/tmp/e2e-02-admin.png', fullPage: false });

    // ─── TEST 9: WASM Module Loading ───
    console.log('\n═══ TEST 9: WASM Module ═══');
    await page.goto(BASE, { waitUntil: 'networkidle', timeout: 30000 });

    const wasmLoaded = await page.evaluate(() => {
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      const wasmScript = scripts.find(s => s.src.includes('wasm') || s.src.includes('.js'));
      return {
        hasWasmInit: typeof window.__wbg_init !== 'undefined' || document.querySelector('link[href*="wasm"]') !== null,
        scriptCount: scripts.length,
        wasmFiles: scripts.filter(s => s.src.includes('wasm')).map(s => s.src.split('/').pop()),
      };
    });
    log('WASM assets', wasmLoaded.scriptCount > 0 ? 'PASS' : 'WARN', `${wasmLoaded.scriptCount} scripts, ${wasmLoaded.wasmFiles.length} wasm refs`);

    // ─── TEST 10: Console errors audit ───
    console.log('\n═══ TEST 10: Console Errors ═══');
    const criticalErrors = consoleErrors.filter(e =>
      !e.includes('favicon') && !e.includes('Blocked a frame') && !e.includes('third-party')
    );
    if (criticalErrors.length === 0) {
      log('Console errors', 'PASS', 'no critical errors');
    } else {
      log('Console errors', 'WARN', `${criticalErrors.length} errors`);
      criticalErrors.slice(0, 5).forEach(e => console.log(`  ⚠ ${e.slice(0, 100)}`));
    }

    // Network errors
    if (networkErrors.length === 0) {
      log('Network errors', 'PASS', 'no failed requests');
    } else {
      log('Network errors', 'WARN', `${networkErrors.length} failed`);
      networkErrors.slice(0, 5).forEach(e => console.log(`  ⚠ ${e.slice(0, 100)}`));
    }

  } catch (e) {
    log('Test execution', 'FAIL', e.message);
  } finally {
    await browser.close();
  }

  // ─── SUMMARY ───
  console.log('\n═══════════════════════════════════════════');
  console.log('           E2E SMOKE TEST SUMMARY          ');
  console.log('═══════════════════════════════════════════');
  const pass = results.filter(r => r.status === 'PASS').length;
  const warn = results.filter(r => r.status === 'WARN').length;
  const fail = results.filter(r => r.status === 'FAIL').length;
  console.log(`  PASS: ${pass}  |  WARN: ${warn}  |  FAIL: ${fail}  |  Total: ${results.length}`);
  console.log('═══════════════════════════════════════════');

  if (fail > 0) process.exit(1);
})();
