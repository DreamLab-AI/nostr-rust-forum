import { chromium } from 'playwright';

const BASE = 'https://dreamlab-ai.com/community';
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

  const consoleErrors = [];
  const consoleAll = [];
  page.on('console', msg => {
    consoleAll.push(`[${msg.type()}] ${msg.text()}`);
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  const networkErrors = [];
  page.on('requestfailed', req => {
    networkErrors.push(`${req.method()} ${req.url()} → ${req.failure()?.errorText}`);
  });

  // Track API calls
  const apiCalls = [];
  page.on('response', resp => {
    const url = resp.url();
    if (url.includes('workers.dev') || url.includes('supabase')) {
      apiCalls.push({ url: url.split('?')[0], status: resp.status() });
    }
  });

  try {
    // ─── TEST 1: Forum Homepage ───
    console.log('\n═══ TEST 1: Forum Homepage ═══');
    const resp = await page.goto(BASE, { waitUntil: 'networkidle', timeout: 30000 });
    if (resp.ok()) {
      log('Forum page load', 'PASS', `HTTP ${resp.status()}`);
    } else {
      log('Forum page load', 'FAIL', `HTTP ${resp.status()}`);
    }

    const title = await page.title();
    log('Page title', title.includes('Nostr') || title.includes('Forum') || title.includes('BBS') ? 'PASS' : 'WARN', title);

    await page.screenshot({ path: '/tmp/e2e-forum-01-home.png', fullPage: false });

    // ─── TEST 2: WASM Module Loading ───
    console.log('\n═══ TEST 2: WASM Module ═══');
    const wasmInfo = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('link[href*="wasm"], link[rel="preload"][as="fetch"]'));
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      return {
        wasmLinks: links.map(l => l.getAttribute('href')?.split('/').pop()),
        scripts: scripts.map(s => s.getAttribute('src')?.split('/').pop()),
        bodyLen: document.body.innerHTML.length,
      };
    });
    log('WASM assets', wasmInfo.wasmLinks.length > 0 || wasmInfo.scripts.length > 0 ? 'PASS' : 'WARN',
      `${wasmInfo.wasmLinks.length} wasm links, ${wasmInfo.scripts.length} scripts, body ${wasmInfo.bodyLen} chars`);

    // Wait for WASM hydration
    await page.waitForTimeout(3000);
    await page.screenshot({ path: '/tmp/e2e-forum-02-hydrated.png', fullPage: false });

    // ─── TEST 3: Relay Connection from Forum ───
    console.log('\n═══ TEST 3: Relay from Forum Context ═══');
    const wsResult = await page.evaluate(async (relayUrl) => {
      return new Promise((resolve) => {
        try {
          const ws = new WebSocket(relayUrl);
          const timeout = setTimeout(() => { ws.close(); resolve({ connected: false, error: 'timeout' }); }, 8000);
          ws.onopen = () => {
            ws.send(JSON.stringify(['REQ', 'smoke-channels', { kinds: [40], limit: 10 }]));
            ws.send(JSON.stringify(['REQ', 'smoke-profiles', { kinds: [0], limit: 10 }]));
            ws.send(JSON.stringify(['REQ', 'smoke-notes', { kinds: [1, 42], limit: 10 }]));
          };
          const events = { channels: [], profiles: [], notes: [] };
          let eoseCount = 0;
          ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg[0] === 'EVENT') {
              const ev = msg[2];
              if (ev.kind === 40) events.channels.push(ev);
              else if (ev.kind === 0) events.profiles.push(ev);
              else events.notes.push(ev);
            }
            if (msg[0] === 'EOSE') {
              eoseCount++;
              if (eoseCount >= 3) {
                clearTimeout(timeout);
                ws.close();
                resolve({
                  connected: true,
                  channels: events.channels.length,
                  profiles: events.profiles.length,
                  notes: events.notes.length,
                  channelNames: events.channels.map(c => {
                    try { return JSON.parse(c.content).name; } catch { return '?'; }
                  }),
                  profileNames: events.profiles.map(p => {
                    try { return JSON.parse(p.content).name || JSON.parse(p.content).display_name; } catch { return '?'; }
                  }),
                });
              }
            }
          };
          ws.onerror = () => { clearTimeout(timeout); resolve({ connected: false, error: 'ws error' }); };
        } catch (e) {
          resolve({ connected: false, error: e.message });
        }
      });
    }, RELAY);

    if (wsResult.connected) {
      log('Relay WebSocket', 'PASS', `${wsResult.channels} channels, ${wsResult.profiles} profiles, ${wsResult.notes} notes`);
      console.log(`  Channels: ${wsResult.channelNames.join(', ')}`);
      console.log(`  Profiles: ${wsResult.profileNames.join(', ')}`);
    } else {
      log('Relay WebSocket', 'FAIL', wsResult.error);
    }

    // ─── TEST 4: Auth API from Forum ───
    console.log('\n═══ TEST 4: Auth API from Forum ═══');
    const authHealth = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/health');
        return { ok: r.ok, status: r.status, body: await r.json() };
      } catch (e) { return { error: e.message }; }
    }, AUTH_API);

    if (authHealth.ok) {
      log('Auth API health', 'PASS', `service=${authHealth.body.service}, status=${authHealth.body.status}`);
    } else {
      log('Auth API health', 'FAIL', authHealth.error || `HTTP ${authHealth.status}`);
    }

    // Auth challenge test
    const challenge = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/auth/challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pubkey: '0000000000000000000000000000000000000000000000000000000000000001' }),
        });
        return { status: r.status, body: await r.text() };
      } catch (e) { return { error: e.message }; }
    }, AUTH_API);

    log('Auth challenge', challenge.status ? 'PASS' : 'FAIL',
      `HTTP ${challenge.status || 'err'}${challenge.body ? ' — ' + challenge.body.slice(0, 60) : ''}`);

    // ─── TEST 5: Pod API from Forum ───
    console.log('\n═══ TEST 5: Pod API from Forum ═══');
    const podHealth = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/health');
        return { ok: r.ok, body: await r.json() };
      } catch (e) { return { error: e.message }; }
    }, POD_API);

    if (podHealth.ok) {
      log('Pod API health', 'PASS', `${podHealth.body.features.length} features, v${podHealth.body.version}`);
    } else {
      log('Pod API health', 'FAIL', podHealth.error);
    }

    // Payment info
    const payInfo = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/pay/.info');
        return { ok: r.ok, status: r.status, body: await r.json() };
      } catch (e) { return { error: e.message }; }
    }, POD_API);

    if (payInfo.ok) {
      log('Payment gateway info', 'PASS', `${payInfo.body.name}, unit=${payInfo.body.unit}, cost=${payInfo.body.cost_sats} sats`);
    } else {
      log('Payment gateway info', payInfo.status < 500 ? 'WARN' : 'FAIL',
        payInfo.error || `HTTP ${payInfo.status}`);
    }

    // ─── TEST 6: Search API from Forum ───
    console.log('\n═══ TEST 6: Search API from Forum ═══');
    const searchHealth = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/health');
        return { ok: r.ok, body: await r.json() };
      } catch (e) { return { error: e.message }; }
    }, SEARCH_API);

    if (searchHealth.ok) {
      log('Search API health', 'PASS', `${searchHealth.body.totalVectors} vectors, model=${searchHealth.body.model}`);
    } else {
      log('Search API health', 'FAIL', searchHealth.error);
    }

    const searchQuery = await page.evaluate(async (url) => {
      try {
        const r = await fetch(url + '/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'DreamLab AI', limit: 5 }),
        });
        return { ok: r.ok, status: r.status, body: await r.json() };
      } catch (e) { return { error: e.message }; }
    }, SEARCH_API);

    if (searchQuery.ok) {
      const count = searchQuery.body.results?.length ?? searchQuery.body.length ?? 0;
      log('Search query', 'PASS', `${count} results for "DreamLab AI"`);
    } else {
      log('Search query', searchQuery.status < 500 ? 'WARN' : 'FAIL',
        searchQuery.error || `HTTP ${searchQuery.status}`);
    }

    // ─── TEST 7: Forum Navigation ───
    console.log('\n═══ TEST 7: Forum Navigation ═══');
    const forumRoutes = ['/community/channels', '/community/calendar', '/community/settings'];
    for (const route of forumRoutes) {
      try {
        const navResp = await page.goto('https://dreamlab-ai.com' + route, { waitUntil: 'domcontentloaded', timeout: 15000 });
        const status = navResp?.status() || 0;
        await page.waitForTimeout(1000);
        const bodyText = await page.textContent('body').catch(() => '');
        const isBlank = bodyText.trim().length < 50;
        log(`Route ${route}`, status === 200 && !isBlank ? 'PASS' : status === 200 ? 'WARN' : 'FAIL',
          `HTTP ${status}, body ${bodyText.trim().length} chars`);
      } catch (e) {
        log(`Route ${route}`, 'WARN', e.message.slice(0, 60));
      }
    }

    await page.screenshot({ path: '/tmp/e2e-forum-03-channels.png', fullPage: false });

    // ─── TEST 8: UI Element Check ───
    console.log('\n═══ TEST 8: Forum UI Elements ═══');
    await page.goto(BASE, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(2000);

    const uiElements = await page.evaluate(() => {
      const body = document.body.textContent || '';
      return {
        hasLoginButton: !!document.querySelector('button[class*="login"], button[class*="connect"], [data-login]') || body.includes('Log in') || body.includes('Connect') || body.includes('Sign'),
        hasChannelList: body.includes('channel') || body.includes('Channel') || body.includes('topic'),
        hasNavigation: !!document.querySelector('nav, [role="navigation"], header a'),
        hasForum: body.includes('forum') || body.includes('Forum') || body.includes('BBS') || body.includes('community'),
        bodyPreview: body.replace(/\s+/g, ' ').trim().slice(0, 200),
      };
    });

    log('Login UI', uiElements.hasLoginButton ? 'PASS' : 'WARN', uiElements.hasLoginButton ? 'found' : 'not visible');
    log('Channel/topic UI', uiElements.hasChannelList ? 'PASS' : 'WARN', uiElements.hasChannelList ? 'found' : 'not visible');
    log('Navigation', uiElements.hasNavigation ? 'PASS' : 'WARN', uiElements.hasNavigation ? 'found' : 'not visible');
    console.log(`  Body preview: ${uiElements.bodyPreview}`);

    await page.screenshot({ path: '/tmp/e2e-forum-04-final.png', fullPage: true });

    // ─── TEST 9: Console & Network Audit ───
    console.log('\n═══ TEST 9: Console & Network Audit ═══');
    const criticalErrors = consoleErrors.filter(e =>
      !e.includes('favicon') && !e.includes('third-party') && !e.includes('DevTools')
    );
    if (criticalErrors.length === 0) {
      log('Console errors', 'PASS', 'none');
    } else {
      log('Console errors', 'WARN', `${criticalErrors.length} errors`);
      criticalErrors.slice(0, 5).forEach(e => console.log(`  ⚠ ${e.slice(0, 120)}`));
    }

    if (networkErrors.length === 0) {
      log('Network errors', 'PASS', 'none');
    } else {
      log('Network errors', 'WARN', `${networkErrors.length} failed`);
      networkErrors.slice(0, 5).forEach(e => console.log(`  ⚠ ${e.slice(0, 120)}`));
    }

    // API calls summary
    console.log(`\n  API calls observed: ${apiCalls.length}`);
    apiCalls.forEach(c => console.log(`    ${c.status} ${c.url.split('workers.dev')[1] || c.url}`));

  } catch (e) {
    log('Test execution', 'FAIL', e.message);
  } finally {
    await browser.close();
  }

  // ─── SUMMARY ───
  console.log('\n═══════════════════════════════════════════════════');
  console.log('         FORUM E2E SMOKE TEST SUMMARY              ');
  console.log('═══════════════════════════════════════════════════');
  const pass = results.filter(r => r.status === 'PASS').length;
  const warn = results.filter(r => r.status === 'WARN').length;
  const fail = results.filter(r => r.status === 'FAIL').length;
  console.log(`  PASS: ${pass}  |  WARN: ${warn}  |  FAIL: ${fail}  |  Total: ${results.length}`);

  if (fail > 0) {
    console.log('\n  FAILURES:');
    results.filter(r => r.status === 'FAIL').forEach(r => console.log(`    ❌ ${r.test}: ${r.detail}`));
  }
  if (warn > 0) {
    console.log('\n  WARNINGS:');
    results.filter(r => r.status === 'WARN').forEach(r => console.log(`    ⚠️  ${r.test}: ${r.detail}`));
  }
  console.log('═══════════════════════════════════════════════════');

  process.exit(fail > 0 ? 1 : 0);
})();
