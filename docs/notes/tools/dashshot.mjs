// Usage: DASH_PW=... node dashshot.mjs <base> <out.png> <path> [waitMs]
// Logs into the Wazuh dashboard in headless Chrome via CDP and screenshots <path>.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, out, path, waitMs = '15000'] = process.argv.slice(2);
const port = 9333;
const chrome = spawn('google-chrome', ['--headless=new', '--disable-gpu', '--ignore-certificate-errors',
  `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'cdp-'))}`,
  '--window-size=1600,1000', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

try {
  let targets;
  for (let i = 0; i < 50 && !targets; i++) {
    await sleep(200);
    targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json()).catch(() => null);
  }
  const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  };
  const send = (method, params = {}) => new Promise((r) => {
    pending.set(++id, r); ws.send(JSON.stringify({ id, method, params }));
  });

  await send('Page.enable');
  await send('Page.navigate', { url: `${base}/app/login` });
  await sleep(4000);
  const login = await send('Runtime.evaluate', {
    awaitPromise: true,
    expression: `fetch('/auth/login', {method: 'POST', headers: {'osd-xsrf': 'true', 'content-type': 'application/json'},
      body: JSON.stringify({username: 'admin', password: ${JSON.stringify(process.env.DASH_PW)}})}).then(r => r.status)`,
  });
  console.log('login status', login.result.result.value);
  await send('Page.navigate', { url: base + path });
  await sleep(Number(waitMs));
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
  console.log('wrote', out);
} finally {
  chrome.kill();
}
