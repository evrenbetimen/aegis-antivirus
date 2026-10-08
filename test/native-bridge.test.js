const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { NativeBridge, parseEvent, writePolicy } = require('../src/native-bridge');

const EXEC = {
  v: 1,
  ts: '2026-10-02T04:21:07Z',
  source: 'shield',
  event: 'exec',
  verdict: 'deny',
  reason: 'signature-hit',
  threat: 'EICAR-Test-File',
  pid: 4821,
  path: '/Users/ali/Downloads/evil.bin',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
};

test('parseEvent accepts documented exec and flow-block events', () => {
  const e = parseEvent(JSON.stringify(EXEC));
  assert.strictEqual(e.verdict, 'deny');
  assert.strictEqual(e.threat, 'EICAR-Test-File');
  const f = parseEvent(
    JSON.stringify({ v: 1, source: 'firewall', event: 'flow-block', host: 'doubleclick.net', port: 443, proto: 'tcp', rule: 'r1' })
  );
  assert.strictEqual(f.host, 'doubleclick.net');
  assert.strictEqual(f.port, 443);
});

test('parseEvent rejects malformed or unknown events', () => {
  assert.strictEqual(parseEvent('not json'), null);
  assert.strictEqual(parseEvent(JSON.stringify(Object.assign({}, EXEC, { v: 2 }))), null);
  assert.strictEqual(parseEvent(JSON.stringify(Object.assign({}, EXEC, { verdict: 'maybe' }))), null);
  assert.strictEqual(parseEvent(JSON.stringify({ v: 1, source: 'shield', event: 'rm-rf' })), null);
  assert.strictEqual(parseEvent(JSON.stringify(Object.assign({}, EXEC, { sha256: 'xyz' }))).sha256, '');
});

test('writePolicy mirrors realtimeEnabled into shield-policy.json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-policy-'));
  writePolicy(dir, { realtimeEnabled: true });
  const p = JSON.parse(fs.readFileSync(path.join(dir, 'shield-policy.json'), 'utf8'));
  assert.strictEqual(p.enabled, true);
  assert.ok(Array.isArray(p.denyPaths));
  writePolicy(dir, { realtimeEnabled: false });
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(dir, 'shield-policy.json'), 'utf8')).enabled, false);
});

test('bridge receives newline-delimited events over the socket', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-sock-'));
  const socketPath = path.join(dir, 'aegis.sock');
  const got = [];
  const bridge = new NativeBridge({ socketPath, onEvent: (e) => got.push(e), log: { warn() {} } });
  await bridge.start();
  t.after(() => bridge.stop());
  assert.strictEqual(fs.statSync(socketPath).mode & 0o777, 0o600);

  await new Promise((resolve) => {
    const c = net.createConnection(socketPath, () => {
      // İki olay, biri iki parçaya bölünmüş + bir bozuk satır
      const line = JSON.stringify(EXEC);
      c.write(line.slice(0, 10));
      setTimeout(() => {
        c.write(line.slice(10) + '\n{bad}\n' + JSON.stringify({ v: 1, source: 'firewall', event: 'flow-block', host: 'x.com' }) + '\n');
        setTimeout(() => {
          c.end();
          resolve();
        }, 50);
      }, 20);
    });
  });
  assert.strictEqual(got.length, 2);
  assert.strictEqual(got[0].path, '/Users/ali/Downloads/evil.bin');
  assert.strictEqual(got[1].host, 'x.com');
  const s = bridge.status();
  assert.strictEqual(s.received, 2);
  assert.strictEqual(s.dropped, 1);
  assert.strictEqual(s.connected, true);
});

test('bridge replaces a stale socket file but never a regular file', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-sock-'));
  const socketPath = path.join(dir, 'aegis.sock');
  const first = new NativeBridge({ socketPath, onEvent() {} });
  await first.start();
  first.server.close(); // dosyayı bırakarak kapat (çökme benzetimi)
  first.server = null;
  const second = new NativeBridge({ socketPath, onEvent() {} });
  await second.start();
  second.stop();

  fs.writeFileSync(socketPath, 'keep');
  const third = new NativeBridge({ socketPath, onEvent() {} });
  await assert.rejects(third.start());
  assert.strictEqual(fs.readFileSync(socketPath, 'utf8'), 'keep');
});
