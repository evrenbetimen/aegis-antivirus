// Güvenlik merkezi özellikleri: sistem denetimi, başlangıç öğeleri, parola sızıntı denetimi
// node --test test/features.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sysaudit = require('../src/sysaudit');
const startup = require('../src/startup-items');
const breach = require('../src/breach');

test('sistem denetimi: komut çıktıları doğru yorumlanır', () => {
  assert.equal(sysaudit.parseFileVault('FileVault is On.'), 'pass');
  assert.equal(sysaudit.parseFileVault('FileVault is Off.'), 'fail');
  assert.equal(sysaudit.parseFileVault('Encryption in progress: Percent completed = 40'), 'warn');
  assert.equal(sysaudit.parseGatekeeper('assessments enabled'), 'pass');
  assert.equal(sysaudit.parseGatekeeper('assessments disabled'), 'fail');
  assert.equal(sysaudit.parseSip('System Integrity Protection status: enabled.'), 'pass');
  assert.equal(sysaudit.parseSip('System Integrity Protection status: disabled.'), 'fail');
  assert.equal(sysaudit.parseAppFirewall('Firewall is enabled. (State = 1)'), 'pass');
  assert.equal(sysaudit.parseAppFirewall('Firewall is disabled. (State = 0)'), 'fail');
  assert.equal(sysaudit.parseBoolDefault('1\n'), true);
  assert.equal(sysaudit.parseBoolDefault('0'), false);
  assert.equal(sysaudit.parseBoolDefault('The domain/default pair does not exist'), null);
  assert.equal(sysaudit.parseScreenLock('screenLock delay is immediate'), 'pass');
  assert.equal(sysaudit.parseScreenLock('screenLock delay is 3600 seconds'), 'warn');
  assert.equal(sysaudit.parseScreenLock('screenLock is off'), 'fail');
  assert.equal(sysaudit.parseFileVault(''), 'unknown');
});

test('sistem denetimi: Wi-Fi güvenlik türü', () => {
  const wifi = (mode) =>
    JSON.stringify({
      SPAirPortDataType: [
        {
          spairport_airport_interfaces: [
            { _name: 'en0', spairport_current_network_information: { _name: 'Ofis', spairport_security_mode: mode } }
          ]
        }
      ]
    });
  assert.deepEqual(sysaudit.parseWifi(wifi('spairport_security_mode_wpa3_personal')), {
    status: 'pass',
    security: 'wpa3_personal',
    ssid: 'Ofis'
  });
  assert.equal(sysaudit.parseWifi(wifi('spairport_security_mode_wpa2_personal')).status, 'pass');
  assert.equal(sysaudit.parseWifi(wifi('spairport_security_mode_wep')).status, 'warn');
  assert.equal(sysaudit.parseWifi(wifi('spairport_security_mode_none')).status, 'fail');
  assert.equal(sysaudit.parseWifi(JSON.stringify({ SPAirPortDataType: [{ spairport_airport_interfaces: [{}] }] })).status, 'na');
  assert.equal(sysaudit.parseWifi('bozuk').status, 'unknown');
});

test('sistem denetimi: macOS dışında desteklenmiyor olarak döner', async () => {
  const r = await sysaudit.audit('linux');
  assert.equal(r.supported, false);
  assert.deepEqual(r.items, []);
});

test('başlangıç öğeleri: plist okunur, şüpheli konumlar ve tehditler işaretlenir', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-startup-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const good = path.join(bin, 'helper');
  const evil = path.join(bin, 'evil');
  fs.writeFileSync(good, 'ok');
  fs.writeFileSync(evil, 'bad');
  const plist = (label, args, extra = '') =>
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>${args.map((a) => `<string>${a}</string>`).join('')}</array>
  <key>RunAtLoad</key><true/>${extra}
</dict></plist>`;
  const agents = path.join(dir, 'LaunchAgents');
  fs.mkdirSync(agents);
  fs.writeFileSync(path.join(agents, 'com.good.plist'), plist('com.good.helper', [good, '--bg'], '<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>'));
  fs.writeFileSync(path.join(agents, 'com.evil.plist'), plist('com.evil.agent', [evil]));
  fs.writeFileSync(path.join(agents, 'com.gone.plist'), plist('com.gone', ['/nonexistent/app']));
  fs.writeFileSync(path.join(agents, 'com.tmp.plist'), plist('com.tmp', ['/tmp/x']));
  fs.writeFileSync(path.join(agents, 'broken.plist'), '<plist><dict><key>Label</key>');
  fs.writeFileSync(path.join(agents, 'notes.txt'), 'yok sayılır');

  const res = startup.list({
    scopes: [{ scope: 'user', dir: agents }, { scope: 'daemon', dir: path.join(dir, 'yok') }],
    suspiciousDirs: ['/var/tmp/'], // test dizini os.tmpdir() altında
    checkFile: (p) => (p === evil ? { name: 'Test.Persistence' } : null)
  });
  const by = Object.fromEntries(res.items.map((i) => [i.label, i]));
  assert.equal(res.items.length, 5);
  assert.equal(by['com.good.helper'].risk, null);
  assert.equal(by['com.good.helper'].runAtLoad, true);
  assert.equal(by['com.good.helper'].keepAlive, true);
  assert.deepEqual(by['com.good.helper'].args, ['--bg']);
  assert.equal(by['com.evil.agent'].risk, 'threat');
  assert.equal(by['com.evil.agent'].threat, 'Test.Persistence');
  assert.equal(by['com.gone'].risk, 'missingProgram');
  assert.equal(by.broken.risk, 'unreadable');
  assert.equal(by['com.tmp'].risk, 'missingProgram');
  assert.deepEqual(res.errors, []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('başlangıç öğeleri: risk değerlendirmesi', () => {
  assert.equal(startup.assess({ program: '/tmp/a' }, true), 'tempLocation');
  assert.equal(startup.assess({ program: '/Users/Shared/a' }, true), 'tempLocation');
  assert.equal(startup.assess({ program: '/Users/x/.hidden/a' }, true), 'hiddenPath');
  assert.equal(startup.assess({ program: '/bin/bash' }, true), 'scriptInterpreter');
  assert.equal(startup.assess({ program: '/Applications/A.app/Contents/MacOS/A' }, true), null);
  assert.equal(startup.assess({ program: null }, false), 'noProgram');
});

test('parola sızıntısı: yalnızca 5 karakterlik önek gönderilir, eşleşme yerelde sayılır', async () => {
  const hash = breach.sha1Upper('password');
  assert.equal(hash, '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  let requested = null;
  const res = await breach.checkPassword('password', {
    get: async (url) => {
      requested = url;
      return `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0`;
    }
  });
  assert.equal(requested, breach.API + '5BAA6');
  assert.ok(!requested.slice(breach.API.length).includes('password') && !requested.includes(hash.slice(5)));
  assert.deepEqual(res, { ok: true, count: 9545824 });

  const clean = await breach.checkPassword('çok-uzun-ve-eşsiz-bir-parola-42', { get: async () => 'AAAA:3' });
  assert.deepEqual(clean, { ok: true, count: 0 });
  assert.deepEqual(await breach.checkPassword('x', { get: async () => { throw new Error('offline'); } }), {
    ok: false,
    error: 'offline'
  });
  assert.equal((await breach.checkPassword('')).ok, false);
});
