'use strict';

/**
 * Sistem güvenlik denetimi (McAfee "Vulnerability Scanner", Norton "Security
 * Scan" benzeri): macOS'un yerleşik koruma katmanlarının açık olup olmadığını
 * denetler. Her denetim salt okunurdur; düzeltme kullanıcıya bırakılır ve
 * ilgili Sistem Ayarları bölmesi açılır.
 *
 * Ayrıştırıcılar saf fonksiyonlardır (test/sysaudit.test.js her platformda
 * çalışır); komutlar yalnızca macOS'ta yürütülür.
 */

const { execFile } = require('child_process');

const SETTINGS = {
  filevault: 'x-apple.systempreferences:com.apple.preference.security?FDE',
  firewall: 'x-apple.systempreferences:com.apple.preference.security?Firewall',
  gatekeeper: 'x-apple.systempreferences:com.apple.preference.security?General',
  updates: 'x-apple.systempreferences:com.apple.preferences.softwareupdate',
  wifi: 'x-apple.systempreferences:com.apple.preference.network',
  screenlock: 'x-apple.systempreferences:com.apple.preference.security?General'
};

/* ---------------- ayrıştırıcılar ---------------- */

function parseFileVault(out) {
  if (/FileVault is On/i.test(out)) return 'pass';
  if (/FileVault is Off/i.test(out)) return 'fail';
  if (/Encryption in progress|Decryption in progress/i.test(out)) return 'warn';
  return 'unknown';
}

function parseGatekeeper(out) {
  if (/assessments enabled/i.test(out)) return 'pass';
  if (/assessments disabled/i.test(out)) return 'fail';
  return 'unknown';
}

function parseSip(out) {
  if (/status:\s*enabled/i.test(out)) return 'pass';
  if (/status:\s*disabled/i.test(out)) return 'fail';
  if (/Custom Configuration|unknown \(Custom/i.test(out)) return 'warn';
  return 'unknown';
}

// socketfilterfw --getglobalstate: "Firewall is enabled. (State = 1)"
function parseAppFirewall(out) {
  if (/State = [12]|Firewall is enabled/i.test(out)) return 'pass';
  if (/State = 0|Firewall is disabled/i.test(out)) return 'fail';
  return 'unknown';
}

// defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled / CriticalUpdateInstall
function parseBoolDefault(out) {
  const v = String(out || '').trim();
  if (v === '1' || /^true$/i.test(v)) return true;
  if (v === '0' || /^false$/i.test(v)) return false;
  return null;
}

/**
 * system_profiler SPAirPortDataType -json → bağlı ağın güvenlik türü.
 * @returns {{status:'pass'|'warn'|'fail'|'unknown', security:string|null, ssid:string|null}}
 */
function parseWifi(jsonText) {
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch {
    return { status: 'unknown', security: null, ssid: null };
  }
  const ifaces = [];
  for (const entry of (data && data.SPAirPortDataType) || []) {
    for (const iface of entry.spairport_airport_interfaces || []) ifaces.push(iface);
  }
  const current = ifaces.map((i) => i.spairport_current_network_information).find(Boolean);
  if (!current) return { status: 'na', security: null, ssid: null };
  const security = String(current.spairport_security_mode || '');
  const ssid = current._name || null;
  const s = security.toLowerCase();
  let status = 'unknown';
  if (/none|open/.test(s)) status = 'fail';
  else if (/wep/.test(s) || (/wpa(?!2|3)/.test(s) && !/wpa2|wpa3/.test(s))) status = 'warn';
  else if (/wpa2|wpa3/.test(s)) status = 'pass';
  return { status, security: security.replace(/^spairport_security_mode_/, '') || null, ssid };
}

// sysadminctl -screenLock status → "screenLock delay is immediate" / "... is 300 seconds" / "off"
function parseScreenLock(out) {
  const text = String(out || '');
  if (/screenLock is off/i.test(text)) return 'fail';
  if (/immediate/i.test(text)) return 'pass';
  const m = /screenLock delay is (\d+) seconds/i.exec(text);
  if (m) return Number(m[1]) <= 300 ? 'pass' : 'warn';
  return 'unknown';
}

/* ---------------- yürütme ---------------- */

function run(cmd, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: String(stdout || ''), out: `${stdout || ''}\n${stderr || ''}` });
    });
  });
}

function item(id, status, extra) {
  return Object.assign({ id, status, settingsUrl: SETTINGS[id] || null }, extra || {});
}

/**
 * Tüm denetimleri çalıştırır.
 * @returns {Promise<{supported:boolean, at:number, items:Array}>}
 */
async function audit(platform = process.platform) {
  if (platform !== 'darwin') return { supported: false, at: Date.now(), items: [] };

  const [fv, gk, sip, fw, auto, critical, wifi, lock] = await Promise.all([
    run('/usr/bin/fdesetup', ['status']),
    run('/usr/sbin/spctl', ['--status']),
    run('/usr/bin/csrutil', ['status']),
    run('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticCheckEnabled']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'CriticalUpdateInstall']),
    run('/usr/sbin/system_profiler', ['SPAirPortDataType', '-json'], 15000),
    run('/usr/sbin/sysadminctl', ['-screenLock', 'status'])
  ]);

  const autoOn = parseBoolDefault(auto.stdout);
  const criticalOn = parseBoolDefault(critical.stdout);
  // Anahtar hiç yazılmamışsa (null) macOS varsayılanı açıktır
  const updates = autoOn === false || criticalOn === false ? 'fail' : 'pass';
  const w = parseWifi(wifi.stdout);

  return {
    supported: true,
    at: Date.now(),
    items: [
      item('filevault', parseFileVault(fv.out)),
      item('gatekeeper', parseGatekeeper(gk.out)),
      item('sip', parseSip(sip.out)),
      item('firewall', parseAppFirewall(fw.out)),
      item('updates', updates),
      item('wifi', w.status, { detail: w.ssid ? `${w.ssid} · ${w.security || '?'}` : null }),
      item('screenlock', parseScreenLock(lock.out))
    ]
  };
}

module.exports = {
  audit,
  parseFileVault,
  parseGatekeeper,
  parseSip,
  parseAppFirewall,
  parseBoolDefault,
  parseWifi,
  parseScreenLock,
  SETTINGS
};
