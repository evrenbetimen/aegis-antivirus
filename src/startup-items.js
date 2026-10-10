'use strict';

/**
 * Başlangıç öğeleri (Norton "Startup Manager" benzeri): macOS'ta oturum
 * açılışında ya da sistem açılışında çalışan LaunchAgent/LaunchDaemon
 * kayıtlarını listeler. Kötü amaçlı yazılımların en sık kalıcılık yolu
 * budur; her öğenin çalıştırdığı program tarama motorundan geçirilir ve
 * şüpheli konumlar işaretlenir. Hiçbir öğe değiştirilmez.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const SCOPES = [
  { scope: 'user', dir: () => path.join(os.homedir(), 'Library', 'LaunchAgents') },
  { scope: 'agent', dir: () => '/Library/LaunchAgents' },
  { scope: 'daemon', dir: () => '/Library/LaunchDaemons' }
];

const MAX_PLIST = 512 * 1024;

function xmlUnescape(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

// Küçük XML plist okuyucu (dict, array, string, integer, real, true/false,
// date, data). Bozuk girdide hata fırlatır.
function parseXmlPlist(text) {
  const tokens = [];
  const re = /<(\/?)([A-Za-z]+)(?:\s[^>]*?)?\s*(\/?)>|([^<]+)/g;
  const body = String(text)
    .replace(/<\?xml[\s\S]*?\?>/g, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '');
  let m;
  while ((m = re.exec(body))) {
    if (m[4] !== undefined) tokens.push({ text: m[4] });
    else tokens.push({ close: m[1] === '/', name: m[2], empty: m[3] === '/' });
  }
  let i = 0;
  const skipWs = () => {
    while (i < tokens.length && tokens[i].text !== undefined && !tokens[i].text.trim()) i += 1;
  };
  const textUntil = (name) => {
    let out = '';
    while (i < tokens.length && tokens[i].text !== undefined) out += tokens[i++].text;
    const end = tokens[i++];
    if (!end || !end.close || end.name !== name) throw new Error('malformed plist');
    return xmlUnescape(out);
  };
  function value() {
    skipWs();
    const t = tokens[i++];
    if (!t || t.text !== undefined || t.close) throw new Error('malformed plist');
    if (t.empty) {
      if (t.name === 'true') return true;
      if (t.name === 'false') return false;
      if (t.name === 'dict') return {};
      if (t.name === 'array') return [];
      if (t.name === 'string') return '';
      throw new Error('malformed plist');
    }
    switch (t.name) {
      case 'dict': {
        const obj = {};
        for (;;) {
          skipWs();
          const k = tokens[i];
          if (!k) throw new Error('malformed plist');
          if (k.close && k.name === 'dict') {
            i += 1;
            return obj;
          }
          if (k.name !== 'key' || k.close) throw new Error('malformed plist');
          i += 1;
          const key = k.empty ? '' : textUntil('key');
          const v = value();
          if (!(key in obj)) obj[key] = v;
        }
      }
      case 'array': {
        const arr = [];
        for (;;) {
          skipWs();
          const k = tokens[i];
          if (!k) throw new Error('malformed plist');
          if (k.close && k.name === 'array') {
            i += 1;
            return arr;
          }
          arr.push(value());
        }
      }
      case 'string':
      case 'date':
      case 'data':
        return textUntil(t.name);
      case 'integer':
      case 'real':
        return Number(textUntil(t.name).trim());
      case 'true':
      case 'false': {
        const end = tokens[i++];
        if (!end || !end.close || end.name !== t.name) throw new Error('malformed plist');
        return t.name === 'true';
      }
      case 'plist': {
        const v = value();
        skipWs();
        return v;
      }
      default:
        throw new Error('malformed plist');
    }
  }
  const root = value();
  if (!root || typeof root !== 'object' || Array.isArray(root)) throw new Error('plist root is not a dict');
  return root;
}

function readPlist(file) {
  const buf = fs.readFileSync(file);
  if (buf.length > MAX_PLIST) throw new Error('plist too large');
  if (buf.subarray(0, 6).toString('latin1') === 'bplist') {
    if (process.platform !== 'darwin') throw new Error('binary plist');
    const json = execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file], { timeout: 5000 });
    return JSON.parse(String(json));
  }
  return parseXmlPlist(buf.toString('utf8'));
}

const SUSPICIOUS_DIRS = ['/tmp/', '/private/tmp/', '/var/tmp/', '/private/var/tmp/', '/Users/Shared/'];

/** Öğenin neden şüpheli olduğu (yoksa null). Saf fonksiyon. */
function assess(entry, exists, suspiciousDirs = SUSPICIOUS_DIRS) {
  const program = entry.program || '';
  if (!program) return 'noProgram';
  if (!exists) return 'missingProgram';
  if (suspiciousDirs.some((d) => program.startsWith(d))) return 'tempLocation';
  if (/\/\.[^/]+\//.test(program) || path.basename(program).startsWith('.')) return 'hiddenPath';
  if (/^(\/bin\/(ba|z)?sh|\/usr\/bin\/(python3?|perl|ruby|osascript|curl))$/.test(program)) return 'scriptInterpreter';
  return null;
}

function describe(file, scope, data) {
  const args = Array.isArray(data.ProgramArguments) ? data.ProgramArguments : [];
  const program = typeof data.Program === 'string' ? data.Program : args[0] || null;
  return {
    file,
    scope,
    label: typeof data.Label === 'string' ? data.Label : path.basename(file, '.plist'),
    program,
    args: args.slice(1, 6),
    runAtLoad: data.RunAtLoad === true,
    keepAlive: data.KeepAlive === true || Boolean(data.KeepAlive && typeof data.KeepAlive === 'object'),
    disabled: data.Disabled === true,
    vendor: /^com\.apple\./.test(String(data.Label || '')) ? 'apple' : 'third-party'
  };
}

/**
 * @param {{checkFile?: (file:string) => ({name:string}|null)}} [opts]
 *   checkFile: programı tarama motorundan geçiren fonksiyon
 */
function list(opts = {}) {
  const items = [];
  const errors = [];
  for (const s of opts.scopes || SCOPES) {
    const dir = typeof s.dir === 'function' ? s.dir() : s.dir;
    let names = [];
    try {
      names = fs.readdirSync(dir).filter((n) => n.endsWith('.plist'));
    } catch (err) {
      if (err.code !== 'ENOENT') errors.push({ dir, error: err.code || String(err.message) });
      continue;
    }
    for (const name of names.sort()) {
      const file = path.join(dir, name);
      let entry;
      try {
        entry = describe(file, s.scope, readPlist(file));
      } catch (err) {
        items.push({ file, scope: s.scope, label: name.replace(/\.plist$/, ''), program: null, error: String(err.message || err), risk: 'unreadable' });
        continue;
      }
      let exists = false;
      try {
        exists = Boolean(entry.program) && fs.statSync(entry.program).isFile();
      } catch {
        exists = false;
      }
      entry.exists = exists;
      entry.risk = assess(entry, exists, opts.suspiciousDirs);
      entry.threat = null;
      if (exists && typeof opts.checkFile === 'function') {
        try {
          const hit = opts.checkFile(entry.program);
          if (hit) {
            entry.threat = hit.name;
            entry.risk = 'threat';
          }
        } catch {}
      }
      items.push(entry);
    }
  }
  return { at: Date.now(), items, errors };
}

module.exports = { list, parseXmlPlist, assess, describe };
