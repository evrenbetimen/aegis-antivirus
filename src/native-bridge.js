//
// Native sistem genişletmeleri (native-daemon/) ↔ Electron köprüsü.
//
// Genişletmeler root olarak çalışır ve satır sonu JSON olaylarını bir UNIX
// domain socket'ine yazar (şema: native-daemon/README.md §2). Electron oturum
// açan kullanıcıda çalıştığından kök sahipli /Library/Application Support/Aegis
// klasörüne yazamaz; bu yüzden socket'i ve kalkan politikasını kendi userData
// klasöründe açar. Genişletmeler kanonik yol yoksa
// /Users/*/Library/Application Support/*/ altında bu dosyaları arar.
//
// Socket 0600'dır: root genişletme bağlanabilir, başka kullanıcılar
// bağlanamaz. Gelen olaylar yalnızca bilgi amaçlıdır (kayıt + bildirim);
// karantina gibi bir eylemi tetiklemez.
//

const fs = require('fs');
const net = require('net');
const path = require('path');

const MAX_LINE = 64 * 1024;
const MAX_CLIENTS = 4;
const STRING_LIMIT = 1024;

const DEFAULT_POLICY = {
  enabled: false,
  denyUnsigned: false,
  hashing: true,
  maxHashBytes: 16 * 1024 * 1024,
  denyPaths: ['/private/tmp/', '/var/tmp/'],
  allowPaths: [],
  protectedPaths: ['/Library/Preferences/', '/System/Library/']
};

function str(v, limit = STRING_LIMIT) {
  return typeof v === 'string' ? v.slice(0, limit) : '';
}

function int(v) {
  return Number.isInteger(v) ? v : null;
}

/** Şemaya uymayan satırları atar, bilinen alanları süzer. */
function parseEvent(line) {
  let o;
  try {
    o = JSON.parse(line);
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object' || o.v !== 1) return null;
  if (o.source === 'shield' && o.event === 'exec') {
    if (o.verdict !== 'allow' && o.verdict !== 'deny') return null;
    return {
      source: 'shield',
      event: 'exec',
      verdict: o.verdict,
      reason: str(o.reason, 64),
      threat: str(o.threat, 200),
      path: str(o.path),
      pid: int(o.pid),
      uid: int(o.uid),
      signingID: str(o.signingID, 200),
      teamID: str(o.teamID, 32),
      sha256: /^[0-9a-f]{64}$/.test(o.sha256 || '') ? o.sha256 : ''
    };
  }
  if (o.source === 'firewall' && o.event === 'flow-block') {
    return {
      source: 'firewall',
      event: 'flow-block',
      verdict: 'deny',
      host: str(o.host, 255),
      port: int(o.port),
      proto: str(o.proto, 16),
      rule: str(o.rule, 64),
      sourcePid: int(o.sourcePid)
    };
  }
  return null;
}

function writeAtomic(file, data) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, data, { mode: 0o644 });
  fs.renameSync(tmp, file);
}

/** Kalkan politikasını genişletmenin okuduğu yere yazar (2 sn'de bir yeniden okunur). */
function writePolicy(dir, settings) {
  const policy = Object.assign({}, DEFAULT_POLICY, { enabled: !!(settings && settings.realtimeEnabled) });
  fs.mkdirSync(dir, { recursive: true });
  writeAtomic(path.join(dir, 'shield-policy.json'), JSON.stringify(policy, null, 2));
  return policy;
}

class NativeBridge {
  constructor({ socketPath, onEvent, log = console }) {
    this.socketPath = socketPath;
    this.onEvent = onEvent;
    this.log = log;
    this.server = null;
    this.clients = new Set();
    this.last = { shield: null, firewall: null };
    this.received = 0;
    this.dropped = 0;
  }

  start() {
    if (this.server) return Promise.resolve();
    // Önceki çalıştırmadan kalan socket dosyasını yalnızca gerçekten socket ise sil
    try {
      if (fs.lstatSync(this.socketPath).isSocket()) fs.unlinkSync(this.socketPath);
    } catch {}
    return new Promise((resolve, reject) => {
      const server = net.createServer((sock) => this._accept(sock));
      server.maxConnections = MAX_CLIENTS;
      server.once('error', reject);
      server.listen(this.socketPath, () => {
        try {
          fs.chmodSync(this.socketPath, 0o600);
        } catch {}
        server.removeListener('error', reject);
        server.on('error', (err) => this.log.warn('[native] socket hatası:', err && err.message));
        this.server = server;
        resolve();
      });
    });
  }

  _accept(sock) {
    this.clients.add(sock);
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (chunk) => {
      buf += chunk;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        this._line(line);
      }
      if (buf.length > MAX_LINE) {
        this.dropped++;
        sock.destroy();
      }
    });
    const done = () => this.clients.delete(sock);
    sock.on('close', done);
    sock.on('error', done);
  }

  _line(line) {
    const ev = parseEvent(line);
    if (!ev) {
      if (line.trim()) this.dropped++;
      return;
    }
    this.received++;
    this.last[ev.source] = Date.now();
    try {
      this.onEvent(ev);
    } catch (err) {
      this.log.warn('[native] olay işlenemedi:', err && err.message);
    }
  }

  status() {
    return {
      listening: !!this.server,
      clients: this.clients.size,
      received: this.received,
      dropped: this.dropped,
      shieldSeenAt: this.last.shield,
      firewallSeenAt: this.last.firewall,
      // Bağlı bir genişletme varsa ya da son 10 dakikada olay geldiyse "devrede"
      connected: this.clients.size > 0 || [this.last.shield, this.last.firewall].some((t) => t && Date.now() - t < 600000)
    };
  }

  stop() {
    for (const s of this.clients) s.destroy();
    this.clients.clear();
    if (this.server) {
      this.server.close();
      this.server = null;
      try {
        fs.unlinkSync(this.socketPath);
      } catch {}
    }
  }
}

module.exports = { NativeBridge, parseEvent, writePolicy, DEFAULT_POLICY };
