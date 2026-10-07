const { exec } = require('child_process');
const dns = require('dns');
const net = require('net');
const store = require('./store');

/**
 * Firewall modülü (Evre 1 - izleme + kural yönetimi).
 *
 * Kuralları uygulamak (gerçek paket engelleme) macOS'ta sistem genişletmesi
 * (NEFilterDataProvider / Network Extension) gerektirir; bkz. native-daemon/.
 * Bu modül:
 *  - kuralları saklar/yönetir
 *  - aktif bağlantıları listeler ve kurallarla eşleşenleri işaretler
 *  - ALAN ADI kurallarını DNS ile çözüp IP üzerinden eşleştirir
 *    (lsof yalnız IP gösterir; domain kuralı aksi halde hiç eşleşmezdi)
 */

const RESOLVE_TTL_MS = 5 * 60 * 1000; // 5 dk
const resolutionCache = new Map(); // host -> {ips:[], error:null|string, at:number}
const inflight = new Map(); // host -> Promise

function getRules() {
  return store.getRules();
}

function setRules(rules) {
  return store.setRules(rules);
}

/* ------------------------------ DNS çözümleme ----------------------------- */

/** "example.com" / "localhost" gibi gerçek bir alan adı mı? (IP ve yol değil) */
function looksLikeDomain(h) {
  if (!h || typeof h !== 'string') return false;
  if (net.isIP(h)) return false;
  if (h.startsWith('/') || h.includes('/')) return false; // uygulama yolu
  if (h.startsWith('*.')) h = h.slice(2);
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  // Tek etiketli adlar alan adı sayılmaz (süreç adıyla karışmasın: "curl" vb.)
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(h);
}

function normalizeIp(ip) {
  let s = String(ip || '').toLowerCase();
  if (s.startsWith('::ffff:')) s = s.slice(7); // IPv4-mapped IPv6
  return s;
}

/**
 * Alan adını IP'lere çözer (A + AAAA), sonucu TTL ile önbelleğe alır.
 * @returns {Promise<{ips:string[], error:string|null, at:number, stale:boolean}>}
 */
function resolveHost(host, { force = false } = {}) {
  const cached = resolutionCache.get(host);
  if (!force && cached && Date.now() - cached.at < RESOLVE_TTL_MS) {
    return Promise.resolve({ ...cached, stale: false });
  }
  if (inflight.has(host)) return inflight.get(host);

  const p = new Promise((resolve) => {
    dns.lookup(host, { all: true, verbatim: false }, (err, addrs) => {
      const rec = err
        ? { ips: [], error: String(err.code || err.message || err), at: Date.now() }
        : {
            ips: Array.from(new Set((addrs || []).map((a) => normalizeIp(a.address)))),
            error: null,
            at: Date.now()
          };
      resolutionCache.set(host, rec);
      resolve({ ...rec, stale: false });
    });
  }).finally(() => inflight.delete(host));

  inflight.set(host, p);
  return p;
}

/** Kurallardaki tüm alan adlarını (tazelik durumuna göre) çözer. */
async function resolveRules(rules, { force = false } = {}) {
  const out = {};
  const domains = Array.from(
    new Set((rules || []).filter((r) => r.host && looksLikeDomain(r.host)).map((r) => r.host))
  );
  await Promise.all(
    domains.map(async (h) => {
      const r = await resolveHost(h, { force });
      out[h] = { ips: r.ips, error: r.error, at: r.at };
    })
  );
  return out;
}

/* ------------------------------ Bağlantı ayrıştırma ------------------------ */

function splitAddr(s) {
  // "[v6]:443" veya "1.2.3.4:443" biçimlerini ayırır
  let m = s.match(/^\[(.+)\]:(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]) };
  m = s.match(/^(.*):(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]) };
  return null;
}

function parseFieldOutput(text) {
  // lsof -Fpcn alan biçimi: p<pid> / c<komut> / n<adres>
  const conns = [];
  let pid = null;
  let cmd = null;
  for (const line of text.split('\n')) {
    if (!line) continue;
    const tag = line[0];
    const val = line.slice(1);
    if (tag === 'p') {
      pid = val;
      cmd = null;
    } else if (tag === 'c') {
      cmd = val;
    } else if (tag === 'n') {
      const arrow = val.indexOf('->');
      if (arrow === -1) continue; // dinleyici/yerel uç
      const local = splitAddr(val.slice(0, arrow));
      const remote = splitAddr(val.slice(arrow + 2));
      if (!remote) continue;
      conns.push({
        process: cmd || '?',
        pid,
        local: local ? `${local.host}:${local.port}` : '?',
        remote: remote.host,
        port: remote.port
      });
    }
  }
  return conns;
}

/* --------------------------------- Eşleme --------------------------------- */

/**
 * @param conn {remote, port, process}
 * @param resolutions host -> {ips:[...]} (isteğe bağlı; verilmezse cache'ten)
 */
function matchRules(conn, resolutions) {
  const rules = getRules();
  const remoteNorm = normalizeIp(conn.remote);

  const resFor = (host) => {
    if (resolutions && resolutions[host]) return resolutions[host];
    const c = resolutionCache.get(host);
    return c ? { ips: c.ips, error: c.error } : null;
  };

  for (const r of rules) {
    if (r.port != null && Number(r.port) !== Number(conn.port)) continue;

    if (!r.host) {
      return r; // tüm hedefler (yalnız port filtresiyle)
    }

    // 1) Doğrudan IP eşleşmesi
    if (normalizeIp(r.host) === remoteNorm) return r;

    // 2) Alan adı → çözülmüş IP seti üzerinden eşleşme
    if (looksLikeDomain(r.host)) {
      const res = resFor(r.host);
      const ips = (res && res.ips) || [];
      if (ips.includes(remoteNorm)) return r;
    }

    // 3) Eski davranış: alt dize eşleşmesi (maskeli IP/host kuralları)
    if (conn.remote && conn.remote.includes(r.host)) return r;

    // 4) Süreç adı eşleşmesi
    if ((conn.process || '').toLowerCase().includes(String(r.host).toLowerCase())) return r;
  }
  return null;
}

/* ------------------------------- Bağlantılar ------------------------------ */

function getConnections() {
  const settings = store.getSettings();
  return new Promise((resolve) => {
    exec('lsof -i -n -P -sTCP:ESTABLISHED -Fpcn 2>/dev/null', { timeout: 4000, maxBuffer: 4 * 1024 * 1024 }, async (err, stdout) => {
      let conns = [];
      if (!err && stdout) conns = parseFieldOutput(stdout);

      // Benzersizleştir
      const seen = new Set();
      conns = conns.filter((c) => {
        const k = c.process + c.remote + c.port;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });

      // Domain kurallarını DNS ile çöz (TTL dolmuşsa tazele)
      let resolutions = {};
      try {
        resolutions = await resolveRules(getRules());
      } catch {
        resolutions = {};
      }

      const marked = conns.map((c) => {
        const rule = matchRules(c, resolutions);
        return Object.assign({}, c, {
          verdict:
            settings.firewallEnabled && rule
              ? rule.type === 'block'
                ? 'blocked'
                : 'allowed'
              : 'none',
          ruleId: rule ? rule.id : null
        });
      });

      // Engellenenler en üste
      marked.sort((a, b) => (a.verdict === 'blocked' ? -1 : 0) - (b.verdict === 'blocked' ? -1 : 0));
      resolve({
        enabled: settings.firewallEnabled,
        connections: marked.slice(0, 120),
        resolutions
      });
    });
  });
}

module.exports = {
  getRules,
  setRules,
  getConnections,
  matchRules,
  resolveHost,
  resolveRules,
  looksLikeDomain,
  parseFieldOutput
};
