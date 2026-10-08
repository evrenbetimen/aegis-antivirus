//
// IPC girdi doğrulaması — renderer'dan gelen ayar ve firewall kuralları.
// Saf modül (electron gerektirmez); store/firewall bu fonksiyonlardan geçirir.
//

const SETTING_TYPES = {
  autoQuarantine: 'boolean',
  heuristics: 'boolean',
  notifications: 'boolean',
  scanArchives: 'boolean',
  firewallEnabled: 'boolean',
  realtimeEnabled: 'boolean',
  scheduledScan: 'boolean',
  honeypotEnabled: 'boolean',
  dbAutoUpdate: 'boolean',
  fdaOnboardingDone: 'boolean'
};

const MAX_EXCLUSIONS = 200;
const MAX_RULES = 500;

/**
 * Ayar yamasını süzer: bilinmeyen anahtarlar ve yanlış tipteki değerler atılır.
 * @returns {object} yalnızca geçerli alanları içeren yama
 */
function sanitizeSettingsPatch(patch) {
  const out = {};
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return out;
  for (const [k, v] of Object.entries(patch)) {
    if (SETTING_TYPES[k]) {
      if (typeof v === SETTING_TYPES[k]) out[k] = v;
    } else if (k === 'language') {
      if (v === 'tr' || v === 'en') out[k] = v;
    } else if (k === 'scanIntervalHours') {
      const n = Number(v);
      if (Number.isFinite(n)) out[k] = Math.min(168, Math.max(1, Math.round(n)));
    } else if (k === 'dbUrl') {
      if (typeof v === 'string' && v.length <= 2048) out[k] = v.trim();
    } else if (k === 'exclusions') {
      if (Array.isArray(v)) {
        out[k] = Array.from(
          new Set(v.filter((p) => typeof p === 'string' && p.startsWith('/') && p.length <= 4096 && !p.includes('\0')))
        ).slice(0, MAX_EXCLUSIONS);
      }
    }
  }
  return out;
}

/**
 * Firewall kural listesini doğrular; geçersiz kurallar atılır.
 * @returns {Array<{id,type,proto,host,port,note}>}
 */
function sanitizeRules(rules) {
  if (!Array.isArray(rules)) return null;
  const out = [];
  const seen = new Set();
  for (const r of rules) {
    if (!r || typeof r !== 'object') continue;
    if (r.type !== 'block' && r.type !== 'allow') continue;
    let id = typeof r.id === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(r.id) ? r.id : null;
    if (!id || seen.has(id)) id = 'r' + Date.now().toString(36) + out.length;
    seen.add(id);

    let host = null;
    if (r.host != null && r.host !== '') {
      if (typeof r.host !== 'string') continue;
      host = r.host.trim();
      if (!host || host.length > 253 || /[\s\0<>"'`]/.test(host)) continue;
    }

    let port = null;
    if (r.port != null && r.port !== '') {
      const n = Number(r.port);
      if (!Number.isInteger(n) || n < 1 || n > 65535) continue;
      port = n;
    }

    out.push({
      id,
      type: r.type,
      proto: r.proto === 'udp' ? 'udp' : 'tcp',
      host,
      port,
      note: typeof r.note === 'string' ? r.note.slice(0, 200) : ''
    });
    if (out.length >= MAX_RULES) break;
  }
  return out;
}

module.exports = { sanitizeSettingsPatch, sanitizeRules };
