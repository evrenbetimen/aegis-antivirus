const fs = require('fs');
const path = require('path');

const VERSION = 1;
const FLUSH_EVERY = 1000; // bu kadar yazımdan sonra otomatik flush
const HASH_RE = /^[0-9a-f]{64}$/; // SHA-256 (64 hex karakter)

/** 64 hex ise kucuk harfe normalize edip döner, degilse null (degeri at). */
function normalizeHash(value) {
  if (typeof value !== 'string') return null;
  const v = value.toLowerCase();
  return HASH_RE.test(v) ? v : null;
}

/**
 * Tarama hash önbelleği: dosya başına (dev:ino:size:mtimeMs) -> SHA-256.
 * Bellek içi Map + kalıcı JSON {version:1, entries:{key:hash}}.
 * Yalnızca Node builtins kullanır (electron gerekmez).
 */
class HashCache {
  constructor(filePath, { maxEntries = 50000 } = {}) {
    if (typeof filePath !== 'string' || filePath.length === 0) {
      throw new TypeError('HashCache: filePath bir dize olmalı');
    }
    this.filePath = filePath;
    this.maxEntries =
      Number.isFinite(maxEntries) && maxEntries > 0 ? Math.floor(maxEntries) : 50000;

    this._map = new Map();
    this._hits = 0;
    this._misses = 0;
    this._writes = 0;
    this._evictions = 0;
    this._sinceFlush = 0; // son flush'tan bu yana yazımdan sayısı
    this._exitHandler = null;

    this._load();
  }

  /**
   * stat (fs.statSync) nesnesinden önbellek anahtarı: "dev:ino:size:mtimeMs".
   * Aynı dosya değişmediği sürece aynı, farklı dosyalar için farklıdır.
   */
  static keyFor(stat) {
    if (!stat || typeof stat !== 'object') return '';
    const dev = stat.dev === undefined ? '' : String(stat.dev);
    const ino = stat.ino === undefined ? '' : String(stat.ino);
    const size = stat.size === undefined ? '' : String(stat.size);
    const mtime = stat.mtimeMs === undefined ? '' : String(stat.mtimeMs);
    return `${dev}:${ino}:${size}:${mtime}`;
  }

  // ---- yükleme ----------------------------------------------------------

  _load() {
    let raw;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch {
      return; // dosya yok / okunamadı -> boş önbellek
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return; // yozlaşmış JSON -> sessizce boş önbellek
    }

    if (
      !data ||
      typeof data !== 'object' ||
      data.version !== VERSION ||
      !data.entries ||
      typeof data.entries !== 'object'
    ) {
      return; // bilinmeyen sürüm / yapı -> boş önbellek
    }

    for (const key of Object.keys(data.entries)) {
      if (key.length === 0) continue;
      const value = normalizeHash(data.entries[key]);
      if (value === null) continue; // geçersiz değeri atla
      this._map.set(key, value);
      if (this._map.size >= this.maxEntries) break;
    }
    this._evict();
  }

  _evict() {
    while (this._map.size > this.maxEntries) {
      const oldest = this._map.keys().next();
      if (oldest.done) break;
      this._map.delete(oldest.value);
      this._evictions++;
    }
  }

  // ---- erişim ------------------------------------------------------------

  /** Önbellekte varsa hash döner, yoksa undefined (istatistikleri etkiler). */
  get(key) {
    const value = typeof key === 'string' ? this._map.get(key) : undefined;
    if (value === undefined) {
      this._misses++;
      return undefined;
    }
    this._hits++;
    return value;
  }

  /**
   * Hash yazar. 64 hex değilse değer reddedilir (false).
   * Her 1000 yazımda bir dosyaya otomatik flush; her set'te değil.
   */
  set(key, hash) {
    if (typeof key !== 'string' || key.length === 0) return false;
    const value = normalizeHash(hash);
    if (value === null) return false; // gecersiz value'yu at

    // güncellenen girdiyi sona al ki "eski" sayılmasın (insertion-order LRU)
    if (this._map.has(key)) this._map.delete(key);
    this._map.set(key, value);

    this._writes++;
    this._sinceFlush++;
    this._evict();

    if (this._sinceFlush >= FLUSH_EVERY) this.flush();
    return true;
  }

  has(key) {
    return typeof key === 'string' && this._map.has(key);
  }

  size() {
    return this._map.size;
  }

  // ---- kalıcılık ---------------------------------------------------------

  /**
   * Atomik yazım: aynı dizinde .tmp dosyasına yaz -> rename.
   * Kirli yazma yok; yalnızca bu metot (ve 1000 yazımdaki otomatik tetik)
   * diske vurur.
   */
  flush() {
    const payload = JSON.stringify({ version: VERSION, entries: Object.fromEntries(this._map) });
    const tmp = this.filePath + '.tmp'; // hedefle aynı dizin -> rename atomik
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(tmp, payload, 'utf8');
      fs.renameSync(tmp, this.filePath); // atomik takas
      this._sinceFlush = 0;
      return true;
    } catch {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // tmp yoksa yok
      }
      return false;
    }
  }

  /**
   * process 'exit' olayına senkron flush bağlar. İsteğe bağlı: kendiliğinden
   * kurulmaz, çağıran karar verir. Tekrar çağırılırsa yeniden bağlamaz.
   */
  flushOnExit() {
    if (this._exitHandler) return this;
    this._exitHandler = () => {
      this.flush();
    };
    process.on('exit', this._exitHandler);
    return this;
  }

  /** Bağlı çıkış dinleyicisini kaldırır ve belleği serbest bırakır. */
  dispose() {
    if (this._exitHandler) {
      process.removeListener('exit', this._exitHandler);
      this._exitHandler = null;
    }
    this._map.clear();
  }

  stats() {
    return {
      hits: this._hits,
      misses: this._misses,
      writes: this._writes,
      evictions: this._evictions
    };
  }
}

module.exports = { HashCache };
