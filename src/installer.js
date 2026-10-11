//
// macOS yükleyici taraması — .pkg (xar) ve .dmg (disk görüntüsü)
//
// archive.js'teki scanEntries sözleşmesinin aynısını uygular:
//   onEntry(entry, getStream) → okunan bayt sayısı
//
// .pkg
//   - xar başlığı ve zlib sıkıştırılmış XML içindekiler tablosu saf JS ile
//     okunur (her platformda çalışır, harici araç yok).
//   - Distribution, PackageInfo gibi düz girdiler ve Scripts / Payload
//     içindeki cpio (odc / newc) üyeleri tek tek taranır. preinstall ve
//     postinstall betikleri kötü amaçlı yükleyicilerin asıl yüküdür.
//   - Apple'ın pbzx (xz) yükleri Node'da açılamaz; macOS'ta
//     `pkgutil --expand-full` ile 0700 geçici klasöre açılıp taranır.
//   - Hiçbir girdi adı dosya yolu olarak kullanılmaz.
//
// .dmg (yalnızca macOS)
//   - `hdiutil attach -readonly -nobrowse -noautoopen` ile Finder'da görünmeden,
//     salt okunur olarak rastgele bir geçici noktaya bağlanır, dosyalar
//     sembolik bağlar izlenmeden okunur, sonra her durumda ayrılır.
//   - Şifreli görüntüler parola penceresi açmamak için atlanır.
//   - Lisans sözleşmeli (SLA) görüntülerde sözleşme yalnızca salt okunur
//     bağlamak için kabul edilir; hiçbir şey çalıştırılmaz veya kurulmaz.
//
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { Readable } = require('stream');
const { execFile } = require('child_process');

const DEFAULTS = {
  maxEntries: 300,
  maxEntryBytes: 30 * 1024 * 1024,
  maxTotalBytes: 200 * 1024 * 1024,
  // Sıkıştırılmış yükte gezilecek toplam açılmış bayt (atlananlar dahil)
  maxInflatedBytes: 2 * 1024 * 1024 * 1024,
  timeoutMs: 120000
};

const TOC_MAX = 16 * 1024 * 1024;

function kindOf(filePath) {
  const p = String(filePath || '').toLowerCase();
  if (p.endsWith('.pkg') || p.endsWith('.mpkg')) return 'pkg';
  if (p.endsWith('.dmg')) return 'dmg';
  return null;
}

/* ------------------------------ xar okuyucu ------------------------------ */

function readAt(fd, offset, length) {
  const buf = Buffer.alloc(length);
  let got = 0;
  while (got < length) {
    const n = fs.readSync(fd, buf, got, length - got, offset + got);
    if (n === 0) break;
    got += n;
  }
  return got === length ? buf : buf.subarray(0, got);
}

function decodeXml(s) {
  return s.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (m, e) => {
    if (e === 'amp') return '&';
    if (e === 'lt') return '<';
    if (e === 'gt') return '>';
    if (e === 'quot') return '"';
    if (e === 'apos') return "'";
    const code = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : '';
  });
}

/**
 * xar içindekiler tablosundaki <file> ağacını düz listeye çevirir.
 * Yalnızca ihtiyaç duyulan alanlar okunur: ad, tür, veri ofseti/uzunluğu
 * ve kodlama. Bozuk XML hata fırlatmaz; o ana kadar okunanlar döner.
 */
function parseToc(xml) {
  const files = [];
  const stack = []; // açık <file> düğümleri
  const tags = []; // açık etiket adları
  let text = '';
  const re = /<(\/?)([A-Za-z_][\w.-]*)([^>]*?)(\/?)>|<!\[CDATA\[([\s\S]*?)\]\]>|<[?!][^>]*>|([^<]+)/g;
  let m;
  while ((m = re.exec(xml))) {
    if (m[6] !== undefined) {
      text += m[6];
      continue;
    }
    if (m[5] !== undefined) {
      text += m[5];
      continue;
    }
    if (!m[2]) continue; // <?xml ...?> / yorum
    const closing = m[1] === '/';
    const selfClosing = m[4] === '/';
    const name = m[2];
    const attrs = m[3] || '';
    if (!closing) {
      text = '';
      if (name === 'file') {
        const node = { name: '', type: '', data: null, parent: stack[stack.length - 1] || null };
        stack.push(node);
        files.push(node);
        if (selfClosing) stack.pop();
      } else if (name === 'data' && stack.length) {
        stack[stack.length - 1].data = { offset: 0, length: 0, size: 0, encoding: '' };
      } else if (name === 'encoding' && stack.length && stack[stack.length - 1].data) {
        const st = attrs.match(/style\s*=\s*"([^"]*)"/);
        stack[stack.length - 1].data.encoding = st ? decodeXml(st[1]) : '';
      }
      if (!selfClosing) tags.push(name);
      continue;
    }
    // kapanış etiketi
    const cur = stack[stack.length - 1];
    const parentTag = tags[tags.length - 2];
    if (cur) {
      const v = decodeXml(text.trim());
      if (name === 'name' && parentTag === 'file') cur.name = v;
      else if (name === 'type' && parentTag === 'file') cur.type = v;
      else if (cur.data && parentTag === 'data' && (name === 'offset' || name === 'length' || name === 'size')) {
        const n = Number(v);
        cur.data[name] = Number.isSafeInteger(n) && n >= 0 ? n : 0;
      }
    }
    if (name === 'file') stack.pop();
    tags.pop();
    text = '';
  }
  for (const f of files) {
    const parts = [];
    for (let n = f; n; n = n.parent) parts.unshift(n.name);
    f.path = parts.join('/');
    delete f.parent;
  }
  return files;
}

/** xar dosyasını okur: { filePath, heapStart, files } veya null (xar değil/bozuk). */
function openXar(filePath) {
  let fd = null;
  try {
    fd = fs.openSync(filePath, 'r');
    const h = readAt(fd, 0, 28);
    if (h.length < 28 || h.toString('latin1', 0, 4) !== 'xar!') throw new Error('xar değil');
    const headerSize = h.readUInt16BE(4);
    const tocComp = Number(h.readBigUInt64BE(8));
    const tocRaw = Number(h.readBigUInt64BE(16));
    if (headerSize < 28 || !tocComp || tocComp > TOC_MAX || tocRaw > TOC_MAX) throw new Error('xar başlığı geçersiz');
    const comp = readAt(fd, headerSize, tocComp);
    const xml = zlib.inflateSync(comp, { maxOutputLength: TOC_MAX }).toString('utf8');
    fs.closeSync(fd);
    fd = null;
    return { filePath, heapStart: headerSize + tocComp, files: parseToc(xml) };
  } catch {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
    return null;
  }
}

/** xar girdisinin çözülmüş içeriğini akış olarak verir. */
function xarDataStream(xar, file) {
  const d = file.data;
  const start = xar.heapStart + d.offset;
  const raw = d.length
    ? fs.createReadStream(xar.filePath, { start, end: start + d.length - 1 })
    : Readable.from([]);
  const enc = (d.encoding || '').toLowerCase();
  if (enc === 'application/x-gzip') {
    // xar "x-gzip" aslında zlib (deflate + zlib başlığı) demektir
    const inf = zlib.createInflate();
    raw.on('error', (e) => inf.destroy(e));
    return raw.pipe(inf);
  }
  if (!enc || enc === 'application/octet-stream') return raw;
  raw.destroy();
  return null; // bzip2 vb. desteklenmiyor
}

/* ------------------------------ akış okuyucu ----------------------------- */

/** Akıştan tam n bayt okuma / atlama (cpio ayrıştırıcısı için). */
class ByteReader {
  constructor(stream, limit) {
    this.it = stream[Symbol.asyncIterator]();
    this.stream = stream;
    this.buf = Buffer.alloc(0);
    this.ended = false;
    this.consumed = 0;
    this.limit = limit;
  }
  async fill(n) {
    while (this.buf.length < n && !this.ended) {
      const { value, done } = await this.it.next();
      if (done) {
        this.ended = true;
        break;
      }
      this.consumed += value.length;
      if (this.consumed > this.limit) throw new Error('açılmış bayt sınırı');
      this.buf = this.buf.length ? Buffer.concat([this.buf, value]) : value;
    }
    return this.buf.length >= n;
  }
  async peek(n) {
    await this.fill(n);
    return this.buf.subarray(0, Math.min(n, this.buf.length));
  }
  async read(n) {
    if (!(await this.fill(n))) throw new Error('beklenmeyen son');
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
  async skip(n) {
    while (n > 0) {
      if (!this.buf.length && !(await this.fill(1))) throw new Error('beklenmeyen son');
      const k = Math.min(n, this.buf.length);
      this.buf = this.buf.subarray(k);
      n -= k;
    }
  }
  close() {
    try {
      this.stream.destroy();
    } catch {}
  }
}

/**
 * cpio (odc "070707" veya newc "070701"/"070702") üyelerini sırayla verir.
 * Her üye için onMember({name, size, regular}, readBody) çağrılır;
 * readBody(cap) en fazla cap bayt döndürür, kalan kısım otomatik atlanır.
 */
async function walkCpio(reader, onMember) {
  for (;;) {
    const magic = (await reader.peek(6)).toString('latin1');
    let name;
    let size;
    let mode;
    let namePad = 0;
    let dataPad = 0;
    if (magic === '070707') {
      const h = (await reader.read(76)).toString('latin1');
      mode = parseInt(h.slice(18, 24), 8);
      const nameSize = parseInt(h.slice(59, 65), 8);
      size = parseInt(h.slice(65, 76), 8);
      name = (await reader.read(nameSize)).toString('utf8').replace(/\0+$/, '');
    } else if (magic === '070701' || magic === '070702') {
      const h = (await reader.read(110)).toString('latin1');
      const hex = (i) => parseInt(h.slice(6 + i * 8, 14 + i * 8), 16);
      mode = hex(1);
      size = hex(6);
      const nameSize = hex(11);
      namePad = (4 - ((110 + nameSize) % 4)) % 4;
      dataPad = (4 - (size % 4)) % 4;
      name = (await reader.read(nameSize)).toString('utf8').replace(/\0+$/, '');
      await reader.skip(namePad);
    } else {
      return; // cpio değil ya da bitti
    }
    if (!Number.isFinite(size) || size < 0 || !Number.isFinite(mode)) return;
    if (name === 'TRAILER!!!') return;
    let left = size;
    // Kesik arşivde eldeki kısım yine taranır; sonraki üyeye geçilmez
    const readBody = async (cap) => {
      const n = Math.min(cap, left);
      await reader.fill(n);
      const out = Buffer.from(reader.buf.subarray(0, n));
      reader.buf = reader.buf.subarray(out.length);
      left -= out.length;
      return out;
    };
    const regular = (mode & 0o170000) === 0o100000;
    const stop = await onMember({ name: name.replace(/^\.\//, ''), size, regular }, readBody);
    await reader.skip(left + dataPad);
    if (stop) return;
  }
}

/* ------------------------------- .pkg tarama ------------------------------ */

function run(cmd, args, timeoutMs, input) {
  return new Promise((resolve) => {
    const child = execFile(
      cmd,
      args,
      { timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: stdout || '', stderr: stderr || '' })
    );
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

/** Dizindeki normal dosyaları (sembolik bağ izlemeden) göreli yollarıyla listeler. */
function walkDir(root, limit) {
  const out = [];
  const stack = [''];
  while (stack.length && out.length < limit) {
    const rel = stack.pop();
    let names;
    try {
      names = fs.readdirSync(path.join(root, rel));
    } catch {
      continue;
    }
    for (const n of names.sort()) {
      const r = rel ? rel + '/' + n : n;
      let st;
      try {
        st = fs.lstatSync(path.join(root, r));
      } catch {
        continue;
      }
      if (st.isDirectory()) stack.push(r);
      else if (st.isFile()) out.push({ name: r, size: st.size });
      if (out.length >= limit) break;
    }
  }
  return out;
}

/** Bütçeli tarama durumu (girdi / bayt / süre sınırları). */
function makeBudget(opts) {
  const o = Object.assign({}, DEFAULTS, opts);
  const res = { scanned: 0, skipped: 0, totalBytes: 0, truncated: false, unsupported: 0 };
  const deadline = Date.now() + o.timeoutMs;
  return {
    o,
    res,
    full() {
      if (res.scanned + res.skipped >= o.maxEntries || res.totalBytes >= o.maxTotalBytes || Date.now() > deadline) {
        res.truncated = true;
        return true;
      }
      return false;
    }
  };
}

/** Tek bir girdiyi tüketiciye verir; getStream bir arabellekten beslenir. */
async function deliver(b, onEntry, entry, loadBuffer) {
  if (entry.size > b.o.maxEntryBytes) {
    b.res.skipped++;
    return;
  }
  let loaded = null;
  const getStream = () => {
    const s = new Readable({ read() {} });
    (async () => {
      try {
        if (!loaded) loaded = await loadBuffer();
        s.push(loaded);
        s.push(null);
      } catch (e) {
        s.destroy(e);
      }
    })();
    return s;
  };
  try {
    const n = await onEntry(entry, getStream);
    b.res.scanned++;
    const sz = Number.isFinite(n) ? n : loaded ? loaded.length : 0;
    b.res.totalBytes += sz;
  } catch {
    b.res.skipped++;
  }
}

function readStreamAll(stream, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', (c) => {
      size += c.length;
      if (size > cap) {
        stream.destroy();
        reject(new Error('girdi sınırı aşıldı'));
        return;
      }
      chunks.push(c);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

async function scanPkg(filePath, onEntry, opts = {}) {
  const b = makeBudget(opts);
  const xar = openXar(filePath);
  if (!xar) return b.res;
  const needsExpand = [];
  // Önce küçük girdiler ve betikler: büyük Payload bütçeyi tüketmeden önce
  // asıl risk olan preinstall/postinstall betikleri taranmış olsun
  const rank = (f) => {
    const base = f.path.split('/').pop();
    return base === 'Payload' ? 2 : base === 'Scripts' ? 1 : 0;
  };
  const ordered = xar.files.slice().sort((x, y) => rank(x) - rank(y));
  for (const f of ordered) {
    if (b.full()) break;
    if (f.type !== 'file' || !f.data || !f.path) continue;
    const base = f.path.split('/').pop();
    // Payload / Scripts: gzip'li cpio → üyeler tek tek taranır
    if (base === 'Payload' || base === 'Scripts') {
      const s = xarDataStream(xar, f);
      if (!s) {
        b.res.unsupported++;
        continue;
      }
      const reader = new ByteReader(s, b.o.maxInflatedBytes);
      try {
        const head = await reader.peek(4);
        if (head[0] === 0x1f && head[1] === 0x8b) {
          reader.close();
          const gz = xarDataStream(xar, f).pipe(zlib.createGunzip());
          const inner = new ByteReader(gz, b.o.maxInflatedBytes);
          try {
            await walkCpio(inner, async (m, readBody) => {
              if (b.full()) return true;
              if (!m.regular || !m.name) return false;
              await deliver(b, onEntry, { name: `${f.path}/${m.name}`, size: m.size, isDir: false }, () =>
                readBody(b.o.maxEntryBytes)
              );
              return false;
            });
          } finally {
            inner.close();
          }
        } else if (head.toString('latin1') === 'pbzx') {
          reader.close();
          needsExpand.push(f.path);
        } else {
          reader.close();
          b.res.unsupported++;
        }
      } catch {
        reader.close();
        b.res.skipped++;
      }
      continue;
    }
    // Bom ikili malzeme listesidir; tarama değeri yok
    if (base === 'Bom') continue;
    await deliver(b, onEntry, { name: f.path, size: f.data.size || f.data.length, isDir: false }, () => {
      const s = xarDataStream(xar, f);
      if (!s) throw new Error('desteklenmeyen kodlama');
      return readStreamAll(s, b.o.maxEntryBytes);
    });
  }

  // pbzx yükleri: yalnızca macOS'ta pkgutil ile açılabilir
  if (needsExpand.length && !b.full()) {
    if (process.platform === 'darwin') await scanExpanded(filePath, onEntry, b, needsExpand);
    else b.res.unsupported += needsExpand.length;
  }
  return b.res;
}

async function scanExpanded(filePath, onEntry, b, wanted) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-pkg-'));
  fs.chmodSync(tmp, 0o700);
  const out = path.join(tmp, 'x');
  try {
    const r = await run('/usr/sbin/pkgutil', ['--expand-full', filePath, out], b.o.timeoutMs);
    if (!r.ok) {
      b.res.unsupported += wanted.length;
      return;
    }
    // pkgutil "Payload" yükünü aynı adlı klasöre açar
    const prefixes = wanted.map((w) => w + '/');
    for (const e of walkDir(out, b.o.maxEntries * 4)) {
      if (b.full()) break;
      if (!prefixes.some((p) => e.name.startsWith(p))) continue;
      await deliver(b, onEntry, { name: e.name, size: e.size, isDir: false }, () =>
        readStreamAll(fs.createReadStream(path.join(out, e.name)), b.o.maxEntryBytes)
      );
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* ------------------------------- .dmg tarama ------------------------------ */

function plistMountPoints(xml) {
  const out = [];
  const re = /<key>mount-point<\/key>\s*<string>([^<]+)<\/string>/g;
  let m;
  while ((m = re.exec(xml))) out.push(decodeXml(m[1]));
  return out;
}

function plistDevEntries(xml) {
  const out = [];
  const re = /<key>dev-entry<\/key>\s*<string>([^<]+)<\/string>/g;
  let m;
  while ((m = re.exec(xml))) out.push(decodeXml(m[1]));
  return out;
}

async function scanDmg(filePath, onEntry, opts = {}) {
  const b = makeBudget(opts);
  if (process.platform !== 'darwin') {
    b.res.unsupported++;
    return b.res;
  }
  const hdiutil = '/usr/bin/hdiutil';
  const enc = await run(hdiutil, ['isencrypted', filePath], 15000);
  if (/encrypted:\s*YES/i.test(enc.stdout)) {
    b.res.unsupported++;
    return b.res;
  }
  // /var → /private/var: hdiutil bağlama noktasını gerçek yolla bildirir
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-dmg-')));
  fs.chmodSync(base, 0o700);
  let devs = [];
  try {
    // SLA'lı görüntüler stdin'den "Y" bekler; boş stdin bağlamayı reddettirir
    const r = await run(
      hdiutil,
      ['attach', '-readonly', '-nobrowse', '-noautoopen', '-noverify', '-mountrandom', base, '-plist', filePath],
      Math.min(b.o.timeoutMs, 90000),
      'Y\n'
    );
    const xmlStart = r.stdout.indexOf('<?xml');
    const xml = xmlStart >= 0 ? r.stdout.slice(xmlStart) : '';
    devs = plistDevEntries(xml);
    const mounts = plistMountPoints(xml).filter((m) => m.startsWith(base + path.sep));
    if (!r.ok || !mounts.length) {
      b.res.unsupported++;
      return b.res;
    }
    for (const mount of mounts) {
      for (const e of walkDir(mount, b.o.maxEntries + 1)) {
        if (b.full()) break;
        const name = mounts.length > 1 ? `${path.basename(mount)}/${e.name}` : e.name;
        const full = path.join(mount, e.name);
        // Akış doğrudan diskten okunur; tüketici yalnızca ihtiyacı kadarını okur
        if (e.size > b.o.maxEntryBytes) {
          b.res.skipped++;
          continue;
        }
        try {
          const n = await onEntry({ name, size: e.size, isDir: false }, () => fs.createReadStream(full));
          b.res.scanned++;
          b.res.totalBytes += Number.isFinite(n) ? n : e.size;
        } catch {
          b.res.skipped++;
        }
      }
    }
    return b.res;
  } finally {
    // Önce kök aygıt (tüm bölümleri ayırır); olmazsa zorla
    const root = devs.slice().sort((x, y) => x.length - y.length)[0];
    if (root) {
      const d = await run(hdiutil, ['detach', root, '-quiet'], 30000);
      if (!d.ok) await run(hdiutil, ['detach', root, '-force', '-quiet'], 30000);
    }
    try {
      fs.rmSync(base, { recursive: true, force: true });
    } catch {}
  }
}

async function scanEntries(filePath, onEntry, opts = {}) {
  const kind = kindOf(filePath);
  if (kind === 'pkg') return scanPkg(filePath, onEntry, opts);
  if (kind === 'dmg') return scanDmg(filePath, onEntry, opts);
  return { scanned: 0, skipped: 0, totalBytes: 0, truncated: false, unsupported: 0 };
}

module.exports = { kindOf, scanEntries, scanPkg, scanDmg, parseToc, openXar, walkCpio, ByteReader, DEFAULTS };
