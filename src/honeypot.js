//
// Fidye yazılımı algılama — yerel (native olmayan) yaklaşım
//
// İki sinyal:
//   1. Yem dosyalar (honeypot): korunan dizinlere yerleştirilen kolayca
//      fark edilen .txt dosyaları. Fidye yazılımı dizini tararken bunları
//      da şifreler/değiştirir → anında alarm.
//   2. Toplu değişiklik patlaması: kısa sürede çok sayıda dosya
//      oluşturulması/adı değiştirilmesi (fidye imzası) → davranışsal alarm.
//
// Gerçek zamanlı dosya olayları için fs.watch (macOS'ta FSEvents üzerinde
// çalışır). Daha derin izleme (exec/open engelleme) native ES daemon ister
// (native-daemon/).
//
const fs = require('fs');
const path = require('path');
const os = require('os');

const BAIT_NAME = 'Aegis-Korumali-Dosya.txt';
const BAIT_CONTENT = [
  'Bu dosya Aegis Security Suite tarafından yerleştirilmiş bir yem dosyadır.',
  'Fidye yazılımı bu dosyayı değiştirirse güvenlik sistemi anında uyarır.',
  '',
  'This is a honeypot file placed by Aegis Security Suite.',
  'If ransomware modifies it, you will be alerted immediately.',
  ''
].join('\n');

const BURST_WINDOW_MS = 5000;
const BURST_THRESHOLD = 40; // 5 sn içinde eşik üstü olay → şüphe

class Honeypot {
  constructor({ dirs, onEvent } = {}) {
    this.dirs = dirs && dirs.length ? dirs : defaultDirs();
    this.onEvent = onEvent || (() => {});
    this.watchers = [];
    this.baitState = new Map(); // path -> {size, mtimeMs}
    this.burst = { events: 0, windowStart: 0, reported: false };
    this.running = false;
    this.lastEvent = null;
  }

  start() {
    if (this.running) return;
    this.running = true;

    for (const dir of this.dirs) {
      if (!fs.existsSync(dir)) continue;
      this.placeBait(dir);
      try {
        const w = fs.watch(dir, { persistent: false }, (eventType, filename) => {
          this.onFsEvent(dir, eventType, filename);
        });
        this.watchers.push(w);
      } catch {
        // izin yoksa o dizin atlanır
      }
    }
    this.snapshotBaits();
  }

  stop() {
    this.running = false;
    for (const w of this.watchers) {
      try {
        w.close();
      } catch {}
    }
    this.watchers = [];
  }

  /** Yem dosyalarını oluşturur (varsa dokunmaz). */
  placeBait(dir) {
    try {
      const p = path.join(dir, BAIT_NAME);
      if (!fs.existsSync(p)) {
        fs.writeFileSync(p, BAIT_CONTENT, 'utf8');
      }
    } catch {}
  }

  snapshotBaits() {
    this.baitState.clear();
    for (const dir of this.dirs) {
      const p = path.join(dir, BAIT_NAME);
      try {
        const st = fs.statSync(p);
        this.baitState.set(p, { size: st.size, mtimeMs: st.mtimeMs });
      } catch {}
    }
  }

  onFsEvent(dir, eventType, filename) {
    if (!this.running) return;
    const fname = filename ? String(filename) : '';

    // 1) Yem dosyası kontrolü
    const baitPath = path.join(dir, BAIT_NAME);
    if (!fname || fname === BAIT_NAME || fname.includes(BAIT_NAME)) {
      let state = null;
      try {
        const st = fs.statSync(baitPath);
        state = { size: st.size, mtimeMs: st.mtimeMs };
      } catch {
        state = null; // silinmiş
      }
      const prev = this.baitState.get(baitPath);
      if (prev) {
        if (!state) {
          this.emit({
            type: 'ransomware',
            kind: 'decoy-deleted',
            path: baitPath,
            detail: 'Yem dosyası silindi'
          });
        } else if (state.size !== prev.size || state.mtimeMs !== prev.mtimeMs) {
          this.emit({
            type: 'ransomware',
            kind: 'decoy-modified',
            path: baitPath,
            detail: 'Yem dosyası değiştirildi (fidye aktivitesi)'
          });
        }
      }
      if (state) this.baitState.set(baitPath, state);
    }

    // 2) Toplu değişiklik patlaması
    const now = Date.now();
    if (now - this.burst.windowStart > BURST_WINDOW_MS) {
      this.burst.windowStart = now;
      this.burst.events = 0;
      this.burst.reported = false;
    }
    this.burst.events++;
    if (this.burst.events >= BURST_THRESHOLD && !this.burst.reported) {
      this.burst.reported = true;
      this.emit({
        type: 'ransomware',
        kind: 'mass-modification',
        path: dir,
        detail: `${BURST_WINDOW_MS / 1000} sn içinde ${this.burst.events} dosya olayı — toplu değiştirme şüphesi`
      });
    }
  }

  emit(ev) {
    const payload = Object.assign({ ts: Date.now() }, ev);
    this.lastEvent = payload;
    try {
      this.onEvent(payload);
    } catch {}
  }

  status() {
    return {
      running: this.running,
      dirs: this.dirs,
      baits: Array.from(this.baitState.keys()),
      watchers: this.watchers.length,
      lastEvent: this.lastEvent
    };
  }

  /** Yem dosyalarını kaldır (kullanıcı kapatmak isterse). */
  cleanup() {
    this.stop();
    for (const p of this.baitState.keys()) {
      try {
        fs.unlinkSync(p);
      } catch {}
    }
    this.baitState.clear();
  }
}

function defaultDirs() {
  const home = os.homedir();
  return [path.join(home, 'Documents'), path.join(home, 'Desktop')];
}

module.exports = { Honeypot, BAIT_NAME, defaultDirs };
