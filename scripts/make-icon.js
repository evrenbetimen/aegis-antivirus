'use strict';

/**
 * Aegis Security Suite — uygulama ikonu üreticisi (Electron ana süreç scripti).
 *
 * Çalıştırma:
 *   env -u NODE_OPTIONS ./node_modules/.bin/electron scripts/make-icon.js
 *
 * Ne yapar:
 *   1. 1024x1024 HTML sayfası (data URL) içinde koyu-lacivert zemin üzerinde
 *      gradyanlı (cyan #22d3ee → mavi #3b82f6) modern kalkan SVG'si oluşturur.
 *   2. Gizli BrowserWindow ile yükler, webContents.capturePage() ile
 *      build/icon.png (1024x1024) kaydeder.
 *   3. sips ile klasik boyut setini üretir → build/icon.iconset → iconutil ile
 *      build/icon.icns.
 *   4. app.quit().
 *
 * Yeni bağımlılık YOK: sadece electron, node:fs, node:child_process.
 */

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = path.join(ROOT, 'build');
const PNG_PATH = path.join(BUILD_DIR, 'icon.png');
const ICONSET_DIR = path.join(BUILD_DIR, 'icon.iconset');
const ICNS_PATH = path.join(BUILD_DIR, 'icon.icns');

const SIZE = 1024;

/* ------------------------------------------------------------------ */
/* ikonset boyutları: [dosya adı, piksel boyutu]                      */
/* ------------------------------------------------------------------ */
const ICONSET_SIZES = [
  ['icon_16x16.png', 16],
  ['icon_16x16@2x.png', 32],
  ['icon_32x32.png', 32],
  ['icon_32x32@2x.png', 64],
  ['icon_128x128.png', 128],
  ['icon_128x128@2x.png', 256],
  ['icon_256x256.png', 256],
  ['icon_256x256@2x.png', 512],
  ['icon_512x512.png', 512],
  ['icon_512x512@2x.png', 1024],
];

/* ------------------------------------------------------------------ */
/* HTML + SVG                                                          */
/* ------------------------------------------------------------------ */

// Kalkan konturu (512 viewBox): yuvarlak köşeli, alta doğru sivri modern shield.
const SHIELD_PATH = [
  'M102 96',
  'H410',
  'A24 24 0 0 1 434 120',
  'V240',
  'C434 348 366 428 256 470',
  'C146 428 78 348 78 240',
  'V120',
  'A24 24 0 0 1 102 96',
  'Z',
].join(' ');

const CHECK_PATH = 'M176 264 L232 320 L340 204';

function buildHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Aegis Icon</title>
<style>
  html, body {
    margin: 0; padding: 0;
    width: ${SIZE}px; height: ${SIZE}px;
    overflow: hidden;
  }
  body {
    background:
      radial-gradient(120% 85% at 50% -10%, #16264a 0%, rgba(22,38,74,0) 55%),
      linear-gradient(160deg, #0b1224 0%, #080e1c 45%, #070b14 100%);
    display: flex; align-items: center; justify-content: center;
    -webkit-font-smoothing: antialiased;
  }
  svg { display: block; }
</style>
</head>
<body>
<svg width="${SIZE}" height="${SIZE}" viewBox="0 0 512 512"
     xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Aegis">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="85%" y2="100%">
      <stop offset="0%"   stop-color="#22d3ee" />
      <stop offset="52%"  stop-color="#2b9fe0" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>

    <linearGradient id="glossGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%"   stop-color="#ffffff" stop-opacity="0.42" />
      <stop offset="38%"  stop-color="#ffffff" stop-opacity="0.10" />
      <stop offset="70%"  stop-color="#ffffff" stop-opacity="0.00" />
      <stop offset="100%" stop-color="#0b1a33" stop-opacity="0.18" />
    </linearGradient>

    <radialGradient id="haloGrad" cx="50%" cy="44%" r="52%">
      <stop offset="0%"   stop-color="#38bdf8" stop-opacity="0.50" />
      <stop offset="55%"  stop-color="#3b82f6" stop-opacity="0.14" />
      <stop offset="100%" stop-color="#3b82f6" stop-opacity="0" />
    </radialGradient>

    <clipPath id="shieldClip">
      <path d="${SHIELD_PATH}" />
    </clipPath>

    <filter id="dropShadow" x="-40%" y="-40%" width="180%" height="180%">
      <feDropShadow dx="0" dy="16" stdDeviation="20"
                    flood-color="#020617" flood-opacity="0.70" />
      <feDropShadow dx="0" dy="4"  stdDeviation="6"
                    flood-color="#0ea5e9" flood-opacity="0.35" />
    </filter>

    <filter id="checkShadow" x="-40%" y="-40%" width="180%" height="180%">
      <feDropShadow dx="0" dy="5" stdDeviation="6"
                    flood-color="#0b2742" flood-opacity="0.45" />
    </filter>
  </defs>

  <!-- arka plan parıltısı -->
  <circle cx="256" cy="246" r="212" fill="url(#haloGrad)" />

  <g filter="url(#dropShadow)">
    <!-- gradyanlı kalkan gövdesi -->
    <path d="${SHIELD_PATH}" fill="url(#shieldGrad)" />

    <!-- iç yüzey parlaklığı (clip'li) -->
    <g clip-path="url(#shieldClip)">
      <rect x="0" y="0" width="512" height="512" fill="url(#glossGrad)" />
      <!-- yumuşak üst kenar vurgusu -->
      <path d="${SHIELD_PATH}" fill="none" stroke="#ffffff"
            stroke-opacity="0.55" stroke-width="7" />
      <!-- ince iç hat -->
      <path d="${SHIELD_PATH}" fill="none" stroke="#0b2a4a"
            stroke-opacity="0.30" stroke-width="2.5"
            transform="translate(0 3) scale(0.965) translate(9 3)" />
    </g>

    <!-- dış kontur -->
    <path d="${SHIELD_PATH}" fill="none" stroke="#ffffff"
          stroke-opacity="0.30" stroke-width="5" />
  </g>

  <!-- beyaz onay işareti -->
  <g filter="url(#checkShadow)">
    <path d="${CHECK_PATH}" fill="none" stroke="#ffffff"
          stroke-width="46" stroke-linecap="round" stroke-linejoin="round" />
  </g>
  <!-- onay işaretinde hafif gradyan derinlik -->
  <path d="${CHECK_PATH}" fill="none" stroke="#e0f7ff"
        stroke-opacity="0.55" stroke-width="14"
        stroke-linecap="round" stroke-linejoin="round"
        transform="translate(0 -7)" />
</svg>
</body>
</html>`;
}

function toDataUrl(html) {
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
}

/* ------------------------------------------------------------------ */
/* yardımcılar                                                         */
/* ------------------------------------------------------------------ */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function ensureBuildDir() {
  fs.mkdirSync(BUILD_DIR, { recursive: true });
}

function pngSize(file) {
  // PNG başlığı: width/height big-endian uint32 @ offset 16/20
  const buf = fs.readFileSync(file);
  if (buf.length < 24 || buf.toString('ascii', 1, 4) !== 'PNG') return null;
  return {
    width: buf.readUInt32BE(16),
    height: buf.readUInt32BE(20),
    bytes: buf.length,
  };
}

function sipsResize(src, dst, px) {
  execFileSync('sips', ['-z', String(px), String(px), src, '--out', dst], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });
}

/* ------------------------------------------------------------------ */
/* 1-2: HTML → capturePage → build/icon.png                            */
/* ------------------------------------------------------------------ */
async function captureIconPng() {
  const win = new BrowserWindow({
    width: SIZE,
    height: SIZE,
    show: false,
    frame: false,
    resizable: false,
    backgroundColor: '#070b14',
    webPreferences: {
      offscreen: true,
      backgroundThrottling: false,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const wc = win.webContents;
  let painted = null;
  wc.on('paint', (_e, _rect, image) => {
    const png = image.toPNG();
    if (png && png.length > 1024) painted = png;
  });

  await wc.loadURL(toDataUrl(buildHtml()));

  // offscreen paint'ini bekle (fallback: paint event image)
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && !painted) await sleep(100);
  await sleep(400); // CSS/filtre geçişlerinin tam oturması

  let buf = Buffer.alloc(0);
  try {
    const img = await wc.capturePage();
    const png = img.toPNG();
    if (png && png.length > 1024) buf = png;
  } catch (err) {
    console.warn('capturePage başarısız, paint event image kullanılacak:', err.message);
  }

  if (!buf || buf.length === 0) buf = painted;

  if (!buf || buf.length === 0) {
    throw new Error('Hiçbir kare yakalanamadı (capturePage ve paint boş).');
  }

  ensureBuildDir();
  fs.writeFileSync(PNG_PATH, buf);

  win.destroy();

  // Boyut doğrulaması; 1024 değilse sips ile büyüt/küçült
  const meta = pngSize(PNG_PATH);
  if (!meta) throw new Error('icon.png geçerli PNG değil.');
  if (meta.width !== SIZE || meta.height !== SIZE) {
    console.log(`capture ${meta.width}x${meta.height} → sips ile ${SIZE}x${SIZE} ayarlanıyor`);
    const resized = PNG_PATH + '.resized.png';
    sipsResize(PNG_PATH, resized, SIZE);
    fs.renameSync(resized, PNG_PATH);
  }
  return pngSize(PNG_PATH);
}

/* ------------------------------------------------------------------ */
/* 3: sips → iconset → iconutil → build/icon.icns                      */
/* ------------------------------------------------------------------ */
function buildIcns() {
  ensureBuildDir();

  if (fs.existsSync(ICONSET_DIR)) fs.rmSync(ICONSET_DIR, { recursive: true, force: true });
  fs.mkdirSync(ICONSET_DIR, { recursive: true });

  for (const [name, px] of ICONSET_SIZES) {
    sipsResize(PNG_PATH, path.join(ICONSET_DIR, name), px);
  }

  execFileSync('iconutil', ['-c', 'icns', ICONSET_DIR, '-o', ICNS_PATH], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  // iconset ara dosyalarını temizle (icon.icns ve icon.png kalmalı)
  fs.rmSync(ICONSET_DIR, { recursive: true, force: true });

  if (!fs.existsSync(ICNS_PATH)) throw new Error('icon.icns üretilemedi.');
  return fs.statSync(ICNS_PATH).size;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
async function main() {
  console.log('[make-icon] proje kökü:', ROOT);

  const meta = await captureIconPng();
  console.log(`[make-icon] build/icon.png → ${meta.width}x${meta.height}, ${meta.bytes} bayt`);

  const icnsBytes = buildIcns();
  console.log(`[make-icon] build/icon.icns → ${icnsBytes} bayt`);
  console.log('[make-icon] bitti.');
}

app.disableHardwareAcceleration();

app
  .whenReady()
  .then(async () => {
    try {
      await main();
      app.exit(0);
    } catch (err) {
      console.error('[make-icon] HATA:', err && err.stack ? err.stack : err);
      app.exit(1);
    }
  })
  .catch((err) => {
    console.error('[make-icon] HATA:', err && err.stack ? err.stack : err);
    app.exit(1);
  });
