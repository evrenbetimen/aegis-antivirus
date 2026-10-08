/* Aegis Security Suite — renderer */

// Teşhis: sessiz hataları yakala
window.__aegis = { errors: [], ready: false, hash: location.hash };
window.addEventListener('error', (e) => window.__aegis.errors.push('error: ' + e.message));
window.addEventListener('unhandledrejection', (e) =>
  window.__aegis.errors.push('rejection: ' + String((e.reason && e.reason.stack) || e.reason))
);

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const t = (...args) => window.I18N.t(...args);

const TITLES = {
  dashboard: 'page.dashboard',
  scan: 'page.scan',
  quarantine: 'page.quarantine',
  firewall: 'page.firewall',
  activity: 'page.activity',
  settings: 'page.settings'
};

// Dinamik metin sözlüğü (TR + EN) — HTML dışı betik metinleri için
const DYN = {
  tr: {
    'event.scanDone': 'Tarama tamamlandı — {files} dosya, {threats} tehdit',
    'event.permissionDenied': '{n} dizine erişilemedi (izin yok)',
    'scan.denied': '⚠ {n} dizin okunamadı — Tam Disk Erişimi izni gerekebilir',
    'event.threat': 'Tehdit: {name}',
    'event.ransomware': 'Fidye şüphesi: {kind}',
    'event.quarantineRestored': 'Karantinadan geri yüklendi',
    'event.dbUpdated': 'İmza DB güncellendi → {version}',
    'scan.progress': '{n} dosya · {bytes}',
    'scan.clean': '✓ Temiz — {files} dosya tarandı ({bytes}, {sec}s){stopped}',
    'scan.dirty': '⚠ {n} tehdit bulundu — {files} dosya tarandı ({sec}s)',
    'scan.stopped': ' · tarama durduruldu',
    'scan.noThreat': 'Tehdit bulunmadı',
    'scan.scanning': 'Taranıyor…',
    'scan.error': 'Hata: {msg}',
    'q.count': '{n} öğe',
    'q.restored': 'Geri yüklendi',
    'q.deleted': 'Silindi',
    'conn.empty': 'Aktif bağlantı yok',
    'conn.blocked': 'ENGELLENDİ',
    'conn.allowed': 'İZİN',
    'fw.resolvedIps': '{n} IP çözümlendi',
    'fw.unresolved': 'Çözümlenemedi: {reason}',
    'db.idle': 'v2026.10.1',
    'db.checking': 'Denetleniyor…',
    'db.uptodate': 'Güncel ({version} · {count} imza)',
    'db.updated': 'Güncellendi → {version} ({count} imza)',
    'db.error': 'Hata: {reason}',
    'integrity.ok': 'Sağlam: {n} kayıt',
    'integrity.bad': '⚠ {n} kayıt bozulmuş!',
    'integrity.legacy': 'Sağlam: {n} kayıt (eski sürüm {legacy})',
    'rules.empty': 'Kural yok',
    'time.now': 'şimdi',
    'time.m': '{n} dk önce',
    'time.h': '{n} sa önce',
    'time.d': '{n} gün önce',
    'runtime.pending': 'native daemon bekleniyor',
    'runtime.active': 'devrede',
    'event.shieldBlocked': 'Kalkan engelledi: {name}',
    'event.flowBlocked': 'Bağlantı engellendi: {host}',
    'fda.granted': '✓ Tam Disk Erişimi verildi',
    'fda.denied': 'Tam Disk Erişimi henüz verilmedi',
    'fda.unknown': 'Tam Disk Erişimi durumu belirlenemedi',
    'upd.version': 'Sürüm {v}',
    'upd.idle': 'Sürüm {v}',
    'upd.checking': 'Denetleniyor…',
    'upd.none': 'Güncel (sürüm {v})',
    'upd.downloading': 'Sürüm {v} indiriliyor… %{p}',
    'upd.ready': 'Sürüm {v} hazır, çıkışta kurulacak',
    'upd.error': 'Güncelleme denetlenemedi: {reason}',
    'upd.unsupported': 'Sürüm {v} · yalnızca imzalı macOS sürümünde'
  },
  en: {
    'event.scanDone': 'Scan completed — {files} files, {threats} threats',
    'event.permissionDenied': '{n} folders unreadable (permission denied)',
    'scan.denied': '⚠ {n} folders could not be read — Full Disk Access may be required',
    'event.threat': 'Threat: {name}',
    'event.ransomware': 'Ransomware suspicion: {kind}',
    'event.quarantineRestored': 'Restored from quarantine',
    'event.dbUpdated': 'Signature DB updated → {version}',
    'scan.progress': '{n} files · {bytes}',
    'scan.clean': '✓ Clean — {files} files scanned ({bytes}, {sec}s){stopped}',
    'scan.dirty': '⚠ {n} threats found — {files} files scanned ({sec}s)',
    'scan.stopped': ' · scan stopped',
    'scan.noThreat': 'No threats found',
    'scan.scanning': 'Scanning…',
    'scan.error': 'Error: {msg}',
    'q.count': '{n} items',
    'q.restored': 'Restored',
    'q.deleted': 'Deleted',
    'conn.empty': 'No active connections',
    'conn.blocked': 'BLOCKED',
    'conn.allowed': 'ALLOWED',
    'fw.resolvedIps': '{n} IPs resolved',
    'fw.unresolved': 'Could not resolve: {reason}',
    'db.idle': 'v2026.10.1',
    'db.checking': 'Checking…',
    'db.uptodate': 'Up to date ({version} · {count} signatures)',
    'db.updated': 'Updated → {version} ({count} signatures)',
    'db.error': 'Error: {reason}',
    'integrity.ok': 'Intact: {n} records',
    'integrity.bad': '⚠ {n} records tampered!',
    'integrity.legacy': 'Intact: {n} records (legacy {legacy})',
    'rules.empty': 'No rules',
    'time.now': 'now',
    'time.m': '{n} min ago',
    'time.h': '{n} h ago',
    'time.d': '{n} d ago',
    'runtime.pending': 'native daemon pending',
    'runtime.active': 'active',
    'event.shieldBlocked': 'Shield blocked: {name}',
    'event.flowBlocked': 'Connection blocked: {host}',
    'fda.granted': '✓ Full Disk Access granted',
    'fda.denied': 'Full Disk Access not granted yet',
    'fda.unknown': 'Full Disk Access status could not be determined',
    'upd.version': 'Version {v}',
    'upd.idle': 'Version {v}',
    'upd.checking': 'Checking…',
    'upd.none': 'Up to date (version {v})',
    'upd.downloading': 'Downloading version {v}… {p}%',
    'upd.ready': 'Version {v} is ready and will install when you quit',
    'upd.error': 'Could not check for updates: {reason}',
    'upd.unsupported': 'Version {v} · signed macOS build only'
  }
};

function d(key, vars) {
  const lang = window.I18N.getLanguage();
  let s = (DYN[lang] && DYN[lang][key]) || (DYN.tr && DYN.tr[key]) || key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) s = s.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
  }
  return s;
}

const TCC_URL = 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles';

let scanMode = 'quick';
let settings = null;
let connTimer = null;
let runtime = null;

/* ---------- Gezinme ---------- */
function goto(page) {
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  $('#page-title').textContent = t(TITLES[page] || '');

  clearInterval(connTimer);
  connTimer = null;
  if (page === 'firewall') {
    loadConnections();
    connTimer = setInterval(loadConnections, 5000);
  }
  if (page === 'quarantine') loadQuarantine();
  if (page === 'activity') loadEvents();
  if (page === 'dashboard') refreshDashboard();
  if (page === 'scan') loadHistory();
}

$$('.nav-item').forEach((b) => b.addEventListener('click', () => goto(b.dataset.page)));
$$('[data-goto]').forEach((b) => b.addEventListener('click', () => goto(b.dataset.goto)));

/* ---------- Biçimlendirme ---------- */
function fmtNum(n) {
  return new Intl.NumberFormat(window.I18N.getLanguage() === 'en' ? 'en-US' : 'tr-TR').format(n || 0);
}
function fmtBytes(b) {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log2(b) / 10));
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}
function fmtTime(ts) {
  if (!ts) return '—';
  const dte = new Date(ts);
  return dte.toLocaleString(window.I18N.getLanguage() === 'en' ? 'en-US' : 'tr-TR', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit'
  });
}
function relTime(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return d('time.now');
  if (s < 3600) return d('time.m', { n: Math.floor(s / 60) });
  if (s < 86400) return d('time.h', { n: Math.floor(s / 3600) });
  return d('time.d', { n: Math.floor(s / 86400) });
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function renderEvent(e) {
  if (e.i18n) {
    return { title: d(e.i18n.key, e.i18n.vars || {}), detail: e.detail || '' };
  }
  // i18n alanından önce kaydedilmiş eski kayıtlar — İngilizce arayüzde çevir
  if (window.I18N.getLanguage() === 'en') {
    const title = e.title || '';
    if (title === 'Tarama tamamlandı') {
      const m = /(\d+) dosya tarandı, (\d+) tehdit/.exec(e.detail || '');
      return { title: d('event.scanDone', { files: m ? m[1] : 0, threats: m ? m[2] : 0 }), detail: '' };
    }
    if (title.startsWith('Tehdit: ')) {
      return { title: d('event.threat', { name: title.slice(8) }), detail: e.detail || '' };
    }
    if (title === 'Karantinadan geri yüklendi') {
      return { title: d('event.quarantineRestored'), detail: e.detail || '' };
    }
    if (title.startsWith('İmza DB')) {
      return { title: d('event.dbUpdated', { version: e.detail || '' }), detail: '' };
    }
    if (/fidye/i.test(title)) {
      return { title: d('event.ransomware', { kind: title.split(':').pop().trim() }), detail: e.detail || '' };
    }
  }
  return { title: e.title, detail: e.detail || '' };
}

/* ---------- Gerçek zamanlı kalkan (native daemon) ---------- */
function shieldLive() {
  return !!(settings && settings.realtimeEnabled && runtime && runtime.native && runtime.native.connected);
}

function paintShieldModule() {
  const el = $('#module-realtime-status');
  if (!el) return;
  const live = shieldLive();
  el.classList.toggle('ok', live);
  el.classList.toggle('warn', !live);
  const ico = el.parentElement && el.parentElement.querySelector('.module-ico');
  if (ico) {
    ico.classList.toggle('ok', live);
    ico.classList.toggle('warn', !live);
  }
  el.setAttribute('data-i18n', live ? 'status.active' : 'status.standby');
  el.dataset.i18nOrig = live ? 'Aktif' : 'Beklemede';
  el.textContent = t(live ? 'status.active' : 'status.standby');
  const hero = $('#hero-sub');
  hero.setAttribute('data-i18n', live ? 'hero.subLive' : 'hero.sub');
  hero.dataset.i18nOrig = live
    ? 'Gerçek zamanlı kalkan, tarama ve firewall aktif'
    : 'Gerçek zamanlı kalkan: native daemon bekleniyor · Tarama ve firewall aktif';
  hero.textContent = window.I18N.getLanguage() === 'tr' ? hero.dataset.i18nOrig : t(hero.getAttribute('data-i18n'));
}

// Genişletme sonradan bağlanabilir: durumu düzenli yenile
setInterval(async () => {
  try {
    runtime = await window.api.getRuntime();
    if ($('#page-dashboard').classList.contains('active')) refreshDashboard();
    else paintShieldModule();
  } catch {}
}, 15000);

/* ---------- Dashboard ---------- */
async function refreshDashboard() {
  paintShieldModule();
  const stats = await window.api.getStats();
  $('#stat-scanned').textContent = fmtNum(stats.filesScanned);
  $('#stat-threats').textContent = fmtNum(stats.threatsFound);
  $('#stat-lastscan').textContent = stats.lastScan ? relTime(stats.lastScan) : '—';

  const q = await window.api.quarantineList();
  $('#stat-quarantine').textContent = fmtNum(q.length);
  updateBadge('#nav-quarantine-badge', q.length);

  const score = Math.max(35, 100 - Math.min(45, q.length * 8) - (shieldLive() ? 0 : 14));
  setScore(score);

  // Fidye izleyici durumu
  if (runtime && runtime.honeypot) {
    const tag = $('#module-honeypot-status');
    if (tag) {
      const on = runtime.honeypot.running;
      tag.textContent = on ? t('status.watch') : t('status.disabled');
      tag.className = 'status-tag ' + (on ? 'ok' : 'bad');
    }
  }

  const events = await window.api.getEvents();
  renderFeed($('#dash-feed'), events.slice(0, 6));
}

function setScore(v) {
  $('#score-value').textContent = v;
  const c = 2 * Math.PI * 52;
  const fg = $('#ring-fg');
  fg.style.strokeDasharray = c;
  fg.style.strokeDashoffset = c - (v / 100) * c;
  fg.style.stroke = v >= 80 ? 'var(--green)' : v >= 60 ? 'var(--amber)' : 'var(--red)';
}

function updateBadge(sel, n) {
  const el = $(sel);
  if (!el) return;
  el.hidden = n === 0;
  el.textContent = n;
}

function renderFeed(el, events) {
  if (!events || events.length === 0) {
    el.innerHTML = '<div class="feed-empty">' + esc(t('feed.empty')) + '</div>';
    return;
  }
  el.innerHTML = events
    .map((e) => {
      const r = renderEvent(e);
      return `
    <div class="feed-item">
      <span class="feed-dot ${e.type === 'threat' || e.type === 'ransomware' ? 'threat' : e.type === 'scan' ? 'scan' : 'info'}"></span>
      <div style="min-width:0">
        <strong>${esc(r.title)}</strong>
        <span>${esc(r.detail)}</span>
      </div>
      <time>${relTime(e.ts)}</time>
    </div>`;
    })
    .join('');
}

async function loadEvents() {
  renderFeed($('#activity-feed'), await window.api.getEvents());
}
$('#btn-refresh-events').addEventListener('click', loadEvents);

// Ana süreçten gelen canlı olaylar
window.api.onEvent(() => {
  const active = $('.page.active');
  if (active && (active.id === 'page-dashboard')) refreshDashboard();
  if (active && (active.id === 'page-activity')) loadEvents();
});

/* ---------- Tarama ---------- */
$$('.mode-card').forEach((c) =>
  c.addEventListener('click', () => {
    $$('.mode-card').forEach((x) => x.classList.remove('active'));
    c.classList.add('active');
    scanMode = c.dataset.mode;
  })
);

function scanningUi(on) {
  $('#btn-start-scan').hidden = on;
  $('#btn-stop-scan').hidden = !on;
  $('#scan-progress').hidden = !on;
  if (on) $('#scan-summary').hidden = true;
}

async function startScan() {
  let paths = [];
  if (scanMode === 'custom') {
    paths = await window.api.scanCustomPaths();
    if (!paths.length) return;
  }
  const res = await window.api.scanStart({ paths });
  if (!res.ok) return;
  scanningUi(true);
  $('#results-body').innerHTML = `<tr class="empty-row"><td colspan="3">${esc(d('scan.scanning'))}</td></tr>`;
}

$('#btn-start-scan').addEventListener('click', startScan);
$('#top-quick-scan').addEventListener('click', () => {
  goto('scan');
  startScan();
});
$('#btn-stop-scan').addEventListener('click', () => window.api.scanStop());

$('#btn-eicar-test').addEventListener('click', async () => {
  const p = await window.api.createEicar();
  scanMode = 'custom';
  $$('.mode-card').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'custom'));
  const res = await window.api.scanStart({ paths: [p] });
  if (res.ok) scanningUi(true);
});

window.api.onScanProgress((p) => {
  $('#progress-count').textContent = d('scan.progress', { n: fmtNum(p.filesScanned), bytes: fmtBytes(p.bytesScanned) });
  $('#progress-elapsed').textContent = (p.elapsed / 1000).toFixed(1) + 's';
  $('#progress-file').textContent = p.file;
  const pct = p.total ? Math.min(99, (p.filesScanned / p.total) * 100) : Math.min(95, (p.filesScanned % 200) / 2);
  $('#progress-fill').style.width = pct + '%';
});

let liveThreats = [];

window.api.onScanDone(async (report) => {
  scanningUi(false);
  $('#progress-fill').style.width = '100%';

  const sum = $('#scan-summary');
  sum.hidden = false;
  const stopped = report.stopped ? d('scan.stopped') : '';
  let text;
  if (report.threats.length === 0) {
    sum.className = 'scan-result-summary clean';
    text = d('scan.clean', {
      files: fmtNum(report.filesScanned),
      bytes: fmtBytes(report.bytesScanned),
      sec: (report.duration / 1000).toFixed(1),
      stopped
    });
  } else {
    sum.className = 'scan-result-summary dirty';
    text = d('scan.dirty', {
      n: report.threats.length,
      files: fmtNum(report.filesScanned),
      sec: (report.duration / 1000).toFixed(1)
    });
  }

  // İzin verilmeyen dizinler varsa Tam Disk Erişimi uyarısı göster
  let html = esc(text);
  if (report.deniedCount > 0) {
    html += `<div class="scan-denied">${esc(d('scan.denied', { n: report.deniedCount }))}
      <button class="btn ghost sm" id="btn-denied-tcc">${esc(t('set.tcc.open'))}</button></div>`;
  }
  sum.innerHTML = html;
  const deniedBtn = $('#btn-denied-tcc');
  if (deniedBtn) deniedBtn.addEventListener('click', () => window.api.openExternal(TCC_URL));

  liveThreats = report.threats;
  renderResults();
  updateBadge('#nav-threat-badge', report.threats.length);
  refreshDashboard();
  await loadHistory();
});

window.api.onScanError((m) => {
  scanningUi(false);
  const sum = $('#scan-summary');
  sum.hidden = false;
  sum.className = 'scan-result-summary dirty';
  sum.textContent = d('scan.error', { msg: m });
});

function renderResults() {
  const body = $('#results-body');
  if (liveThreats.length === 0) {
    body.innerHTML = `<tr class="empty-row"><td colspan="3">${esc(d('scan.noThreat'))}</td></tr>`;
    return;
  }
  const quarantineLabel = t('scan.inQuarantine');
  const flaggedLabel = t('scan.flagged');
  const openLabel = t('scan.openFolder');
  body.innerHTML = liveThreats
    .map(
      (th, i) => `
    <tr>
      <td><div class="cell-path" title="${esc(th.path)}">${esc(th.path)}</div>
          <div class="muted">${th.hash ? 'SHA-256: ' + esc(th.hash.slice(0, 24)) + '…' : ''}</div></td>
      <td><span class="row-danger">${esc(th.threat)}</span><div class="muted">${esc(th.detail || '')}</div></td>
      <td>
        ${th.quarantined ? `<span class="row-ok">${esc(quarantineLabel)}</span>` : `<span class="row-muted">${esc(flaggedLabel)}</span>`}
        <div class="cell-actions" style="margin-top:7px">
          <button class="btn ghost sm" data-open="${i}">${esc(openLabel)}</button>
        </div>
      </td>
    </tr>`
    )
    .join('');

  body.querySelectorAll('[data-open]').forEach((b) =>
    b.addEventListener('click', () => {
      const th = liveThreats[Number(b.dataset.open)];
      window.api.openPath(th.path);
    })
  );
}

/* ---------- Tarama geçmişi ---------- */
const HISTORY_MODE_KEYS = {
  quick: 'history.mode.quick',
  custom: 'history.mode.custom',
  scheduled: 'history.mode.scheduled'
};
const HISTORY_COLS = 5;
let historyRows = [];

function historyStatus(key, vars) {
  const el = $('#history-status');
  if (!el) return;
  if (!key) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.textContent = t(key, vars);
}

function historyDetailHtml(h) {
  const threats = Array.isArray(h.threats) ? h.threats : [];
  const shown = threats.slice(0, 10);
  const total = Number(h.threatCount) || threats.length;
  const rest = Math.max(0, total - shown.length);
  const quarantineLabel = t('scan.inQuarantine');
  const items = shown
    .map(
      (th) => `<div class="history-threat">
        <span class="tag block">${esc(th.threat)}</span>
        <span class="cell-path" title="${esc(th.path)}">${esc(th.path)}</span>
        ${th.quarantined ? `<span class="row-ok">${esc(quarantineLabel)}</span>` : ''}
      </div>`
    )
    .join('');
  const more = rest > 0 ? `<div class="muted">${esc(t('history.moreThreats', { n: fmtNum(rest) }))}</div>` : '';
  return `<div class="history-detail-body">${items}${more}</div>`;
}

function toggleHistoryDetail(row, index) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains('history-detail')) {
    next.parentNode.removeChild(next);
    row.classList.remove('open');
    return;
  }
  const h = historyRows[index];
  if (!h) return;
  const detail = document.createElement('tr');
  detail.className = 'history-detail';
  const cell = document.createElement('td');
  cell.colSpan = HISTORY_COLS;
  cell.innerHTML = historyDetailHtml(h);
  detail.appendChild(cell);
  row.parentNode.insertBefore(detail, row.nextElementSibling);
  row.classList.add('open');
}

function renderHistory() {
  const body = $('#history-body');
  if (!body) return;
  if (!historyRows.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="${HISTORY_COLS}">${esc(t('history.empty'))}</td></tr>`;
    return;
  }
  const stoppedLabel = t('history.stopped');
  const deniedLabel = (n) => t('history.denied', { n });
  body.innerHTML = historyRows
    .map((h, i) => {
      const threats = Number(h.threatCount) || 0;
      const denied = Number(h.deniedCount) > 0;
      const modeLabel = t(HISTORY_MODE_KEYS[h.mode] || HISTORY_MODE_KEYS.quick);
      const seconds = (Math.max(0, Number(h.duration) || 0) / 1000).toFixed(1);
      return `
    <tr class="history-row${threats > 0 ? ' clickable' : ''}" data-hist="${i}">
      <td class="row-muted">${fmtTime(h.at)}</td>
      <td><span class="tag hist-mode">${esc(modeLabel)}</span>${
        h.stopped ? `<span class="tag hist-stopped">${esc(stoppedLabel)}</span>` : ''
      }</td>
      <td>${fmtNum(h.filesScanned)}${
        denied
          ? `<span class="tag hist-denied" title="${esc(deniedLabel(fmtNum(h.deniedCount)))}">⚠ ${esc(
              fmtNum(h.deniedCount)
            )}</span>`
          : ''
      }</td>
      <td>${
        threats > 0 ? `<span class="row-danger">${fmtNum(threats)}</span>` : esc(fmtNum(threats))
      }</td>
      <td class="row-muted">${seconds}s</td>
    </tr>`;
    })
    .join('');

  body.querySelectorAll('tr.history-row[data-hist]').forEach((row) => {
    const index = Number(row.dataset.hist);
    const h = historyRows[index];
    if (!h || !(Number(h.threatCount) > 0)) return;
    row.addEventListener('click', () => toggleHistoryDetail(row, index));
  });
}

async function loadHistory() {
  const body = $('#history-body');
  if (!body) return;
  let rows = [];
  try {
    rows = await window.api.scanHistory();
  } catch (err) {
    window.__aegis.errors.push('loadHistory: ' + String((err && err.stack) || err));
  }
  historyRows = Array.isArray(rows) ? rows : [];
  renderHistory();
}

async function exportHistory(format) {
  try {
    const res = await window.api.scanHistoryExport(format);
    if (res && res.ok) historyStatus(null);
    else if (res && res.canceled) historyStatus('history.export.canceled');
    else historyStatus('history.export.failed', { error: (res && res.error) || '—' });
  } catch (err) {
    historyStatus('history.export.failed', { error: String((err && err.message) || err) });
    window.__aegis.errors.push('exportHistory: ' + String((err && err.stack) || err));
  }
}

$('#btn-hist-json').addEventListener('click', () => exportHistory('json'));
$('#btn-hist-csv').addEventListener('click', () => exportHistory('csv'));
$('#btn-hist-clear').addEventListener('click', async () => {
  try {
    await window.api.scanHistoryClear();
  } catch (err) {
    window.__aegis.errors.push('clearHistory: ' + String((err && err.stack) || err));
  }
  historyStatus(null);
  await loadHistory();
});

/* ---------- Karantina ---------- */
async function loadQuarantine() {
  const items = await window.api.quarantineList();
  updateBadge('#nav-quarantine-badge', items.length);
  $('#quarantine-count').textContent = d('q.count', { n: items.length });

  // Bütünlük rozeti
  const tag = $('#q-integrity-tag');
  if (tag) {
    const bad = items.filter((x) => x.intact === false).length;
    if (bad > 0) {
      tag.textContent = d('integrity.bad', { n: bad });
      tag.className = 'status-tag bad';
    } else {
      tag.textContent = t('q.integrityOk');
      tag.className = 'status-tag ok';
    }
  }

  const body = $('#quarantine-body');
  if (items.length === 0) {
    body.innerHTML = `<tr class="empty-row"><td colspan="4">${esc(t('q.empty'))}</td></tr>`;
    return;
  }
  const restoreLabel = t('q.restore');
  const deleteLabel = t('q.delete');
  body.innerHTML = items
    .map(
      (q) => `
    <tr>
      <td><span class="row-danger">${esc(q.threat)}</span><div class="muted">${esc(q.detail || '')}</div>
          ${q.intact === false ? `<span class="status-tag bad">${esc(d('integrity.bad', { n: 1 }))}</span>` : ''}</td>
      <td><div class="cell-path" title="${esc(q.originalPath)}">${esc(q.originalPath)}</div></td>
      <td class="row-muted">${fmtTime(q.quarantinedAt)}</td>
      <td>
        <div class="cell-actions">
          <button class="btn ghost sm" data-restore="${esc(q.id)}">${esc(restoreLabel)}</button>
          <button class="btn danger sm" data-del="${esc(q.id)}">${esc(deleteLabel)}</button>
        </div>
      </td>
    </tr>`
    )
    .join('');

  body.querySelectorAll('[data-restore]').forEach((b) =>
    b.addEventListener('click', async () => {
      await window.api.quarantineRestore(b.dataset.restore);
      loadQuarantine();
      refreshDashboard();
    })
  );
  body.querySelectorAll('[data-del]').forEach((b) =>
    b.addEventListener('click', async () => {
      await window.api.quarantineDelete(b.dataset.del);
      loadQuarantine();
      refreshDashboard();
    })
  );
}

/* ---------- Firewall ---------- */
let cachedRules = [];
let lastResolutions = {}; // host -> {ips, error} (getConnections'tan gelir)

async function loadRules() {
  cachedRules = await window.api.firewallRules();
  renderRulesBody();
  // DNS durumunu lsof'tan bağımsız iste (kural tablosu hemen bilgilensin)
  try {
    const res = await window.api.firewallResolve();
    if (res && Object.keys(res).length) {
      lastResolutions = Object.assign({}, lastResolutions, res);
      renderRulesBody();
    }
  } catch {}
}

function renderRulesBody() {
  const rules = cachedRules;
  const body = $('#rules-body');
  const deleteLabel = t('fw.delete');
  const blockLabel = t('fw.block');
  const allowLabel = t('fw.allow');
  const allLabel = t('fw.all');
  if (!rules.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="5">${esc(d('rules.empty'))}</td></tr>`;
    return;
  }
  body.innerHTML = rules
    .map((r) => {
      // Domain kuralının DNS çözüm durumu (dürüst geri bildirim)
      let hostSub = '';
      if (r.host && lastResolutions[r.host]) {
        const res = lastResolutions[r.host];
        if (res.error) {
          hostSub = `<div class="muted warn-text">${esc(d('fw.unresolved', { reason: res.error }))}</div>`;
        } else if (res.ips && res.ips.length) {
          hostSub = `<div class="muted">${esc(d('fw.resolvedIps', { n: res.ips.length }))}: ${esc(res.ips.slice(0, 3).join(', '))}${res.ips.length > 3 ? '…' : ''}</div>`;
        }
      }
      return `
    <tr>
      <td><span class="tag ${r.type === 'block' ? 'block' : 'allow'}">${r.type === 'block' ? esc(blockLabel) : esc(allowLabel)}</span></td>
      <td>${esc(r.host || '*')}${hostSub}</td>
      <td class="row-muted">${r.port ? esc(r.port) : esc(allLabel)}</td>
      <td class="row-muted">${esc(r.note || '')}</td>
      <td><div class="cell-actions"><button class="btn ghost sm" data-rule-del="${esc(r.id)}">${esc(deleteLabel)}</button></div></td>
    </tr>`;
    })
    .join('');

  body.querySelectorAll('[data-rule-del]').forEach((b) =>
    b.addEventListener('click', async () => {
      const current = await window.api.firewallRules();
      await window.api.firewallSetRules(current.filter((r) => r.id !== b.dataset.ruleDel));
      loadRules();
      loadConnections();
    })
  );
}

$('#btn-add-rule').addEventListener('click', () => {
  $('#rule-form').hidden = !$('#rule-form').hidden;
});
$('#btn-cancel-rule').addEventListener('click', () => {
  $('#rule-form').hidden = true;
  $('#rule-form').reset();
});
$('#rule-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const current = await window.api.firewallRules();
  current.push({
    id: 'r' + Date.now().toString(36),
    type: $('#rule-type').value,
    host: $('#rule-host').value.trim() || null,
    port: $('#rule-port').value.trim() ? Number($('#rule-port').value.trim()) : null,
    note: $('#rule-note').value.trim()
  });
  await window.api.firewallSetRules(current);
  $('#rule-form').reset();
  $('#rule-form').hidden = true;
  loadRules();
  loadConnections();
});

async function loadConnections() {
  const data = await window.api.firewallConnections();
  lastResolutions = data.resolutions || {};
  if (cachedRules.length) renderRulesBody(); // kural tablosuna DNS durumunu yansıt
  const body = $('#conns-body');
  if (!data.connections.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="4">${esc(d('conn.empty'))}</td></tr>`;
    return;
  }
  const blockedLabel = d('conn.blocked');
  const allowedLabel = d('conn.allowed');
  body.innerHTML = data.connections
    .map((c) => {
      const verdict =
        c.verdict === 'blocked'
          ? `<span class="tag block">${esc(blockedLabel)}</span>`
          : c.verdict === 'allowed'
          ? `<span class="tag allow">${esc(allowedLabel)}</span>`
          : '<span class="row-muted">—</span>';
      return `<tr>
        <td>${esc(c.process)}<div class="muted">PID ${esc(c.pid)}</div></td>
        <td><span class="conn-remote" title="${esc(c.remote)}">${esc(c.remote)}</span></td>
        <td class="row-muted">${esc(c.port)}</td>
        <td>${verdict}</td>
      </tr>`;
    })
    .join('');
}
$('#btn-refresh-conns').addEventListener('click', loadConnections);

$('#fw-toggle').addEventListener('change', async (e) => {
  await window.api.setSettings({ firewallEnabled: e.target.checked });
  settings = await window.api.getSettings();
  updateFirewallUi();
  loadConnections();
});

function updateFirewallUi() {
  const on = settings.firewallEnabled;
  $('#fw-toggle').checked = on;
  const tag = $('#fw-banner-status');
  tag.textContent = on ? t('status.active') : t('status.disabled');
  tag.className = 'status-tag ' + (on ? 'ok' : 'bad');
  const mod = $('#module-fw-status');
  if (mod) {
    mod.textContent = tag.textContent;
    mod.className = tag.className;
  }
}

/* ---------- Ayarlar ---------- */
async function loadSettings() {
  settings = await window.api.getSettings();
  $('#set-auto-quarantine').checked = settings.autoQuarantine;
  $('#set-heuristics').checked = settings.heuristics;
  $('#set-notifications').checked = settings.notifications;
  $('#set-firewall').checked = settings.firewallEnabled;
  $('#set-realtime').checked = !!settings.realtimeEnabled;
  $('#set-archives').checked = !!settings.scanArchives;
  $('#set-honeypot').checked = !!settings.honeypotEnabled;
  $('#set-scheduled').checked = !!settings.scheduledScan;
  $('#set-interval').value = settings.scanIntervalHours || 24;
  $('#set-db-url').value = settings.dbUrl || '';
  $('#set-db-auto').checked = !!settings.dbAutoUpdate;
  $('#set-app-auto').checked = settings.appAutoUpdate !== false;
  $('#set-language').value = settings.language || 'tr';
  updateFirewallUi();
  renderExclusions();
}

const bind = (sel, key) =>
  $(sel).addEventListener('change', async (e) => {
    await window.api.setSettings({ [key]: e.target.checked });
    settings = await window.api.getSettings();
    updateFirewallUi();
    runtime = await window.api.getRuntime();
    refreshDashboard();
  });

bind('#set-auto-quarantine', 'autoQuarantine');
bind('#set-heuristics', 'heuristics');
bind('#set-notifications', 'notifications');
bind('#set-firewall', 'firewallEnabled');
bind('#set-archives', 'scanArchives');
bind('#set-honeypot', 'honeypotEnabled');
bind('#set-realtime', 'realtimeEnabled');
bind('#set-scheduled', 'scheduledScan');
bind('#set-db-auto', 'dbAutoUpdate');
bind('#set-app-auto', 'appAutoUpdate');

$('#set-interval').addEventListener('change', async (e) => {
  const v = Math.max(1, Math.min(168, Number(e.target.value) || 24));
  e.target.value = v;
  await window.api.setSettings({ scanIntervalHours: v });
});

$('#set-db-url').addEventListener('change', async (e) => {
  await window.api.setSettings({ dbUrl: e.target.value.trim() });
});

/* ---------- Dışlamalar ---------- */
function renderExclusions() {
  const box = $('#exclusions-list');
  if (!box) return;
  const list = (settings && settings.exclusions) || [];
  if (!list.length) {
    box.innerHTML = `<div class="muted exclusions-empty">${esc(t('set.exclusions.empty'))}</div>`;
    return;
  }
  const removeLabel = t('set.exclusions.remove');
  box.innerHTML = list
    .map(
      (p, i) => `<div class="chip-row">
        <span class="cell-path" title="${esc(p)}">${esc(p)}</span>
        <button class="btn ghost sm" data-excl="${i}" title="${esc(removeLabel)}" aria-label="${esc(removeLabel)}">✕</button>
      </div>`
    )
    .join('');
  box.querySelectorAll('[data-excl]').forEach((b) =>
    b.addEventListener('click', async () => {
      const cur = ((settings && settings.exclusions) || []).slice();
      cur.splice(Number(b.dataset.excl), 1);
      settings = await window.api.setSettings({ exclusions: cur });
      renderExclusions();
    })
  );
}

$('#btn-add-exclusion').addEventListener('click', async () => {
  const dirs = await window.api.scanCustomPaths(); // klasör seçici diyalog
  if (!dirs || !dirs.length) return;
  const cur = ((settings && settings.exclusions) || []).slice();
  for (const dir of dirs) if (!cur.includes(dir)) cur.push(dir);
  settings = await window.api.setSettings({ exclusions: cur });
  renderExclusions();
});

$('#set-language').addEventListener('change', async (e) => {
  const lang = e.target.value;
  await window.api.setSettings({ language: lang });
  applyLanguage(lang);
});

function applyLanguage(lang) {
  window.I18N.setLanguage(lang);
  window.I18N.applyDom();
  // Sayfadaki dinamik içerikleri yenile
  gotoCurrent();
  if (settings) updateFirewallUi();
}

function gotoCurrent() {
  const active = $('.page.active');
  const page = active ? active.id.replace('page-', '') : 'dashboard';
  goto(page);
}

/* ---------- İmza DB güncelleme ---------- */
async function refreshDbStatus(prefix) {
  const el = $('#db-update-status');
  if (!el) return;
  if (prefix) {
    el.textContent = prefix;
    return;
  }
  const info = await window.api.dbInfo();
  el.textContent = info.version
    ? `${info.version} · ${info.count} imza${info.skipped ? ` · ${info.skipped} atlandı` : ''}`
    : t('db.error', { reason: info.reason || '—' });
}

$('#btn-db-update').addEventListener('click', async () => {
  const btn = $('#btn-db-update');
  btn.disabled = true;
  await refreshDbStatus(d('db.checking'));
  const res = await window.api.dbUpdate();
  await refreshDbStatus(res.ok ? null : t('db.error', { reason: res.reason || '—' }));
  if (res.ok && res.changed) {
    window.api.getEvents && loadEvents();
  }
  btn.disabled = false;
});

/* ---------- Bütünlük denetimi ---------- */
$('#btn-integrity').addEventListener('click', async () => {
  const el = $('#integrity-status');
  const rep = await window.api.quarantineIntegrity();
  el.textContent =
    rep.tampered > 0
      ? d('integrity.bad', { n: rep.tampered })
      : d('integrity.legacy', { n: rep.intact, legacy: rep.legacy });
  el.style.color = rep.tampered > 0 ? 'var(--red)' : '';
});

/* ---------- Uygulama güncellemesi ---------- */
let appUpdate = { state: 'idle' };

function paintUpdate(s) {
  appUpdate = Object.assign({}, appUpdate, s);
  const cur = appUpdate.current || '';
  const v = appUpdate.version || cur;
  $('#app-version').textContent = d('upd.version', { v: cur });
  $('#app-update-status').textContent = d('upd.' + appUpdate.state, {
    v,
    p: appUpdate.percent || 0,
    reason: appUpdate.reason || '—'
  });
  $('#btn-app-install').hidden = appUpdate.state !== 'ready';
  $('#btn-app-update').disabled = appUpdate.state === 'checking' || appUpdate.state === 'downloading';
}

window.api.onUpdateStatus(paintUpdate);
$('#btn-app-update').addEventListener('click', async () => paintUpdate(await window.api.updateCheck()));
$('#btn-app-install').addEventListener('click', () => window.api.updateInstall());

/* ---------- TCC / Tam Disk Erişimi ---------- */
$('#btn-tcc').addEventListener('click', () => {
  window.api.openExternal(TCC_URL);
});

let fdaStatus = 'unsupported';

function paintFda(el, status) {
  if (!el) return;
  el.classList.toggle('ok', status === 'granted');
  el.classList.toggle('bad', status === 'denied');
  el.textContent = status === 'unsupported' ? '' : d('fda.' + status);
}

async function refreshFda() {
  try {
    fdaStatus = (await window.api.fdaStatus()).status;
  } catch {
    fdaStatus = 'unknown';
  }
  paintFda($('#tcc-status'), fdaStatus);
  paintFda($('#fda-state'), $('#fda-modal').hidden ? 'unsupported' : fdaStatus);
  return fdaStatus;
}

async function closeFdaModal() {
  $('#fda-modal').hidden = true;
  await window.api.setSettings({ fdaOnboardingDone: true });
  settings = await window.api.getSettings();
}

$('#fda-open').addEventListener('click', () => window.api.openExternal(TCC_URL));
$('#fda-later').addEventListener('click', closeFdaModal);
$('#fda-recheck').addEventListener('click', async () => {
  if ((await refreshFda()) === 'granted') setTimeout(closeFdaModal, 1200);
});
// Kullanıcı Sistem Ayarları'ndan dönünce durumu yenile
window.addEventListener('focus', async () => {
  if (fdaStatus === 'unsupported') return;
  const before = fdaStatus;
  const now = await refreshFda();
  if (!$('#fda-modal').hidden && now === 'granted' && before !== 'granted') setTimeout(closeFdaModal, 1200);
});

// İlk açılış: izin yoksa ve tanıtım daha önce kapatılmadıysa göster
async function maybeShowFdaOnboarding() {
  const status = await refreshFda();
  if (status === 'denied' && settings && !settings.fdaOnboardingDone) {
    $('#fda-modal').hidden = false;
    paintFda($('#fda-state'), status);
  }
}

/* ---------- Başlangıç ---------- */
(async function init() {
  try {
    await loadSettings();
    window.I18N.setLanguage((settings && settings.language) || 'tr');
    window.I18N.applyDom();
    runtime = await window.api.getRuntime();
    await refreshDashboard();
    await loadHistory();
    await loadRules();
    await refreshDbStatus();
    paintUpdate(await window.api.appVersion());
    await maybeShowFdaOnboarding();
    const m = (location.hash || '').match(/^#(\w+)$/);
    if (m && TITLES[m[1]]) goto(m[1]);
    window.__aegis.ready = true;
  } catch (err) {
    window.__aegis.errors.push('init: ' + String((err && err.stack) || err));
  }
})();
