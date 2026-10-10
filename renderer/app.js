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
  audit: 'page.audit',
  startup: 'page.startup',
  identity: 'page.identity',
  activity: 'page.activity',
  settings: 'page.settings'
};

// Tüm metinler locales/<dil>.js sözlüklerinden gelir
const d = t;

/**
 * Bir öğenin metnini ayarlar. Değişkensiz metinlerde data-i18n anahtarı
 * güncellenir (dil değişince applyDom doğru metni yazar); değişkenli
 * metinler dil değişiminde yeniden çizilir.
 */
function setText(el, key, vars) {
  if (!el) return;
  if (vars) {
    el.removeAttribute('data-i18n');
    el.textContent = t(key, vars);
  } else {
    el.setAttribute('data-i18n', key);
    el.textContent = t(key);
  }
}

let toastTimer = null;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2600);
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
  setText($('#page-title'), TITLES[page] || 'page.dashboard');
  setText($('#page-sub'), 'pagesub.' + (TITLES[page] ? page : 'dashboard'));

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
  if (page === 'audit') renderAudit();
  if (page === 'startup') {
    if (startupData) renderStartup();
    else loadStartup();
  }
  if (page === 'identity') paintStrength();
}

$$('.nav-item').forEach((b) => b.addEventListener('click', () => goto(b.dataset.page)));
document.addEventListener('click', (e) => {
  const g = e.target.closest('[data-goto]');
  if (g) goto(g.dataset.goto);
  const a = e.target.closest('[data-action="quick-scan"]');
  if (a) quickScan();
});

/* ---------- Biçimlendirme ---------- */
function fmtNum(n) {
  return window.I18N.formatNumber(n);
}
function fmtBytes(b) {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log2(b) / 10));
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}
function fmtTime(ts) {
  if (!ts) return '—';
  return window.I18N.formatDate(ts);
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
  // i18n alanından önce Türkçe kaydedilmiş eski kayıtlar — diğer dillerde çevir
  if (window.I18N.getLanguage() !== 'tr') {
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
  el.className = 'status-tag ' + (live ? 'ok' : 'warn');
  const ico = $('#module-realtime-ico');
  if (ico) ico.className = 'module-ico ' + (live ? 'ok' : 'warn');
  setText(el, live ? 'status.active' : 'status.standby');
}

// Genişletme sonradan bağlanabilir: durumu düzenli yenile
setInterval(async () => {
  try {
    runtime = await window.api.getRuntime();
    if ($('#page-dashboard').classList.contains('active')) refreshDashboard();
    else paintShieldModule();
  } catch {}
}, 15000);

/* ---------- Güvenlik merkezi ---------- */
const DAY = 86400000;
let auditData = null; // sysaudit.audit() sonucu
let startupData = null; // startup-items.list() sonucu
let dbInfoCache = null;
let lastStats = {};

const ICONS = {
  ok: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></svg>',
  warn: '<svg viewBox="0 0 24 24"><path d="M12 7v6M12 17h.01"/></svg>',
  bad: '<svg viewBox="0 0 24 24"><path d="M7 7l10 10M17 7L7 17"/></svg>',
  info: '<svg viewBox="0 0 24 24"><path d="M12 11v6M12 7h.01"/></svg>',
  na: '<svg viewBox="0 0 24 24"><path d="M7 12h10"/></svg>'
};

const FIXES = {
  enableRealtime: async () => {
    await window.api.setSettings({ realtimeEnabled: true });
    await reloadState();
  },
  enableFirewall: async () => {
    await window.api.setSettings({ firewallEnabled: true });
    await reloadState();
  },
  enableHoneypot: async () => {
    await window.api.setSettings({ honeypotEnabled: true });
    await reloadState();
  },
  enableAutoQuarantine: async () => {
    await window.api.setSettings({ autoQuarantine: true });
    await reloadState();
  },
  scan: () => quickScan(),
  grantFda: () => window.api.openExternal(TCC_URL),
  audit: () => goto('audit'),
  startup: () => goto('startup'),
  settings: () => goto('settings')
};

async function reloadState() {
  settings = await window.api.getSettings();
  runtime = await window.api.getRuntime();
  loadSettingsUi();
  refreshDashboard();
}

/**
 * Önerilecek işlemler. Ağırlık puandan düşülür; 'info' düzeyi bandı
 * sarıya çevirmez (ör. Apple onayı bekleyen gerçek zamanlı kalkan).
 */
function computeIssues() {
  const out = [];
  const s = settings || {};
  if (!s.realtimeEnabled) {
    out.push({ level: 'warn', key: 'issue.realtimeOff', fix: 'enableRealtime', fixKey: 'fix.enable', weight: 10 });
  } else if (!shieldLive()) {
    out.push({ level: 'info', key: 'issue.realtimePending', weight: 4 });
  }
  if (!s.firewallEnabled) out.push({ level: 'bad', key: 'issue.firewallOff', fix: 'enableFirewall', fixKey: 'fix.enable', weight: 15 });
  if (!s.autoQuarantine) out.push({ level: 'warn', key: 'issue.autoQuarantineOff', fix: 'enableAutoQuarantine', fixKey: 'fix.enable', weight: 6 });
  if (!s.honeypotEnabled) out.push({ level: 'warn', key: 'issue.honeypotOff', fix: 'enableHoneypot', fixKey: 'fix.enable', weight: 6 });

  const last = lastStats.lastScan;
  if (!last) out.push({ level: 'warn', key: 'issue.scanNever', fix: 'scan', fixKey: 'fix.scan', weight: 10 });
  else if (Date.now() - last > 7 * DAY) {
    out.push({ level: 'warn', key: 'issue.scanOld', vars: { n: Math.floor((Date.now() - last) / DAY) }, fix: 'scan', fixKey: 'fix.scan', weight: 8 });
  }
  if (fdaStatus === 'denied') out.push({ level: 'warn', key: 'issue.fda', fix: 'grantFda', fixKey: 'fix.grant', weight: 8 });
  if (dbInfoCache && !dbInfoCache.version) out.push({ level: 'bad', key: 'issue.db', fix: 'settings', fixKey: 'fix.review', weight: 15 });

  if (auditData && auditData.supported) {
    const fails = auditData.items.filter((i) => i.status === 'fail').length;
    const warns = auditData.items.filter((i) => i.status === 'warn').length;
    if (fails) out.push({ level: 'bad', key: 'issue.auditFail', vars: { n: fails }, fix: 'audit', fixKey: 'fix.review', weight: 8 * fails });
    else if (warns) out.push({ level: 'warn', key: 'issue.auditWarn', vars: { n: warns }, fix: 'audit', fixKey: 'fix.review', weight: 4 * warns });
  }
  if (startupData) {
    const threats = startupData.items.filter((i) => i.risk === 'threat').length;
    const risky = startupData.items.filter((i) => i.risk && i.risk !== 'threat').length;
    if (threats) out.push({ level: 'bad', key: 'issue.startupThreat', vars: { n: threats }, fix: 'startup', fixKey: 'fix.review', weight: 25 });
    else if (risky) out.push({ level: 'warn', key: 'issue.startupRisk', vars: { n: risky }, fix: 'startup', fixKey: 'fix.review', weight: 5 });
  }
  const order = { bad: 0, warn: 1, info: 2 };
  return out.sort((a, b) => order[a.level] - order[b.level]);
}

function renderIssues(issues) {
  const list = $('#issue-list');
  const actionable = issues.filter((i) => i.level !== 'info').length;
  $('#center-count').textContent = actionable ? t('center.count', { n: actionable }) : '';
  if (!issues.length) {
    list.innerHTML = `<div class="issue ok"><div class="issue-ico">${ICONS.ok}</div>
      <div class="issue-info"><strong>${esc(t('center.allGood'))}</strong><span>${esc(t('center.allGood.sub'))}</span></div></div>`;
    return;
  }
  list.innerHTML = issues
    .map(
      (i) => `<div class="issue ${i.level === 'info' ? '' : i.level}">
      <div class="issue-ico">${ICONS[i.level]}</div>
      <div class="issue-info"><strong>${esc(t(i.key, i.vars))}</strong><span>${esc(t(i.key + '.sub', i.vars))}</span></div>
      ${i.fix ? `<button class="btn ${i.level === 'bad' ? 'primary' : 'ghost'} sm" data-fix="${esc(i.fix)}">${esc(t(i.fixKey))}</button>` : ''}
    </div>`
    )
    .join('');
  list.querySelectorAll('[data-fix]').forEach((b) =>
    b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        await FIXES[b.dataset.fix]();
      } finally {
        b.disabled = false;
      }
    })
  );
}

function paintOverall(issues) {
  const bad = issues.filter((i) => i.level === 'bad').length;
  const warn = issues.filter((i) => i.level === 'warn').length;
  const level = bad ? 'bad' : warn ? 'warn' : 'ok';
  const score = Math.max(10, 100 - issues.reduce((sum, i) => sum + i.weight, 0));
  setScore(score, level);

  $('#status-banner').className = 'status-banner ' + level;
  setText($('#hero-title'), level === 'ok' ? 'hero.title' : 'hero.title.' + level);
  if (level === 'ok') setText($('#hero-sub'), 'hero.sub.ok');
  else setText($('#hero-sub'), 'hero.sub.' + level, { n: level === 'bad' ? bad : bad + warn });

  $('#top-status-pill').className = 'pill ' + level;
  setText($('#top-status-text'), level === 'ok' ? 'top.status' : 'top.status.' + level);
  $('#protection-chip').className = 'protection-chip ' + level;
  setText($('#sidebar-status'), level === 'ok' ? 'sidebar.status' : 'sidebar.status.' + level);
}

/* ---------- Dashboard ---------- */
async function refreshDashboard() {
  paintShieldModule();
  paintEngine();
  const stats = await window.api.getStats();
  lastStats = stats || {};
  $('#stat-scanned').textContent = fmtNum(stats.filesScanned);
  $('#stat-threats').textContent = fmtNum(stats.threatsFound);
  $('#stat-lastscan').textContent = stats.lastScan ? relTime(stats.lastScan) : '—';

  const q = await window.api.quarantineList();
  $('#stat-quarantine').textContent = fmtNum(q.length);
  updateBadge('#nav-quarantine-badge', q.length);

  // Fidye izleyici durumu
  if (runtime && runtime.honeypot) {
    const tag = $('#module-honeypot-status');
    if (tag) {
      const on = runtime.honeypot.running;
      setText(tag, on ? 'status.watch' : 'status.disabled');
      tag.className = 'status-tag ' + (on ? 'ok' : 'bad');
    }
  }

  const issues = computeIssues();
  renderIssues(issues);
  paintOverall(issues);

  const events = await window.api.getEvents();
  renderFeed($('#dash-feed'), events.slice(0, 6));
}

function paintEngine() {
  const eng = runtime && runtime.engine;
  if (!eng) return;
  const native = eng.engine === 'native';
  setText($('#module-engine-sub'), native ? 'module.scanEngine.subNative' : 'module.scanEngine.sub');
  const about = $('#about-engine');
  if (about) about.textContent = native ? t('engine.native', { version: eng.version || '' }) : t('engine.js');
}

function setScore(v, level) {
  $('#score-value').textContent = v;
  const c = 2 * Math.PI * 52;
  const fg = $('#ring-fg');
  fg.style.strokeDasharray = c;
  fg.style.strokeDashoffset = c - (v / 100) * c;
  fg.style.stroke = { ok: 'var(--success)', warn: 'var(--warn)', bad: 'var(--danger)' }[level] || 'var(--success)';
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
function quickScan() {
  scanMode = 'quick';
  $$('.mode-card').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'quick'));
  goto('scan');
  startScan();
}
$('#top-quick-scan').addEventListener('click', quickScan);
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

async function exportEvents(format) {
  const el = $('#events-export-status');
  try {
    const res = await window.api.eventsExport(format);
    if (res && res.ok) el.textContent = '';
    else if (res && res.canceled) el.textContent = t('history.export.canceled');
    else el.textContent = t('history.export.failed', { error: (res && res.error) || '—' });
  } catch (err) {
    el.textContent = t('history.export.failed', { error: String((err && err.message) || err) });
  }
}
$('#btn-events-json').addEventListener('click', () => exportEvents('json'));
$('#btn-events-csv').addEventListener('click', () => exportEvents('csv'));
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
  updateFirewallUi();
  renderExclusions();
  paintAppearance();
}

// Ayar değişikliğinden sonra form öğelerini eşitle (gezinmeden)
function loadSettingsUi() {
  if (!settings) return;
  $('#set-auto-quarantine').checked = settings.autoQuarantine;
  $('#set-firewall').checked = settings.firewallEnabled;
  $('#set-realtime').checked = !!settings.realtimeEnabled;
  $('#set-honeypot').checked = !!settings.honeypotEnabled;
  updateFirewallUi();
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

/* ---------- Görünüm: tema ve dil ---------- */
const THEMES = ['system', 'light', 'dark'];

function applyTheme(pref) {
  const theme = THEMES.includes(pref) ? pref : 'system';
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('#theme-toggle');
  btn.dataset.mode = theme;
  btn.setAttribute('data-i18n-title', 'theme.toggle.' + theme);
  const label = t('theme.toggle.' + theme);
  btn.setAttribute('title', label);
  btn.setAttribute('aria-label', label);
  $$('#set-theme button').forEach((b) => {
    const on = b.dataset.value === theme;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', on ? 'true' : 'false');
    b.setAttribute('role', 'radio');
  });
}

async function setTheme(theme) {
  applyTheme(theme);
  settings = await window.api.setSettings({ theme });
}

$('#theme-toggle').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') || 'system';
  setTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
});
$$('#set-theme button').forEach((b) => b.addEventListener('click', () => setTheme(b.dataset.value)));

function fillLanguageSelect() {
  const sel = $('#set-language');
  const pref = (settings && settings.language) || 'system';
  sel.innerHTML =
    `<option value="system">${esc(t('lang.system'))}</option>` +
    window.I18N.LANGUAGES.map((l) => `<option value="${l.code}" lang="${l.code}">${esc(l.name)}</option>`).join('');
  sel.value = pref;
}

function paintAppearance() {
  applyTheme((settings && settings.theme) || 'system');
  fillLanguageSelect();
}

$('#set-language').addEventListener('change', async (e) => {
  const lang = e.target.value;
  settings = await window.api.setSettings({ language: lang });
  applyLanguage(lang);
});

function applyLanguage(lang) {
  window.I18N.setLanguage(lang);
  window.I18N.applyDom();
  fillLanguageSelect();
  applyTheme((settings && settings.theme) || 'system');
  // Değişkenli metinleri yeniden çiz
  gotoCurrent();
  if (settings) updateFirewallUi();
  renderResults();
  refreshDbStatus();
  paintUpdate({});
  paintFda($('#tcc-status'), fdaStatus);
  paintStrength();
  if (breachState) paintBreach(breachState);
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
  dbInfoCache = info;
  let text;
  if (info.version) {
    const vars = { version: info.version, count: fmtNum(info.count), skipped: fmtNum(info.skipped) };
    text = t(info.skipped ? 'db.info.skipped' : 'db.info', vars);
    $('#sidebar-sub').textContent = t('sidebar.sub', { version: info.version });
  } else {
    text = t('db.error', { reason: info.reason || '—' });
    $('#sidebar-sub').textContent = '—';
  }
  el.textContent = text;
  $('#about-db').textContent = text;
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
  el.style.color = rep.tampered > 0 ? 'var(--danger)' : '';
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

/* ---------- Sistem güvenlik denetimi ---------- */
const AUDIT_ICON = { pass: ICONS.ok, warn: ICONS.warn, fail: ICONS.bad, unknown: ICONS.warn, na: ICONS.na };
let auditRunning = false;

async function runAudit() {
  if (auditRunning) return;
  auditRunning = true;
  $('#btn-run-audit').disabled = true;
  $('#audit-status').textContent = t('audit.running');
  try {
    auditData = await window.api.auditRun();
  } catch (err) {
    window.__aegis.errors.push('audit: ' + String((err && err.stack) || err));
  }
  auditRunning = false;
  $('#btn-run-audit').disabled = false;
  renderAudit();
  if ($('#page-dashboard').classList.contains('active')) refreshDashboard();
}
$('#btn-run-audit').addEventListener('click', runAudit);

function renderAudit() {
  const list = $('#audit-list');
  const status = $('#audit-status');
  if (auditRunning) return;
  if (!auditData) {
    list.innerHTML = `<div class="feed-empty">${esc(t('audit.empty'))}</div>`;
    status.textContent = '';
    updateBadge('#nav-audit-badge', 0);
    return;
  }
  if (!auditData.supported) {
    list.innerHTML = `<div class="feed-empty">${esc(t('audit.unsupported'))}</div>`;
    status.textContent = '';
    updateBadge('#nav-audit-badge', 0);
    return;
  }
  const items = auditData.items;
  const passed = items.filter((i) => i.status === 'pass').length;
  const counted = items.filter((i) => i.status !== 'na').length;
  status.textContent = t('audit.summary', { pass: passed, total: counted, time: relTime(auditData.at) });
  updateBadge('#nav-audit-badge', items.filter((i) => i.status === 'fail' || i.status === 'warn').length);
  const fixLabel = t('audit.fix');
  list.innerHTML = items
    .map(
      (i) => `<div class="check ${esc(i.status)}">
      <div class="issue-ico">${AUDIT_ICON[i.status] || ICONS.na}</div>
      <div class="check-info">
        <strong>${esc(t('audit.item.' + i.id))}</strong>
        <span>${esc(t('audit.item.' + i.id + '.' + (i.status === 'pass' ? 'pass' : 'sub')))}</span>
        ${i.detail ? `<span class="detail mono">${esc(i.detail)}</span>` : ''}
      </div>
      <span class="status-tag ${i.status === 'pass' ? 'ok' : i.status === 'fail' ? 'bad' : i.status === 'na' ? '' : 'warn'}">${esc(t('audit.status.' + i.status))}</span>
      ${i.status !== 'pass' && i.status !== 'na' && i.settingsUrl ? `<button class="btn ghost sm" data-settings="${esc(i.settingsUrl)}">${esc(fixLabel)}</button>` : ''}
    </div>`
    )
    .join('');
  list.querySelectorAll('[data-settings]').forEach((b) =>
    b.addEventListener('click', () => window.api.openExternal(b.dataset.settings))
  );
}

/* ---------- Başlangıç öğeleri ---------- */
let startupLoading = false;

async function loadStartup() {
  if (startupLoading) return;
  startupLoading = true;
  $('#btn-startup-refresh').disabled = true;
  $('#startup-body').innerHTML = `<tr class="empty-row"><td colspan="5">${esc(t('startup.loading'))}</td></tr>`;
  try {
    startupData = await window.api.startupList();
  } catch (err) {
    window.__aegis.errors.push('startup: ' + String((err && err.stack) || err));
    startupData = { items: [], errors: [] };
  }
  startupLoading = false;
  $('#btn-startup-refresh').disabled = false;
  renderStartup();
  if ($('#page-dashboard').classList.contains('active')) refreshDashboard();
}
$('#btn-startup-refresh').addEventListener('click', loadStartup);
$('#startup-hide-apple').addEventListener('change', renderStartup);

function startupStatus(i) {
  if (i.risk === 'threat') return `<span class="row-danger">${esc(t('startup.risk.threat', { name: i.threat }))}</span>`;
  if (i.risk) return `<span class="row-warn">${esc(t('startup.risk.' + i.risk))}</span>`;
  return `<span class="row-ok">${esc(t('startup.ok'))}</span>`;
}

function renderStartup() {
  if (startupLoading || !startupData) return;
  const all = startupData.items || [];
  updateBadge('#nav-startup-badge', all.filter((i) => i.risk).length);
  const hideApple = $('#startup-hide-apple').checked;
  const rows = all.filter((i) => !(hideApple && i.vendor === 'apple' && !i.risk));
  $('#startup-count').textContent = t('startup.count', { shown: fmtNum(rows.length), total: fmtNum(all.length) });
  const body = $('#startup-body');
  if (!rows.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="5">${esc(t('startup.empty'))}</td></tr>`;
    return;
  }
  const revealLabel = t('startup.reveal');
  body.innerHTML = rows
    .map((i, n) => {
      const tags = [
        i.vendor === 'apple' ? `<span class="tag">Apple</span>` : '',
        i.runAtLoad ? `<span class="tag info">${esc(t('startup.runAtLoad'))}</span>` : '',
        i.keepAlive ? `<span class="tag info">${esc(t('startup.keepAlive'))}</span>` : '',
        i.disabled ? `<span class="tag">${esc(t('startup.disabled'))}</span>` : ''
      ].join('');
      return `<tr>
        <td><strong>${esc(i.label)}</strong><div style="margin-top:4px">${tags}</div></td>
        <td><div class="cell-path mono" title="${esc(i.program || '')}">${esc(i.program || '—')}</div>
            ${i.args && i.args.length ? `<div class="muted cell-path">${esc(i.args.join(' '))}</div>` : ''}</td>
        <td class="row-muted">${esc(t('startup.scope.' + i.scope))}</td>
        <td>${startupStatus(i)}</td>
        <td><div class="cell-actions"><button class="btn ghost sm" data-reveal="${n}">${esc(revealLabel)}</button></div></td>
      </tr>`;
    })
    .join('');
  body.querySelectorAll('[data-reveal]').forEach((b) =>
    b.addEventListener('click', () => window.api.openPath(rows[Number(b.dataset.reveal)].file))
  );
}

/* ---------- Kimlik koruması: parola oluşturucu ---------- */
const PW_SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~'
};
const AMBIGUOUS = /[O0Il1|]/g;

// Tarafsız rastgele indeks (modülo yanlılığı olmadan)
function randomIndex(n) {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / n) * n;
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

function pwOptions() {
  const sets = Object.keys(PW_SETS)
    .filter((k) => $('#pw-' + k).checked)
    .map((k) => ($('#pw-ambiguous').checked ? PW_SETS[k].replace(AMBIGUOUS, '') : PW_SETS[k]));
  return { length: Number($('#pw-length').value) || 20, sets };
}

function generatePassword() {
  const { length, sets } = pwOptions();
  if (!sets.length) {
    $('#pw-output').value = '';
    paintStrength();
    return;
  }
  const pool = sets.join('');
  // Seçilen her türden en az bir karakter, sonra karıştır
  const chars = sets.map((set) => set[randomIndex(set.length)]);
  while (chars.length < length) chars.push(pool[randomIndex(pool.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  $('#pw-output').value = chars.join('');
  paintStrength();
}

function paintStrength() {
  const { length, sets } = pwOptions();
  const fill = $('#pw-strength-fill');
  const label = $('#pw-strength-label');
  if (!sets.length) {
    fill.style.width = '0';
    label.textContent = t('id.gen.noSet');
    return;
  }
  const bits = Math.round(length * Math.log2(sets.join('').length));
  const level = bits < 40 ? 'weak' : bits < 60 ? 'fair' : bits < 80 ? 'good' : bits < 100 ? 'strong' : 'excellent';
  const color = { weak: 'var(--danger)', fair: 'var(--warn)', good: 'var(--warn)', strong: 'var(--success)', excellent: 'var(--success)' }[level];
  fill.style.width = Math.min(100, (bits / 128) * 100) + '%';
  fill.style.background = color;
  label.textContent = t('id.strength', { level: t('id.strength.' + level), bits });
}

$('#pw-generate').addEventListener('click', generatePassword);
$('#pw-length').addEventListener('input', (e) => {
  $('#pw-length-value').textContent = e.target.value;
  generatePassword();
});
['upper', 'lower', 'digits', 'symbols', 'ambiguous'].forEach((k) => $('#pw-' + k).addEventListener('change', generatePassword));
$('#pw-copy').addEventListener('click', async () => {
  const v = $('#pw-output').value;
  if (!v) return;
  try {
    await navigator.clipboard.writeText(v);
    toast(t('id.gen.copied'));
  } catch {
    $('#pw-output').select();
  }
});

/* ---------- Kimlik koruması: sızıntı denetimi ---------- */
let breachState = null;

function paintBreach(st) {
  const el = $('#breach-result');
  el.hidden = false;
  if (st.checking) {
    el.className = 'breach-result';
    el.textContent = t('id.breach.checking');
  } else if (!st.ok) {
    el.className = 'breach-result warn';
    el.textContent = t('id.breach.error', { reason: st.error || '—' });
  } else if (st.count > 0) {
    el.className = 'breach-result bad';
    el.textContent = t('id.breach.found', { n: fmtNum(st.count) });
  } else {
    el.className = 'breach-result ok';
    el.textContent = t('id.breach.clean');
  }
}

$('#breach-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#breach-input');
  const pw = input.value;
  if (!pw) return;
  $('#breach-check').disabled = true;
  breachState = { checking: true };
  paintBreach(breachState);
  try {
    breachState = await window.api.breachCheck(pw);
  } catch (err) {
    breachState = { ok: false, error: String((err && err.message) || err) };
  }
  input.value = '';
  $('#breach-check').disabled = false;
  paintBreach(breachState);
});

/* ---------- Başlangıç ---------- */
(async function init() {
  try {
    await loadSettings();
    window.I18N.setLanguage((settings && settings.language) || 'tr');
    window.I18N.applyDom();
    paintAppearance();
    runtime = await window.api.getRuntime();
    await refreshDbStatus();
    await refreshFda();
    await refreshDashboard();
    await loadHistory();
    await loadRules();
    paintUpdate(await window.api.appVersion());
    generatePassword();
    await maybeShowFdaOnboarding();
    const m = (location.hash || '').match(/^#(\w+)$/);
    if (m && TITLES[m[1]]) goto(m[1]);
    else goto('dashboard');
    window.__aegis.ready = true;
    // macOS'ta salt okunur denetimleri arka planda çalıştır (güvenlik merkezi için)
    if (runtime && runtime.platform === 'darwin') {
      runAudit();
      loadStartup();
    } else {
      auditData = { supported: false, items: [] };
      renderAudit();
      loadStartup();
    }
  } catch (err) {
    window.__aegis.errors.push('init: ' + String((err && err.stack) || err));
  }
})();
