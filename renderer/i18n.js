//
// Dil desteği — TR/EN
//
// Kullanım:
//   index.html içinde: <span data-i18n="key">Türkçe varsayılan</span>
//   JS içinde: t('key')  |  dinamik listeler için: t('key', {n: 3})
//
// Sözlük tek doğruluk kaynağıdır; HTML'deki Türkçe metin yalnızca
// varsayılan/seed'dir ve data-i18n yoksa değiştirilmez.
//
const DICT = {
  tr: {
    'set.exclusions': 'Dışlamalar',
    'set.exclusions.sub': 'Taramalarda tamamen atlanacak klasör ve dosyalar',
    'set.exclusions.add': '+ Klasör ekle',
    'set.exclusions.empty': 'Dışlama yok',
    'set.exclusions.remove': 'Kaldır',
    // Genel
    'app.name': 'AEGIS',
    'app.sub': 'Security Suite',
    'nav.dashboard': 'Genel Bakış',
    'nav.scan': 'Tarama',
    'nav.quarantine': 'Karantina',
    'nav.firewall': 'Firewall',
    'nav.activity': 'Etkinlik',
    'nav.settings': 'Ayarlar',
    'page.dashboard': 'Genel Bakış',
    'page.scan': 'Tarama',
    'page.quarantine': 'Karantina',
    'page.firewall': 'Firewall',
    'page.activity': 'Etkinlik',
    'page.settings': 'Ayarlar',
    'top.status': 'Kalkan devrede',
    'top.quickScan': 'Hızlı Tarama',
    'sidebar.status': 'Koruma Aktif',
    'sidebar.sub': 'İmza DB v2026.10',
    'status.active': 'Aktif',
    'status.standby': 'Beklemede',
    'status.disabled': 'Kapalı',
    'status.watch': 'İzliyor',
    'feed.empty': 'Henüz etkinlik yok',
    'q.empty': 'Karantina boş',
    'q.restore': 'Geri yükle',
    'q.delete': 'Sil',
    'q.integrityOk': 'Bütünlük doğrulandı',
    'scan.inQuarantine': 'Karantinada',
    'scan.flagged': 'İşaretlendi',
    'scan.openFolder': 'Konumu aç',
    'fw.block': 'ENGELLE',
    'fw.allow': 'İZİN',
    'fw.all': 'tümü',
    'fw.delete': 'Sil',
    'rules.empty': 'Kural yok',
    'db.idle': 'v2026.10.1',
    // Tarama geçmişi
    'history.title': 'Tarama geçmişi',
    'history.exportJson': 'JSON',
    'history.exportCsv': 'CSV',
    'history.clear': 'Geçmişi temizle',
    'history.empty': 'Henüz tarama yok',
    'history.col.date': 'Tarih',
    'history.col.mode': 'Mod',
    'history.col.files': 'Dosya',
    'history.col.threats': 'Tehdit',
    'history.col.duration': 'Süre',
    'history.mode.quick': 'Hızlı',
    'history.mode.custom': 'Özel',
    'history.mode.scheduled': 'Zamanlanmış',
    'history.stopped': 'Kesildi',
    'history.denied': '⚠ {n} dizin erişimi reddedildi',
    'history.moreThreats': '+{n} tehdit daha',
    'history.export.canceled': 'Dışa aktarma iptal edildi',
    'history.export.failed': 'Dışa aktarma başarısız: {error}'
  },
  en: {
    'set.exclusions': 'Exclusions',
    'set.exclusions.sub': 'Folders and files always skipped during scans',
    'set.exclusions.add': '+ Add folder',
    'set.exclusions.empty': 'No exclusions',
    'set.exclusions.remove': 'Remove',
    // Genel
    'app.name': 'AEGIS',
    'app.sub': 'Security Suite',
    'nav.dashboard': 'Overview',
    'nav.scan': 'Scan',
    'nav.quarantine': 'Quarantine',
    'nav.firewall': 'Firewall',
    'nav.activity': 'Activity',
    'nav.settings': 'Settings',
    'page.dashboard': 'Overview',
    'page.scan': 'Scan',
    'page.quarantine': 'Quarantine',
    'page.firewall': 'Firewall',
    'page.activity': 'Activity',
    'page.settings': 'Settings',
    'top.status': 'Shield active',
    'top.quickScan': 'Quick Scan',
    'sidebar.status': 'Protection Active',
    'sidebar.sub': 'Signature DB v2026.10',

    // Dashboard
    'hero.title': 'Your system is protected',
    'hero.sub': 'Real-time shield: native daemon pending · Scanning and firewall active',
    'score.label': 'security score',
    'stat.scanned': 'Files scanned',
    'stat.threats': 'Threats found',
    'stat.quarantine': 'In quarantine',
    'stat.lastScan': 'Last scan',
    'modules.title': 'Protection modules',
    'module.scanEngine': 'Scanning engine',
    'module.scanEngine.sub': 'SHA-256 signatures + EICAR + heuristic analysis',
    'module.firewall': 'Firewall',
    'module.firewall.sub': 'Rule engine + connection monitoring',
    'module.realtime': 'Real-time shield',
    'module.realtime.sub': 'Requires Endpoint Security native daemon',
    'module.quarantine': 'Quarantine',
    'module.quarantine.sub': 'Isolates infected files',
    'module.honeypot': 'Ransomware monitor',
    'module.honeypot.sub': 'Decoy files + burst detection',
    'status.active': 'Active',
    'status.standby': 'Standby',
    'status.disabled': 'Disabled',
    'status.watch': 'Watching',
    'feed.recent': 'Recent activity',
    'feed.all': 'All',
    'feed.empty': 'No activity yet',

    // Tarama
    'scan.quick': 'Quick Scan',
    'scan.quick.sub': 'Downloads, Desktop, Documents, Applications',
    'scan.custom': 'Custom Scan',
    'scan.custom.sub': 'Choose your own folders',
    'scan.start': 'Start Scan',
    'scan.stop': 'Stop',
    'scan.results': 'Scan results',
    'scan.eicar': 'Create EICAR test file',
    'scan.empty': 'No scan performed yet',
    'scan.scanning': 'Scanning…',
    'scan.clean': '✓ Clean',
    'scan.threatsFound': 'threats found',
    'scan.files': 'files scanned',
    'scan.col.file': 'File',
    'scan.col.threat': 'Threat',
    'scan.col.result': 'Result',
    'scan.openFolder': 'Show in folder',
    'scan.inQuarantine': 'In quarantine',
    'scan.flagged': 'Flagged',
    'scan.error': 'Error',

    // Karantina
    'q.title': 'Quarantined files',
    'q.items': 'items',
    'q.empty': 'Quarantine is empty',
    'q.col.threat': 'Threat',
    'q.col.location': 'Original location',
    'q.col.date': 'Date',
    'q.col.action': 'Action',
    'q.restore': 'Restore',
    'q.delete': 'Delete',
    'q.integrityOk': 'Integrity verified',
    'q.integrityBad': 'TAMPERING DETECTED',
    'q.integrityLegacy': 'Legacy records',

    // Firewall
    'fw.title': 'Firewall',
    'fw.sub': 'The rule engine evaluates live connections. Blocking packets requires the native Network Extension (native-daemon/).',
    'fw.rules': 'Security rules',
    'fw.addRule': '+ Add rule',
    'fw.col.type': 'Type',
    'fw.col.target': 'Target',
    'fw.col.port': 'Port',
    'fw.col.note': 'Note',
    'fw.block': 'BLOCK',
    'fw.allow': 'ALLOW',
    'fw.all': 'all',
    'fw.save': 'Save',
    'fw.cancel': 'Cancel',
    'fw.delete': 'Delete',
    'fw.addTitle': 'Add rule',
    'fw.hostPlaceholder': 'Domain, IP or application',
    'fw.portPlaceholder': 'Port (opt.)',
    'fw.notePlaceholder': 'Note',
    'fw.connections': 'Active connections',
    'fw.refresh': 'Refresh',
    'fw.col.process': 'Process',
    'fw.col.remote': 'Remote address',
    'fw.col.verdict': 'Verdict',
    'fw.noConnections': 'No active connections',
    'fw.verdict.blocked': 'BLOCKED',
    'fw.verdict.allowed': 'ALLOWED',

    // Etkinlik
    'log.title': 'Activity log',
    'log.refresh': 'Refresh',

    // Ayarlar
    'set.title': 'Protection preferences',
    'set.autoQuarantine': 'Automatic quarantine',
    'set.autoQuarantine.sub': 'Automatically isolate detected threats',
    'set.heuristics': 'Heuristic analysis',
    'set.heuristics.sub': 'Look beyond signatures for behavioural clues',
    'set.notifications': 'Notifications',
    'set.notifications.sub': 'System notification when a threat is found',
    'set.firewall': 'Firewall',
    'set.firewall.sub': 'Enable the rule engine',
    'set.realtime': 'Real-time shield',
    'set.realtime.sub': 'Requires native daemon (Endpoint Security)',
    'set.archives': 'Archive scanning',
    'set.archives.sub': 'Scan inside zip/tar/gz archives',
    'set.scheduled': 'Scheduled scan',
    'set.scheduled.sub': 'Periodic automatic scans while app is open',
    'set.interval': 'Interval (hours)',
    'set.honeypot': 'Ransomware monitor',
    'set.honeypot.sub': 'Decoy files in Documents/Desktop + burst alerts',
    'set.language': 'Language',
    'set.dbUpdate': 'Signature database',
    'set.dbUpdate.check': 'Check for updates',
    'set.dbUpdate.updating': 'Checking…',
    'set.tcc': 'Full Disk Access',
    'set.tcc.sub': 'For scanning all folders, grant Aegis Full Disk Access in System Settings → Privacy & Security.',
    'set.tcc.open': 'Open System Settings',
    'set.integrity': 'Quarantine integrity',
    'set.integrity.check': 'Verify now',
    'set.about': 'About',
    'set.about.sub': 'On-demand scanning, encrypted quarantine, rule-based firewall',
    'set.roadmap': 'Roadmap',
    'set.onDemandScanning': 'On-demand scanning: active',
    'set.encryptedQuarantine': 'Encrypted quarantine (AES-256-GCM): active',
    'set.ruleFirewall': 'Rule-based firewall: active',
    'set.realtimePending': 'Real-time shield: pending Apple approval (native-daemon/)',
    'set.packetBlockPending': 'Packet blocking: pending Apple approval (native-daemon/)',
    'set.version': 'Version 0.1.0 · Signature DB',

    // Ortak
    'common.close': 'Close',
    'common.on': 'On',
    'common.off': 'Off',
    'notify.threatTitle': 'Aegis: Threat found',

    // Tarama geçmişi
    'history.title': 'Scan history',
    'history.exportJson': 'JSON',
    'history.exportCsv': 'CSV',
    'history.clear': 'Clear history',
    'history.empty': 'No scans yet',
    'history.col.date': 'Date',
    'history.col.mode': 'Mode',
    'history.col.files': 'Files',
    'history.col.threats': 'Threats',
    'history.col.duration': 'Duration',
    'history.mode.quick': 'Quick',
    'history.mode.custom': 'Custom',
    'history.mode.scheduled': 'Scheduled',
    'history.stopped': 'Stopped',
    'history.denied': '⚠ {n} folders denied',
    'history.moreThreats': '+{n} more threats',
    'history.export.canceled': 'Export canceled',
    'history.export.failed': 'Export failed: {error}'
  }
};

// Olay/etkinlik metinleri için çeviri anahtarları
const EVENT_EN = {
  'Tarama tamamlandı': 'Scan completed',
  'tehdit': 'threats',
  'Tehdit:': 'Threat:'
};

let current = 'tr';

function tr(key, vars) {
  const lang = current;
  let s = (DICT[lang] && DICT[lang][key]) || key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) s = s.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
  }
  return s;
}

function setLanguage(lang) {
  current = lang === 'en' ? 'en' : 'tr';
  applyDom();
  return current;
}

function getLanguage() {
  return current;
}

function applyDom() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    if (el.dataset.i18nOrig === undefined) el.dataset.i18nOrig = el.textContent;
    const key = el.getAttribute('data-i18n');
    if (current === 'tr' || !DICT[current][key]) el.textContent = el.dataset.i18nOrig;
    else el.textContent = DICT[current][key];
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    if (el.dataset.i18nPhOrig === undefined) el.dataset.i18nPhOrig = el.getAttribute('placeholder') || '';
    const key = el.getAttribute('data-i18n-placeholder');
    if (current === 'tr' || !DICT[current][key]) el.setAttribute('placeholder', el.dataset.i18nPhOrig);
    else el.setAttribute('placeholder', DICT[current][key]);
  });
  document.documentElement.lang = current;
}

const I18N_API = { t: tr, setLanguage, getLanguage, applyDom, DICT, EVENT_EN };
window.I18N = I18N_API;
if (typeof module !== 'undefined') module.exports = I18N_API;
