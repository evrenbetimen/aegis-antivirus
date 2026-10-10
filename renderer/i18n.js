//
// Dil desteği — 12 dil
//
// Sözlükler renderer/locales/<kod>.js dosyalarındadır ve her biri
// window.AEGIS_LOCALES[<kod>] nesnesini doldurur. İngilizce (en) referanstır:
// bir dilde eksik anahtar önce İngilizceye, sonra anahtarın kendisine düşer.
//
// Kullanım:
//   index.html: <span data-i18n="key">…</span>, data-i18n-placeholder, data-i18n-title
//   JS:         t('key') | t('key', { n: 3 })
//
(function () {
  const root = typeof window !== 'undefined' ? window : globalThis;
  const LOCALES = root.AEGIS_LOCALES || {};

  // Ayarlar listesinde gösterilen yerel adlar (sözlükten bağımsız)
  const LANGUAGES = [
    { code: 'tr', name: 'Türkçe', intl: 'tr-TR' },
    { code: 'en', name: 'English', intl: 'en-US' },
    { code: 'de', name: 'Deutsch', intl: 'de-DE' },
    { code: 'fr', name: 'Français', intl: 'fr-FR' },
    { code: 'es', name: 'Español', intl: 'es-ES' },
    { code: 'it', name: 'Italiano', intl: 'it-IT' },
    { code: 'pt', name: 'Português', intl: 'pt-BR' },
    { code: 'nl', name: 'Nederlands', intl: 'nl-NL' },
    { code: 'pl', name: 'Polski', intl: 'pl-PL' },
    { code: 'ru', name: 'Русский', intl: 'ru-RU' },
    { code: 'ja', name: '日本語', intl: 'ja-JP' },
    { code: 'zh', name: '简体中文', intl: 'zh-CN' }
  ];
  const CODES = LANGUAGES.map((l) => l.code);

  let preference = 'tr'; // kullanıcının seçimi ('system' olabilir)
  let current = 'tr'; // çözümlenmiş dil kodu

  /** 'system' tercihini işletim sistemi diline çevirir. */
  function resolve(pref) {
    if (pref && pref !== 'system' && CODES.includes(pref)) return pref;
    const wanted = (root.navigator && (root.navigator.languages || [root.navigator.language])) || [];
    for (const tag of wanted) {
      const base = String(tag || '').toLowerCase().split('-')[0];
      if (CODES.includes(base)) return base;
    }
    return 'en';
  }

  function lookup(key) {
    const dict = LOCALES[current];
    if (dict && Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    const en = LOCALES.en;
    if (en && Object.prototype.hasOwnProperty.call(en, key)) return en[key];
    return key;
  }

  function t(key, vars) {
    let s = lookup(key);
    if (vars) {
      s = s.replace(/\{(\w+)\}/g, (m, name) =>
        Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : m
      );
    }
    return s;
  }

  function setLanguage(pref) {
    preference = pref || 'system';
    current = resolve(preference);
    applyDom();
    return current;
  }

  function getLanguage() {
    return current;
  }

  function getPreference() {
    return preference;
  }

  function intlLocale() {
    const l = LANGUAGES.find((x) => x.code === current);
    return l ? l.intl : 'en-US';
  }

  function applyDom(scope) {
    if (typeof document === 'undefined') return;
    const base = scope || document;
    base.querySelectorAll('[data-i18n]').forEach((el) => {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    base.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
    });
    base.querySelectorAll('[data-i18n-title]').forEach((el) => {
      const s = t(el.getAttribute('data-i18n-title'));
      el.setAttribute('title', s);
      el.setAttribute('aria-label', s);
    });
    document.documentElement.lang = current;
  }

  function formatNumber(n) {
    return new Intl.NumberFormat(intlLocale()).format(n || 0);
  }

  function formatDate(ts, opts) {
    return new Date(ts).toLocaleString(
      intlLocale(),
      opts || { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }
    );
  }

  const API = {
    t,
    setLanguage,
    getLanguage,
    getPreference,
    resolve,
    applyDom,
    formatNumber,
    formatDate,
    intlLocale,
    LANGUAGES,
    LOCALES
  };
  root.I18N = API;
  if (typeof module !== 'undefined') module.exports = API;
})();
