// Arayüz öz testi — gerçek uygulama penceresinde çalışır.
//
//   electron . --ui-selftest [--ui-shots=<dizin>]
//
// main.js bu dosyayı pencereye enjekte eder (executeJavaScript). Betik bir
// Promise döndürür; sonuç main.js'te yazdırılır ve çıkış kodunu belirler.
// macOS'ta sistem denetimi ve başlangıç öğeleri gerçek sistem verisiyle
// doğrulanır; bu yüzden CI'da macos-latest üzerinde de koşar.
(async () => {
  const failures = [];
  const info = { platform: null };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const fail = (msg) => failures.push(msg);
  async function until(fn, ms, what) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      try {
        if (await fn()) return true;
      } catch {}
      await sleep(150);
    }
    fail('zaman aşımı: ' + what);
    return false;
  }

  // Görünür metinde çevrilmemiş anahtar (ör. "audit.item.sip") kalmış mı?
  // (alan adları gibi noktalı metinler yalnızca sözlükteki bir anahtar grubuyla
  // başlıyorsa sayılır: "audit.", "startup." …)
  const KEY_RE = /^[a-z][a-zA-Z]*(\.[a-zA-Z0-9]+)+$/;
  const GROUPS = new Set(Object.keys(window.AEGIS_LOCALES.en).map((k) => k.split('.')[0]));
  const isKey = (s) => KEY_RE.test(s) && GROUPS.has(s.split('.')[0]);
  function keyLeaks(scope) {
    const leaks = [];
    const walker = document.createTreeWalker(scope || document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const s = walker.currentNode.nodeValue.trim();
      if (s && isKey(s)) leaks.push(s);
    }
    $$('[placeholder],[title]').forEach((el) => {
      for (const a of ['placeholder', 'title']) {
        const v = el.getAttribute(a);
        if (v && isKey(v)) leaks.push(`${a}=${v}`);
      }
    });
    return [...new Set(leaks)];
  }

  try {
    await until(() => window.__aegis && window.__aegis.ready, 90000, 'uygulama hazır');
    info.readyMs = Math.round(performance.now());
    const runtime = await window.api.getRuntime();
    info.platform = runtime.platform;
    info.engine = runtime.engine && runtime.engine.engine;

    // İlk açılıştaki izin tanıtımı tıklamaları engellemesin
    if (!$('#fda-modal').hidden) $('#fda-later').click();

    // 1) Her sayfa açılıyor, başlık ve alt başlık çevrilmiş
    const pages = $$('.nav-item').map((b) => b.dataset.page);
    if (pages.length !== 9) fail('beklenmeyen sayfa sayısı: ' + pages.length);
    for (const p of pages) {
      $(`.nav-item[data-page="${p}"]`).click();
      await sleep(250);
      const active = $('.page.active');
      if (!active || active.id !== 'page-' + p) fail(`${p}: sayfa açılmadı`);
      const title = $('#page-title').textContent.trim();
      if (!title || isKey(title)) fail(`${p}: başlık "${title}"`);
    }

    // 2) Güvenlik merkezi ve puan
    $('.nav-item[data-page="dashboard"]').click();
    await sleep(400);
    const score = Number($('#score-value').textContent);
    if (!(score >= 10 && score <= 100)) fail('güvenlik puanı: ' + $('#score-value').textContent);
    if (!$('#issue-list').children.length) fail('güvenlik merkezi boş');
    info.score = score;
    info.issues = $$('#issue-list .issue-info strong').map((e) => e.textContent);

    // 3) Sistem denetimi (macOS'ta gerçek veri)
    if (runtime.platform === 'darwin') {
      await until(() => $$('#audit-list .check').length === 7, 40000, 'denetim sonuçları');
      const checks = $$('#audit-list .check').map((c) => ({
        status: c.className.replace('check', '').trim(),
        title: c.querySelector('strong').textContent
      }));
      info.audit = checks;
      for (const c of checks) {
        if (!['pass', 'warn', 'fail', 'na', 'unknown'].includes(c.status)) fail('denetim durumu: ' + c.status);
      }
      if (!/\d+\/\d+/.test($('#audit-status').textContent)) fail('denetim özeti: ' + $('#audit-status').textContent);
    } else if (!$('#audit-list').textContent.trim()) {
      fail('denetim sayfası boş (macOS dışı mesajı beklenirdi)');
    }

    // 4) Başlangıç öğeleri
    $('.nav-item[data-page="startup"]').click();
    await until(() => !$('#btn-startup-refresh').disabled, 40000, 'başlangıç öğeleri');
    const startup = await window.api.startupList();
    info.startup = { total: startup.items.length, risky: startup.items.filter((i) => i.risk).length };
    if (startup.errors.length) fail('başlangıç öğesi dizin hataları: ' + JSON.stringify(startup.errors));
    const unreadable = startup.items.filter((i) => i.risk === 'unreadable');
    if (unreadable.length) fail('okunamayan kayıtlar: ' + unreadable.map((i) => i.file).join(', '));
    if (runtime.platform === 'darwin') {
      if (!startup.items.length) fail('macOS’ta başlangıç öğesi bulunamadı');
      $('#startup-hide-apple').checked = false;
      $('#startup-hide-apple').dispatchEvent(new Event('change'));
      await sleep(200);
      const rows = $$('#startup-body tr:not(.empty-row)').length;
      if (rows !== startup.items.length) fail(`başlangıç tablosu ${rows} satır, ${startup.items.length} öğe`);
    }

    // 5) Parola oluşturucu
    $('.nav-item[data-page="identity"]').click();
    await sleep(200);
    const len = $('#pw-length');
    len.value = '32';
    len.dispatchEvent(new Event('input'));
    await sleep(100);
    if ($('#pw-output').value.length !== 32) fail('parola uzunluğu: ' + $('#pw-output').value.length);
    if (!$('#pw-strength-label').textContent.trim()) fail('parola gücü etiketi boş');

    // 5b) Bağlantı denetleyici: marka taklidi şüpheli, gerekçeler çevrilmiş
    $('#link-input').value = 'https://paypa1.com/giris';
    $('#link-form').requestSubmit();
    await until(() => /warn|bad/.test($('#link-result').className) && !$('#link-reasons').hidden, 10000, 'bağlantı denetimi');
    info.link = { verdict: $('#link-result').textContent, reasons: $$('#link-reasons li').map((li) => li.textContent), db: $('#link-db').textContent };
    if (!$$('#link-reasons li.warn').length) fail('bağlantı denetimi: uyarı gerekçesi yok');
    if (!$('#link-db').textContent.trim()) fail('bağlantı denetimi: liste boyutu gösterilmedi');

    // 6) Tema: Sistem → Açık → Koyu → Sistem; açık ve koyu arka plan farklı
    const seq = [];
    const bg = {};
    for (let i = 0; i < 3; i++) {
      $('#theme-toggle').click();
      await sleep(250);
      const th = document.documentElement.getAttribute('data-theme');
      seq.push(th);
      bg[th] = getComputedStyle(document.body).backgroundColor;
    }
    info.theme = { seq, bg };
    if (seq.join(',') !== 'light,dark,system') fail('tema sırası: ' + seq.join(','));
    if (bg.light === bg.dark) fail('açık ve koyu temada arka plan aynı: ' + bg.light);
    const saved = (await window.api.getSettings()).theme;
    if (saved !== 'system') fail('tema ayarı kaydedilmedi: ' + saved);

    // 7) Her dilde: tüm sayfalarda çevrilmemiş anahtar kalmıyor
    const sel = $('#set-language');
    const original = sel.value;
    info.languages = [];
    for (const { code } of window.I18N.LANGUAGES) {
      sel.value = code;
      sel.dispatchEvent(new Event('change'));
      await until(() => document.documentElement.lang === code, 3000, 'dil ' + code);
      for (const p of pages) {
        $(`.nav-item[data-page="${p}"]`).click();
        await sleep(60);
      }
      await sleep(150);
      const leaks = keyLeaks();
      if (leaks.length) fail(`${code}: çevrilmemiş anahtarlar: ${leaks.slice(0, 8).join(', ')}`);
      info.languages.push(code);
    }
    sel.value = original;
    sel.dispatchEvent(new Event('change'));
    await sleep(200);
    $('.nav-item[data-page="dashboard"]').click();

    const errs = window.__aegis.errors || [];
    if (errs.length) fail('renderer hataları: ' + errs.join(' | '));
  } catch (err) {
    fail('öz test istisnası: ' + String((err && err.stack) || err));
  }
  return { ok: failures.length === 0, failures, info };
})();
