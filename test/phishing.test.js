// Kimlik avı koruması — node --test test/phishing.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const phishing = require('../src/phishing');

const domains = {
  phishing: phishing.buildList(['kotu-giris.xyz', 'hesap-dogrula.com.tr']),
  malware: phishing.buildList(['malware-cdn.top'])
};

test('liste: sıralı, sabit genişlikli kayıtlar; üst alan adı eşleşir, kardeş eşleşmez', () => {
  assert.equal(domains.phishing.length % phishing.REC, 0);
  assert.equal(phishing.listSize(domains.phishing), 2);
  assert.deepEqual(phishing.lookupHost('KOTU-GIRIS.xyz.', domains), { kind: 'phishing', domain: 'kotu-giris.xyz' });
  assert.deepEqual(phishing.lookupHost('a.b.kotu-giris.xyz', domains), { kind: 'phishing', domain: 'kotu-giris.xyz' });
  assert.equal(phishing.lookupHost('kotu-giris.xyz.example.com', domains), null);
  assert.equal(phishing.lookupHost('xyz', domains), null);
  assert.equal(phishing.validList('abc'), '');
  assert.equal(phishing.validList(domains.phishing), domains.phishing);
});

test('checkUrl: liste eşleşmesi tehlikeli, temiz adres güvenli', () => {
  const bad = phishing.checkUrl('https://giris.kotu-giris.xyz/oturum?x=1', domains);
  assert.equal(bad.verdict, 'dangerous');
  assert.equal(bad.reasons[0].code, 'listPhishing');
  assert.equal(phishing.checkUrl('malware-cdn.top/x.exe', domains).reasons[0].code, 'listMalware');
  const ok = phishing.checkUrl('https://www.paypal.com/signin', domains);
  assert.equal(ok.verdict, 'safe');
  assert.deepEqual(ok.reasons, []);
  assert.equal(phishing.checkUrl('https://www.turkiye.gov.tr', domains).verdict, 'safe');
  assert.equal(phishing.checkUrl('https://github.com/evrenbetimen', domains).verdict, 'safe');
});

test('checkUrl: sezgiler şüpheli uyarısı üretir', () => {
  const codes = (u) => phishing.checkUrl(u, domains).reasons.map((r) => r.code);
  assert.deepEqual(codes('https://paypal.com.hesap-guvenlik.xyz/login'), ['brandName']);
  assert.deepEqual(codes('https://paypa1.com'), ['lookalike']);
  assert.deepEqual(codes('https://amazon-tr-kargo.com'), ['brandName']);
  assert.deepEqual(codes('https://xn--pple-43d.com'), ['punycode']);
  assert.deepEqual(codes('https://аpple.com'), ['punycode']); // Kiril "а"
  assert.deepEqual(codes('https://www.google.com@203.0.113.9/giris'), ['userinfo', 'ipHost']);
  assert.deepEqual(codes('http://198.51.100.7/'), ['ipHost', 'http']);
  assert.deepEqual(codes('https://bit.ly/abc'), ['shortener']);
  assert.deepEqual(codes('https://a.b.c.d.e.example.com'), ['deepSubdomain']);
  assert.equal(phishing.checkUrl('https://bit.ly/abc', domains).verdict, 'safe'); // yalnızca bilgi
  assert.equal(phishing.checkUrl('javascript:alert(1)', domains).verdict, 'dangerous');
  assert.equal(phishing.checkUrl('ftp://x.com', domains).verdict, 'invalid');
  assert.equal(phishing.checkUrl('', domains).verdict, 'invalid');
  assert.equal(phishing.checkUrl('http://exa mple.com', domains).verdict, 'invalid');
});

test('dosya metni: bağlantılar çıkarılır, quoted-printable ve kullanıcı bilgisi aşılır', () => {
  const eml = 'Subject: Hesap\r\n\r\n<a href=3D"https://www.ornek.com@giris.kotu-giris=\r\n.xyz/a">tikla</a> http://temiz.org';
  assert.deepEqual(phishing.extractHosts(eml), ['giris.kotu-giris.xyz', 'temiz.org']);
  assert.deepEqual(phishing.findListedHost(eml, domains), { host: 'giris.kotu-giris.xyz', kind: 'phishing', domain: 'kotu-giris.xyz' });
  const webloc = '<plist><dict><key>URL</key><string>https://malware-cdn.top/kur.dmg</string></dict></plist>';
  assert.equal(phishing.findListedHost(webloc, domains).kind, 'malware');
  assert.equal(phishing.findListedHost('[InternetShortcut]\nURL=https://temiz.org/', domains), null);
  assert.equal(phishing.findListedHost('https://kotu-giris.xyz', { phishing: '', malware: '' }), null);
  assert.ok(phishing.isLinkFile('a/Hesap.webloc') && phishing.isLinkFile('x.EML') && phishing.isLinkFile('s.url'));
  assert.ok(!phishing.isLinkFile('notlar.txt'));
});
