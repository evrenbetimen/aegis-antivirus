const test = require('node:test');
const assert = require('node:assert');
const { fullDiskAccessStatus } = require('../src/permissions');

function fakeFs(codes) {
  return {
    openSync(p) {
      for (const [frag, code] of Object.entries(codes)) {
        if (p.includes(frag)) {
          if (code === 'OK') return 42;
          const e = new Error(code);
          e.code = code;
          throw e;
        }
      }
      const e = new Error('ENOENT');
      e.code = 'ENOENT';
      throw e;
    },
    closeSync() {}
  };
}

test('non-darwin platforms are unsupported', () => {
  assert.strictEqual(fullDiskAccessStatus({ platform: 'linux' }).status, 'unsupported');
});

test('EPERM on TCC.db means denied', () => {
  const r = fullDiskAccessStatus({ platform: 'darwin', home: '/Users/x', fsImpl: fakeFs({ 'TCC.db': 'EPERM' }) });
  assert.strictEqual(r.status, 'denied');
});

test('any readable protected file means granted', () => {
  const r = fullDiskAccessStatus({
    platform: 'darwin',
    home: '/Users/x',
    fsImpl: fakeFs({ '/Users/x/Library/Application Support/com.apple.TCC': 'EPERM', Bookmarks: 'OK' })
  });
  assert.strictEqual(r.status, 'granted');
});

test('nothing present means unknown', () => {
  const r = fullDiskAccessStatus({ platform: 'darwin', home: '/Users/x', fsImpl: fakeFs({}) });
  assert.strictEqual(r.status, 'unknown');
});
