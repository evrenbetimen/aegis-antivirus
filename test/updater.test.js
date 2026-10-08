const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { createUpdater } = require('../src/updater');

function setup({ isPackaged = true, platform = 'darwin' } = {}) {
  const orig = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: platform });
  const sent = [];
  const au = new EventEmitter();
  au.checkForUpdates = async () => {
    au.emit('checking-for-update');
    au.emit('update-available', { version: '0.2.0' });
    au.emit('download-progress', { percent: 50.4 });
    au.emit('update-downloaded', { version: '0.2.0' });
  };
  au.quitAndInstall = () => (au.installed = true);
  const u = createUpdater({
    app: { isPackaged, getVersion: () => '0.1.0' },
    getSettings: () => ({ appAutoUpdate: true }),
    send: (s) => sent.push(s.state),
    loadAutoUpdater: () => au
  });
  return { u, au, sent, restore: () => Object.defineProperty(process, 'platform', orig) };
}

test('unpackaged builds report unsupported and never load electron-updater', async () => {
  const { u, restore } = setup({ isPackaged: false });
  try {
    assert.strictEqual((await u.check()).state, 'unsupported');
  } finally {
    restore();
  }
});

test('non-macOS builds report unsupported', async () => {
  const { u, restore } = setup({ platform: 'linux' });
  try {
    assert.strictEqual((await u.check()).state, 'unsupported');
  } finally {
    restore();
  }
});

test('check walks through download to ready, then installs', async () => {
  const { u, au, sent, restore } = setup();
  try {
    assert.strictEqual(u.install().ok, false);
    const s = await u.check();
    assert.strictEqual(s.state, 'ready');
    assert.strictEqual(s.version, '0.2.0');
    assert.deepStrictEqual(sent, ['checking', 'downloading', 'downloading', 'ready']);
    assert.strictEqual(u.install().ok, true);
    await new Promise((r) => setImmediate(r));
    assert.strictEqual(au.installed, true);
  } finally {
    restore();
  }
});

test('errors are surfaced with a reason', async () => {
  const { u, au, restore } = setup();
  au.checkForUpdates = async () => {
    throw new Error('HttpError: 404');
  };
  try {
    const s = await u.check();
    assert.strictEqual(s.state, 'error');
    assert.match(s.reason, /404/);
  } finally {
    restore();
  }
});
