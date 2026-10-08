//
// Uygulama otomatik güncellemesi (electron-updater, GitHub Releases).
//
// Yalnızca paketlenmiş ve imzalı macOS sürümünde etkindir: Squirrel.Mac
// imzasız bir uygulamaya güncelleme kurmaz, geliştirme modunda da
// app-update.yml bulunmaz. Durum renderer'a 'update:status' ile iletilir.
//

const INITIAL_DELAY_MS = 30 * 1000;
const INTERVAL_MS = 6 * 60 * 60 * 1000;

function createUpdater({ app, getSettings, send, log = console, loadAutoUpdater }) {
  let state = { state: 'idle' };
  let autoUpdater = null;
  let timers = [];

  const supported = () => app.isPackaged && process.platform === 'darwin';

  function setState(next) {
    state = Object.assign({ at: Date.now() }, next);
    try {
      send(state);
    } catch {}
  }

  function ensure() {
    if (autoUpdater) return autoUpdater;
    autoUpdater = (loadAutoUpdater || (() => require('electron-updater').autoUpdater))();
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = true;
    autoUpdater.allowPrerelease = false;
    autoUpdater.logger = null;
    autoUpdater.on('checking-for-update', () => setState({ state: 'checking' }));
    autoUpdater.on('update-available', (i) => setState({ state: 'downloading', version: i && i.version, percent: 0 }));
    autoUpdater.on('update-not-available', () => setState({ state: 'none', version: app.getVersion() }));
    autoUpdater.on('download-progress', (p) =>
      setState({ state: 'downloading', version: state.version, percent: Math.round((p && p.percent) || 0) })
    );
    autoUpdater.on('update-downloaded', (i) => setState({ state: 'ready', version: i && i.version }));
    autoUpdater.on('error', (err) => {
      log.error('[updater]', err && err.message);
      setState({ state: 'error', reason: String((err && err.message) || err).slice(0, 200) });
    });
    return autoUpdater;
  }

  async function check() {
    if (!supported()) {
      setState({ state: 'unsupported' });
      return state;
    }
    if (state.state === 'checking' || state.state === 'downloading' || state.state === 'ready') return state;
    try {
      await ensure().checkForUpdates();
    } catch (err) {
      setState({ state: 'error', reason: String((err && err.message) || err).slice(0, 200) });
    }
    return state;
  }

  function install() {
    if (state.state !== 'ready' || !autoUpdater) return { ok: false };
    setImmediate(() => autoUpdater.quitAndInstall(false, true));
    return { ok: true };
  }

  function schedule() {
    stop();
    if (!supported()) {
      state = { state: 'unsupported' };
      return;
    }
    const tick = () => {
      if (getSettings().appAutoUpdate) check();
    };
    const first = setTimeout(tick, INITIAL_DELAY_MS);
    const every = setInterval(tick, INTERVAL_MS);
    first.unref && first.unref();
    every.unref && every.unref();
    timers = [first, every];
  }

  function stop() {
    timers.forEach((t) => clearTimeout(t));
    timers = [];
  }

  return { check, install, schedule, stop, status: () => Object.assign({ current: app.getVersion() }, state) };
}

module.exports = { createUpdater, INITIAL_DELAY_MS, INTERVAL_MS };
