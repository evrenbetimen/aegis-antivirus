const fs = require('fs');
const os = require('os');
const path = require('path');

// macOS Tam Disk Erişimi (TCC "SystemPolicyAllFiles") için resmi bir sorgu API'si
// yok. Yaygın yöntem: yalnızca FDA ile okunabilen dosyaları açmayı denemek.
// EPERM/EACCES → izin yok; açılırsa → izin var; hiçbiri yoksa → bilinmiyor.
function probePaths(home) {
  return [
    path.join(home, 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db'),
    path.join(home, 'Library', 'Safari', 'Bookmarks.plist'),
    path.join(home, 'Library', 'Safari', 'CloudTabs.db'),
    '/Library/Application Support/com.apple.TCC/TCC.db'
  ];
}

/**
 * @returns {{ status: 'granted'|'denied'|'unknown'|'unsupported', probed?: string }}
 */
function fullDiskAccessStatus({ platform = process.platform, home = os.homedir(), fsImpl = fs } = {}) {
  if (platform !== 'darwin') return { status: 'unsupported' };
  let denied = null;
  for (const p of probePaths(home)) {
    let fd = null;
    try {
      fd = fsImpl.openSync(p, 'r');
      return { status: 'granted', probed: p };
    } catch (err) {
      if (err && (err.code === 'EPERM' || err.code === 'EACCES')) denied = denied || p;
    } finally {
      if (fd !== null) {
        try {
          fsImpl.closeSync(fd);
        } catch {}
      }
    }
  }
  return denied ? { status: 'denied', probed: denied } : { status: 'unknown' };
}

module.exports = { fullDiskAccessStatus, probePaths };
