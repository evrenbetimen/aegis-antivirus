//
// Zamanlanmış tarama — uygulama açıkken periyodik tarama
//
// Not: uygulama kapalıyken de çalışması için üretimde launchd plist'e
// (com.aegis.scan) taşınabilir; iskelet README'de.
//
class Scheduler {
  /**
   * @param {{intervalHours:number, onTick:Function, jitter?:boolean}} opts
   */
  constructor({ intervalHours = 24, onTick, jitter = true } = {}) {
    this.intervalHours = intervalHours;
    this.onTick = onTick;
    this.jitter = jitter;
    this.timer = null;
    this.checkTimer = null;
    this.nextRun = null;
    this.lastRun = null;
    this.runs = 0;
    this.enabled = false;
  }

  start() {
    if (this.enabled) return;
    this.enabled = true;
    this.scheduleNext();

    // Her dakika kontrol et: vakti geldi mi?
    this.checkTimer = setInterval(() => {
      if (this.nextRun && Date.now() >= this.nextRun) this.tick();
    }, 60 * 1000);
    if (this.checkTimer.unref) this.checkTimer.unref();
  }

  stop() {
    this.enabled = false;
    if (this.checkTimer) clearInterval(this.checkTimer);
    if (this.timer) clearTimeout(this.timer);
    this.checkTimer = null;
    this.timer = null;
    this.nextRun = null;
  }

  scheduleNext() {
    let ms = this.intervalHours * 3600 * 1000;
    if (this.jitter && ms > 10 * 60 * 1000) {
      // Rastgele %10 sapma: aynı saatte toplu tarama yükü olmasın
      ms += Math.floor((Math.random() - 0.5) * 0.1 * ms);
    }
    this.nextRun = Date.now() + ms;
  }

  tick() {
    this.lastRun = Date.now();
    this.runs++;
    this.scheduleNext();
    try {
      this.onTick && this.onTick({ scheduled: true, at: this.lastRun });
    } catch (err) {
      console.error('scheduler onTick error:', err);
    }
  }

  /** Test/manuel tetikleme */
  runNow() {
    this.tick();
  }

  setIntervalHours(h) {
    this.intervalHours = h;
    if (this.enabled) this.scheduleNext();
  }

  status() {
    return {
      enabled: this.enabled,
      intervalHours: this.intervalHours,
      lastRun: this.lastRun,
      nextRun: this.nextRun,
      runs: this.runs
    };
  }
}

module.exports = { Scheduler };
