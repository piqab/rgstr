'use strict';
// Garbage collection page: schedule, manual and dry runs, history.

(() => {
  const {t, esc, fmtBytes, fmtTime, toast, post} = App;

  App.page('gc', {title: 'nav.gc', admin: true, render});

  let history = [];

  async function render(el) {
    const res = await App.api('/ui/api/gc');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    const st = res.data;
    history = st.history;
    const off = st.interval === '0s';

    el.innerHTML = `
      <h2 class="page">${esc(t('nav.gc'))}</h2>
      <p class="muted small" style="margin:-8px 0 16px">${esc(t('gc.intro', {grace: humanDur(st.grace_period)}))}</p>

      <div class="card" id="gc-disk"><div class="loading">${esc(t('common.loading'))}</div></div>

      <div class="card">
        <h3 style="margin-top:0">${esc(t('gc.schedule'))}</h3>
        <p style="margin-bottom:12px">${off ? esc(t('gc.off')) : esc(t('gc.every', {interval: humanDur(st.interval)}))}
          <span class="badge ${st.from_ui ? 'badge-blue' : ''}">${esc(st.from_ui ? t('gc.fromUI') : t('gc.fromEnv'))}</span>
          ${st.next_run ? `<span class="muted small"> · ${esc(t('gc.next', {time: fmtTime(st.next_run)}))}</span>` : ''}</p>
        <form class="form toolbar" id="gc-schedule" style="margin:0">
          <select id="gc-interval" style="width:auto;margin:0">
            ${['0', '1h', '6h', '12h', '24h', '168h'].map(v =>
              `<option value="${v}">${esc(v === '0' ? t('gc.optOff') : t('gc.opt', {interval: humanDur(v)}))}</option>`).join('')}
            <option value="custom">${esc(t('gc.optCustom'))}</option>
          </select>
          <input id="gc-custom" placeholder="${esc(t('gc.customHint'))}" style="width:160px;margin:0;display:none">
          <button class="btn btn-primary" type="submit">${esc(t('common.save'))}</button>
          ${st.from_ui ? `<button class="btn" type="button" id="gc-reset">${esc(t('gc.reset', {interval: humanDur(st.env_interval)}))}</button>` : ''}
        </form>
      </div>

      <div class="card">
        <h3 style="margin-top:0">${esc(t('gc.runNow'))}</h3>
        <label class="check"><input type="checkbox" id="gc-dry" checked>${esc(t('gc.dryRun'))}</label>
        <label class="check"><input type="checkbox" id="gc-grace">${esc(t('gc.ignoreGrace'))}</label>
        <p class="muted small" style="margin:-6px 0 12px">${esc(t('gc.ignoreGraceHint', {grace: humanDur(st.grace_period)}))}</p>
        <button class="btn btn-primary" id="gc-run" ${st.running ? 'disabled' : ''}>${esc(st.running ? t('gc.running') : t('gc.run'))}</button>
      </div>

      <h3>${esc(t('gc.history'))}</h3>
      ${history.length ? historyTable() : `<div class="empty">${esc(t('gc.noHistory'))}</div>`}`;

    const sel = el.querySelector('#gc-interval');
    const custom = el.querySelector('#gc-custom');
    const preset = ['0s', '1h0m0s', '6h0m0s', '12h0m0s', '24h0m0s', '168h0m0s'];
    const idx = preset.indexOf(st.interval);
    if (idx >= 0) sel.selectedIndex = idx; else { sel.value = 'custom'; custom.value = st.interval; custom.style.display = ''; }
    sel.addEventListener('change', () => { custom.style.display = sel.value === 'custom' ? '' : 'none'; });

    el.querySelector('#gc-schedule').addEventListener('submit', async e => {
      e.preventDefault();
      const interval = sel.value === 'custom' ? custom.value.trim() : sel.value;
      await saveInterval(interval);
    });
    const reset = el.querySelector('#gc-reset');
    if (reset) reset.addEventListener('click', () => saveInterval(''));
    el.querySelector('#gc-run').addEventListener('click', e => run(e.target, el));
    el.querySelectorAll('[data-run]').forEach(tr => tr.addEventListener('click', () => showRun(history[+tr.dataset.run])));
    loadDisk(el.querySelector('#gc-disk'), st.grace_period);
  }

  // Disk: free space, registry data, what GC frees now / after the grace
  // period, and deleted data waiting for GC.
  async function loadDisk(card, grace) {
    const res = await App.api('/ui/api/disk?details=1');
    if (!card.isConnected) return;
    if (!res.ok) { card.innerHTML = `<div class="err" style="display:block">${esc(res.data.error || '')}</div>`; return; }
    const d = res.data;
    const used = d.total - d.free;
    const pct = d.total ? Math.round(used / d.total * 100) : 0;
    const est = d.estimate || {next: 0, grace: 0};
    const pending = d.pending || [];
    card.innerHTML = `
      <h3 style="margin-top:0">${esc(t('disk.title'))}</h3>
      ${d.supported ? `
        <div class="small">${esc(t('disk.summary', {free: fmtBytes(d.free), total: fmtBytes(d.total), pct}))}</div>
        <div class="bar ${d.low ? 'bar-err' : pct >= 80 ? 'bar-warn' : ''}" style="max-width:none;margin:6px 0 12px"><div style="width:${pct}%"></div></div>` : ''}
      <table class="kv">
        <tr><th>${esc(t('disk.registry'))}</th><td>${esc(fmtBytes(d.data_bytes))}</td></tr>
        <tr><th>${esc(t('disk.next'))}</th><td><b>${esc(fmtBytes(est.next))}</b></td></tr>
        <tr><th>${esc(t('disk.afterGrace', {grace: humanDur(grace)}))}</th><td>${esc(fmtBytes(est.grace))}
          ${est.grace ? `<span class="muted small"> — ${esc(t('disk.afterGraceHint'))}</span>` : ''}</td></tr>
      </table>
      ${pending.length ? `
        <h3>${esc(t('disk.pending'))}</h3>
        <div class="tbl-wrap"><table class="tbl">
          <tr><th>${esc(t('disk.what'))}</th><th>${esc(t('disk.deleted'))}</th><th>${esc(t('img.size'))}</th></tr>
          ${pending.map(p => `<tr>
            <td><span class="badge">${esc(t('disk.kind.' + p.kind))}</span> <span class="mono small">${esc(p.ref)}</span></td>
            <td class="small">${esc(fmtTime(p.time))}${p.user ? ' · ' + esc(p.user) : ''}</td>
            <td>${esc(fmtBytes(p.bytes))}</td></tr>`).join('')}
        </table></div>
        <p class="muted small" style="margin-top:6px">${esc(t('disk.pendingHint'))}</p>` : ''}`;
  }

  function historyTable() {
    return `<div class="tbl-wrap"><table class="tbl">
      <tr><th>${esc(t('gc.colStart'))}</th><th>${esc(t('gc.colTrigger'))}</th><th>${esc(t('gc.colFreed'))}</th>
        <th>${esc(t('gc.colBlobs'))}</th><th>${esc(t('gc.colManifests'))}</th><th>${esc(t('gc.colUploads'))}</th><th>${esc(t('gc.colDuration'))}</th></tr>
      ${history.map((r, i) => `
        <tr data-run="${i}" style="cursor:pointer">
          <td>${esc(fmtTime(r.start))}
            ${r.dry_run ? `<span class="badge badge-blue">${esc(t('gc.dry'))}</span>` : ''}
            ${r.ignore_grace ? `<span class="badge badge-warn">${esc(t('gc.noGrace'))}</span>` : ''}
            ${r.error ? `<span class="badge badge-err" title="${esc(r.error)}">${esc(t('gc.error'))}</span>` : ''}</td>
          <td>${esc(r.trigger === 'manual' ? t('gc.manual', {user: r.user || t('gc.anonymous')}) : t('gc.scheduled'))}</td>
          <td>${esc(fmtBytes(r.bytes_freed))}</td>
          <td>${r.blobs_removed}</td><td>${r.manifests_removed}</td><td>${r.uploads_removed}</td>
          <td>${esc((r.duration_ms / 1000).toFixed(1))} s</td>
        </tr>`).join('')}
    </table></div>`;
  }

  async function saveInterval(interval) {
    const res = await post('/ui/api/gc/settings', {interval});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    toast(t('gc.saved'));
    App.route();
  }

  async function run(btn, el) {
    const dry = el.querySelector('#gc-dry').checked;
    const ignoreGrace = el.querySelector('#gc-grace').checked;
    if (!dry && ignoreGrace && !confirm(t('gc.confirmNoGrace'))) return;
    btn.disabled = true;
    btn.textContent = t('gc.running');
    const res = await post('/ui/api/gc/run', {dry_run: dry, ignore_grace: ignoreGrace});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); App.route(); return; }
    await App.route();
    showRun(res.data);
  }

  function showRun(r) {
    const freed = r.freed && r.freed.length ? `
      <h3>${esc(t('gc.freedFrom'))}</h3>
      ${r.freed.map(f => { const i = f.indexOf(' '); return `<div><span class="badge">${esc(t('disk.kind.' + f.slice(0, i)))}</span> <span class="mono small">${esc(f.slice(i + 1))}</span></div>`; }).join('')}` : '';
    const list = r.manifests && r.manifests.length ? `
      <h3>${esc(t('gc.manifestsList'))}</h3>
      <div class="tbl-wrap" style="max-height:300px;overflow:auto"><table class="tbl">${r.manifests.map(m => `<tr><td class="mono small">${esc(m)}</td></tr>`).join('')}</table></div>
      ${r.manifests_removed > r.manifests.length ? `<p class="muted small">${esc(t('gc.more', {n: r.manifests_removed - r.manifests.length}))}</p>` : ''}` : '';
    const nothing = !freed && !list && !r.bytes_freed ? `<p class="muted">${esc(r.dry_run ? t('gc.nothingDry') : t('gc.nothing'))}</p>` : '';
    const m = App.openModal(`
      <h2>${esc(r.dry_run ? t('gc.resultDry') : t('gc.result'))}</h2>
      ${r.error ? `<p class="err" style="display:block">${esc(r.error)}</p>` : ''}
      <div class="stats-bar">
        <div class="stat-card"><div class="val">${esc(fmtBytes(r.bytes_freed))}</div><div class="lbl">${esc(r.dry_run ? t('gc.wouldFree') : t('gc.freed'))}</div></div>
        <div class="stat-card"><div class="val">${r.blobs_removed}</div><div class="lbl">${esc(t('gc.colBlobs'))}</div></div>
        <div class="stat-card"><div class="val">${r.manifests_removed}</div><div class="lbl">${esc(t('gc.colManifests'))}</div></div>
        <div class="stat-card"><div class="val">${r.uploads_removed}</div><div class="lbl">${esc(t('gc.colUploads'))}</div></div>
      </div>
      ${freed}${list}${nothing}
      <div class="dialog-actions"><button class="btn" id="m-close">${esc(t('common.close'))}</button></div>`);
    m.querySelector('#m-close').addEventListener('click', App.closeModal);
  }

  // "6h0m0s" → "6h", "168h0m0s" → "7d", "0s" → "0".
  function humanDur(s) {
    if (!s) return '';
    const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(s);
    if (!m) return s;
    const h = +(m[1] || 0), min = +(m[2] || 0), sec = +(m[3] || 0);
    if (!h && !min && !sec) return '0';
    const parts = [];
    if (h && h % 24 === 0) parts.push(t('dur.d', {n: h / 24})); else if (h) parts.push(t('dur.h', {n: h}));
    if (min) parts.push(t('dur.m', {n: min}));
    if (sec) parts.push(t('dur.s', {n: sec}));
    return parts.join(' ');
  }
  App.humanDur = humanDur;
})();

App.addLang('en', {
  'nav.gc': 'Garbage collection',
  'gc.intro': 'GC removes images that no tag points to and frees their disk space. Data uploaded within the last {grace} is kept so pushes in progress are not broken.',
  'gc.schedule': 'Schedule',
  'gc.off': 'Scheduled runs are off.',
  'gc.every': 'Runs every {interval}.',
  'gc.fromUI': 'set here',
  'gc.fromEnv': 'from RGSTR_GC_INTERVAL',
  'gc.next': 'next run {time}',
  'gc.optOff': 'Off',
  'gc.opt': 'Every {interval}',
  'gc.optCustom': 'Custom…',
  'gc.customHint': 'e.g. 30m, 3h, 48h',
  'gc.reset': 'Reset to env default ({interval})',
  'gc.saved': 'Schedule saved',
  'gc.runNow': 'Run now',
  'gc.dryRun': 'Dry run — only show what would be removed',
  'gc.ignoreGrace': 'Ignore grace period — free space right away',
  'gc.ignoreGraceHint': 'Also removes unreferenced data uploaded within the last {grace}. Do not use while someone is pushing: their push can break.',
  'gc.confirmNoGrace': 'Run GC ignoring the grace period?\nA push that is in progress right now can break.',
  'gc.run': 'Run GC',
  'gc.running': 'Running…',
  'gc.history': 'History',
  'gc.noHistory': 'No runs yet.',
  'gc.colStart': 'Started',
  'gc.colTrigger': 'Trigger',
  'gc.colFreed': 'Freed',
  'gc.colBlobs': 'blobs',
  'gc.colManifests': 'manifests',
  'gc.colUploads': 'stale uploads',
  'gc.colDuration': 'Duration',
  'gc.dry': 'dry run',
  'gc.noGrace': 'no grace',
  'gc.error': 'error',
  'gc.manual': 'manual ({user})',
  'gc.anonymous': 'anonymous',
  'gc.scheduled': 'schedule',
  'gc.result': 'GC finished',
  'gc.resultDry': 'Dry run result',
  'gc.freed': 'freed',
  'gc.wouldFree': 'would be freed',
  'gc.manifestsList': 'Untagged images removed by GC',
  'gc.freedFrom': 'Space freed from deleted',
  'gc.nothing': 'Nothing to remove.',
  'gc.nothingDry': 'Nothing would be removed now.',
  'disk.title': 'Disk',
  'disk.summary': '{free} free of {total} ({pct}% used)',
  'disk.next': 'Next GC frees',
  'disk.afterGrace': 'After the grace period ({grace}) also',
  'disk.afterGraceHint': 'recently pushed data, freed earlier only by a run ignoring the grace period',
  'disk.pending': 'Deleted, waiting for GC',
  'disk.what': 'What',
  'disk.deleted': 'Deleted',
  'disk.pendingHint': 'Sizes include layers shared with other images; those stay on disk.',
  'disk.kind.repository': 'repository',
  'disk.kind.tag': 'tag',
  'disk.kind.image': 'image',
  'gc.more': 'and {n} more',
  'dur.d': '{n}d',
  'dur.h': '{n}h',
  'dur.m': '{n}m',
  'dur.s': '{n}s',
});
