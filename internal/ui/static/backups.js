'use strict';
// Backups page: schedule, last result, stored backups, run now.

(() => {
  const {t, esc, fmtBytes, fmtTime, toast, post} = App;

  App.page('backups', {title: 'nav.backups', admin: true, render});

  let poll;

  async function render(el) {
    clearTimeout(poll);
    const res = await App.api('/ui/api/backup');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    const d = res.data;
    if (!d.enabled) {
      el.innerHTML = `
        <h2 class="page">${esc(t('nav.backups'))}</h2>
        <div class="card"><p>${esc(t('bk.off'))}</p>
          <pre class="mono small">RGSTR_BACKUP_TARGET=s3://my-bucket/rgstr
RGSTR_BACKUP_S3_ENDPOINT=https://storage.example.com
RGSTR_BACKUP_S3_ACCESS_KEY=...
RGSTR_BACKUP_S3_SECRET_KEY=...
RGSTR_BACKUP_SCHEDULE=0 3 * * *
RGSTR_BACKUP_KEEP=7</pre>
          <p class="muted small">${esc(t('bk.offDir'))}</p></div>`;
      return;
    }
    const st = d.status;
    el.innerHTML = `
      <h2 class="page">${esc(t('nav.backups'))}</h2>
      <p class="muted small" style="margin:-8px 0 16px">${esc(t('bk.intro'))}</p>
      ${st.last_error ? `<div class="err" style="display:block;margin-bottom:12px">${esc(t('bk.failed', {time: fmtTime(st.last_error_at), error: st.last_error}))}</div>` : ''}
      ${d.list_error ? `<div class="err" style="display:block;margin-bottom:12px">${esc(t('bk.listFailed', {error: d.list_error}))}</div>` : ''}
      <div class="card">
        <table class="kv">
          <tr><th>${esc(t('bk.target'))}</th><td class="mono">${esc(st.target)}</td></tr>
          <tr><th>${esc(t('bk.schedule'))}</th><td><span class="mono">${esc(st.schedule)}</span> <span class="muted small">(UTC)</span>
            ${st.next ? `<span class="muted small"> · ${esc(t('bk.next', {time: fmtTime(st.next)}))}</span>` : ''}</td></tr>
          <tr><th>${esc(t('bk.keep'))}</th><td>${esc(st.keep)}</td></tr>
          <tr><th>${esc(t('bk.last'))}</th><td>${st.last_success
            ? esc(t('bk.lastOk', {time: fmtTime(st.last_success), size: fmtBytes(st.last_size)}))
            : `<span class="muted">${esc(t('bk.none'))}</span>`}</td></tr>
        </table>
        <button class="btn btn-primary" id="bk-run" style="margin-top:12px" ${st.running ? 'disabled' : ''}>
          ${esc(st.running ? t('bk.running') : t('bk.run'))}</button>
      </div>

      <h3>${esc(t('bk.list'))}</h3>
      ${d.backups.length ? `<div class="tbl-wrap"><table class="tbl">
        <tr><th>${esc(t('bk.name'))}</th><th>${esc(t('bk.time'))}</th><th>${esc(t('bk.size'))}</th></tr>
        ${d.backups.map(b => `<tr><td class="mono">${esc(b.name)}</td><td>${esc(fmtTime(b.time))}</td><td>${esc(fmtBytes(b.size))}</td></tr>`).join('')}
      </table></div>` : `<div class="empty">${esc(t('bk.empty'))}</div>`}

      <h3>${esc(t('bk.restore'))}</h3>
      <p class="muted small">${esc(t('bk.restoreNote'))}</p>
      <pre class="card mono small" style="user-select:all">rgstr restore latest        # ${esc(t('bk.restoreLatest'))}
rgstr restore ${esc(d.backups[0] ? d.backups[0].name : 'rgstr-backup-YYYYMMDD-HHMMSS.tar')}
rgstr restore -force latest  # ${esc(t('bk.restoreForce'))}</pre>`;

    el.querySelector('#bk-run').addEventListener('click', async e => {
      e.target.disabled = true;
      const r = await post('/ui/api/backup/run', {});
      if (!r.ok && r.status !== 202) { toast(r.data.error || t('common.failed', {status: r.status})); e.target.disabled = false; return; }
      toast(t('bk.started'));
      App.route();
    });
    // Follow a running backup.
    if (st.running) poll = setTimeout(() => { if (location.hash.startsWith('#backups')) App.route(); }, 3000);
  }
})();

App.addLang('en', {
  'nav.backups': 'Backups',
  'bk.off': 'Backups are not configured. Set RGSTR_BACKUP_TARGET to an S3 bucket or a directory, for example:',
  'bk.offDir': 'Or a directory (a mounted NFS share, a second disk): RGSTR_BACKUP_TARGET=/backups. See the README, section "Backups".',
  'bk.intro': 'A backup holds everything: images, users, projects, robots, settings and the audit log. It is taken while the registry runs; garbage collection waits until it is done.',
  'bk.target': 'Target',
  'bk.schedule': 'Schedule',
  'bk.next': 'next {time}',
  'bk.keep': 'Backups kept',
  'bk.last': 'Last backup',
  'bk.lastOk': '{time}, {size}',
  'bk.none': 'none yet',
  'bk.failed': 'The last backup failed ({time}): {error}',
  'bk.listFailed': 'Could not list backups: {error}',
  'bk.run': 'Back up now',
  'bk.running': 'Backing up…',
  'bk.started': 'Backup started',
  'bk.list': 'Stored backups',
  'bk.empty': 'No backups yet.',
  'bk.name': 'Name',
  'bk.time': 'Taken',
  'bk.size': 'Size',
  'bk.restore': 'Restore',
  'bk.restoreNote': 'Stop rgstr, then run with the same environment (RGSTR_STORAGE, RGSTR_BACKUP_*). Without -force the data directory must be empty; with -force the current data is moved to .before-restore-<time>/ inside it.',
  'bk.restoreLatest': 'the newest backup',
  'bk.restoreForce': 'over existing data',
  'act.backup_run': 'backup',
});
