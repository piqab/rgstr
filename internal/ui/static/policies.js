'use strict';
// Policies page: tag retention and immutable tags.

(() => {
  const {t, esc, fmtTime, toast, post} = App;

  App.page('policies', {title: 'nav.policies', admin: true, render});

  let data = null;

  async function render(el) {
    const res = await App.api('/ui/api/policies');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    data = res.data;
    const gcOff = data.gc_interval === '0s';

    el.innerHTML = `
      <h2 class="page">${esc(t('nav.policies'))}</h2>

      <div class="card">
        <div class="toolbar" style="margin-bottom:6px">
          <h3 class="grow" style="margin:0">${esc(t('pol.retention'))}</h3>
          <button class="btn" data-act="ret-dry" ${data.retention.length ? '' : 'disabled'}>${esc(t('pol.dryRun'))}</button>
          <button class="btn btn-danger" data-act="ret-run" ${data.retention.length ? '' : 'disabled'}>${esc(t('pol.runNow'))}</button>
          <button class="btn btn-primary" data-act="ret-add">${esc(t('pol.addRule'))}</button>
        </div>
        <p class="muted small" style="margin-bottom:12px">${esc(t('pol.retentionIntro'))}
          ${esc(gcOff ? t('pol.scheduleOff') : t('pol.schedule', {interval: App.humanDur(data.gc_interval)}))}</p>
        ${data.retention.length ? retentionTable() : `<div class="empty">${esc(t('pol.noRetention'))}</div>`}
      </div>

      <div class="card">
        <div class="toolbar" style="margin-bottom:6px">
          <h3 class="grow" style="margin:0">${esc(t('pol.immutable'))}</h3>
          <button class="btn btn-primary" data-act="imm-add">${esc(t('pol.addRule'))}</button>
        </div>
        <p class="muted small" style="margin-bottom:12px">${esc(t('pol.immutableIntro'))}</p>
        ${data.immutable.length ? immutableTable() : `<div class="empty">${esc(t('pol.noImmutable'))}</div>`}
      </div>

      <h3>${esc(t('pol.history'))}</h3>
      ${data.retention_history.length ? historyTable() : `<div class="empty">${esc(t('pol.noHistory'))}</div>`}`;

    el.addEventListener('click', onClick);
  }

  function retentionTable() {
    return `<div class="tbl-wrap"><table class="tbl">
      <tr><th>${esc(t('pol.repos'))}</th><th>${esc(t('pol.tags'))}</th><th>${esc(t('pol.keep'))}</th><th></th><th></th></tr>
      ${data.retention.map((r, i) => `
        <tr>
          <td class="mono">${esc(r.repos)}</td>
          <td class="mono">${esc(r.tags)}</td>
          <td>${esc(keepText(r))}</td>
          <td>${r.disabled ? `<span class="badge">${esc(t('pol.disabled'))}</span>` : `<span class="badge badge-ok">${esc(t('pol.enabled'))}</span>`}</td>
          <td class="actions">
            <button class="btn btn-sm" data-act="ret-edit" data-i="${i}">${esc(t('pol.edit'))}</button>
            <button class="btn btn-sm btn-danger" data-act="ret-del" data-i="${i}">${esc(t('common.delete'))}</button>
          </td>
        </tr>`).join('')}
    </table></div>`;
  }

  function immutableTable() {
    return `<div class="tbl-wrap"><table class="tbl">
      <tr><th>${esc(t('pol.repos'))}</th><th>${esc(t('pol.tags'))}</th><th></th><th></th></tr>
      ${data.immutable.map((r, i) => `
        <tr>
          <td class="mono">${esc(r.repos)}</td>
          <td class="mono">${esc(r.tags)}</td>
          <td>${r.disabled ? `<span class="badge">${esc(t('pol.disabled'))}</span>` : `<span class="badge badge-ok">${esc(t('pol.enabled'))}</span>`}</td>
          <td class="actions">
            <button class="btn btn-sm" data-act="imm-edit" data-i="${i}">${esc(t('pol.edit'))}</button>
            <button class="btn btn-sm btn-danger" data-act="imm-del" data-i="${i}">${esc(t('common.delete'))}</button>
          </td>
        </tr>`).join('')}
    </table></div>`;
  }

  function historyTable() {
    return `<div class="tbl-wrap"><table class="tbl">
      <tr><th>${esc(t('gc.colStart'))}</th><th>${esc(t('gc.colTrigger'))}</th><th>${esc(t('pol.colDeleted'))}</th></tr>
      ${data.retention_history.map((r, i) => `
        <tr data-act="hist" data-i="${i}" style="cursor:pointer">
          <td>${esc(fmtTime(r.start))} ${r.dry_run ? `<span class="badge badge-blue">${esc(t('gc.dry'))}</span>` : ''}
            ${r.error ? `<span class="badge badge-err" title="${esc(r.error)}">${esc(t('gc.error'))}</span>` : ''}</td>
          <td>${esc(r.trigger === 'manual' ? t('gc.manual', {user: r.user || t('gc.anonymous')}) : t('gc.scheduled'))}</td>
          <td>${r.tags_count}</td>
        </tr>`).join('')}
    </table></div>`;
  }

  function keepText(r) {
    const parts = [];
    if (r.keep_last) parts.push(t('pol.keepLast', {n: r.keep_last}));
    if (r.keep_days) parts.push(t('pol.keepDays', {n: r.keep_days}));
    return parts.join(t('pol.or'));
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  function onClick(e) {
    const el = e.target.closest('[data-act]');
    if (!el) return;
    const i = +el.dataset.i;
    switch (el.dataset.act) {
      case 'ret-add': return editRetention(-1);
      case 'ret-edit': return editRetention(i);
      case 'ret-del':
        if (confirm(t('pol.confirmDelete'))) saveRetention(data.retention.filter((_, j) => j !== i));
        return;
      case 'imm-add': return editImmutable(-1);
      case 'imm-edit': return editImmutable(i);
      case 'imm-del':
        if (confirm(t('pol.confirmDelete'))) saveImmutable(data.immutable.filter((_, j) => j !== i));
        return;
      case 'ret-dry': return runRetention(true);
      case 'ret-run':
        if (confirm(t('pol.confirmRun'))) runRetention(false);
        return;
      case 'hist': return showRun(data.retention_history[i]);
    }
  }

  function editRetention(i) {
    const r = i >= 0 ? data.retention[i] : {repos: '**', tags: '*', keep_last: 10, keep_days: 0};
    const m = App.openModal(`
      <h2>${esc(i >= 0 ? t('pol.editRetention') : t('pol.newRetention'))}</h2>
      <form class="form" id="f">
        <label>${esc(t('pol.repos'))}</label>
        <input name="repos" value="${esc(r.repos)}" required>
        <label>${esc(t('pol.tags'))}</label>
        <input name="tags" value="${esc(r.tags)}" required>
        <p class="muted small" style="margin:-8px 0 14px">${esc(t('pol.globHint'))}</p>
        <label>${esc(t('pol.keepLastLabel'))}</label>
        <input name="keep_last" type="number" min="0" value="${r.keep_last || 0}">
        <label>${esc(t('pol.keepDaysLabel'))}</label>
        <input name="keep_days" type="number" min="0" value="${r.keep_days || 0}">
        <p class="muted small" style="margin:-8px 0 14px">${esc(t('pol.keepHint'))}</p>
        <label class="check"><input type="checkbox" name="enabled" ${r.disabled ? '' : 'checked'}>${esc(t('pol.enabled'))}</label>
        <div class="err" id="f-err"></div>
        <div class="dialog-actions">
          <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-primary">${esc(t('common.save'))}</button>
        </div>
      </form>`);
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('#f').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target;
      const rule = {
        repos: f.repos.value.trim(), tags: f.tags.value.trim(),
        keep_last: +f.keep_last.value || 0, keep_days: +f.keep_days.value || 0, disabled: !f.enabled.checked,
      };
      const rules = data.retention.slice();
      if (i >= 0) rules[i] = rule; else rules.push(rule);
      const err = await saveRetention(rules);
      if (err) showErr(m, err);
    });
  }

  function editImmutable(i) {
    const r = i >= 0 ? data.immutable[i] : {repos: '**', tags: 'v*'};
    const m = App.openModal(`
      <h2>${esc(i >= 0 ? t('pol.editImmutable') : t('pol.newImmutable'))}</h2>
      <form class="form" id="f">
        <label>${esc(t('pol.repos'))}</label>
        <input name="repos" value="${esc(r.repos)}" required>
        <label>${esc(t('pol.tags'))}</label>
        <input name="tags" value="${esc(r.tags)}" required>
        <p class="muted small" style="margin:-8px 0 14px">${esc(t('pol.globHint'))}</p>
        <label class="check"><input type="checkbox" name="enabled" ${r.disabled ? '' : 'checked'}>${esc(t('pol.enabled'))}</label>
        <div class="err" id="f-err"></div>
        <div class="dialog-actions">
          <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-primary">${esc(t('common.save'))}</button>
        </div>
      </form>`);
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('#f').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target;
      const rule = {repos: f.repos.value.trim(), tags: f.tags.value.trim(), disabled: !f.enabled.checked};
      const rules = data.immutable.slice();
      if (i >= 0) rules[i] = rule; else rules.push(rule);
      const err = await saveImmutable(rules);
      if (err) showErr(m, err);
    });
  }

  function showErr(m, msg) {
    const el = m.querySelector('#f-err');
    el.textContent = msg;
    el.style.display = 'block';
  }

  async function saveRetention(rules) { return save('/ui/api/policies/retention', rules); }
  async function saveImmutable(rules) { return save('/ui/api/policies/immutable', rules); }

  async function save(path, rules) {
    const res = await post(path, {rules});
    if (!res.ok) {
      const msg = res.data.error || t('common.failed', {status: res.status});
      if (!document.querySelector('#modal-overlay.show')) toast(msg);
      return msg;
    }
    App.closeModal();
    toast(t('pol.saved'));
    App.route();
    return '';
  }

  async function runRetention(dryRun) {
    const res = await post('/ui/api/policies/retention/run', {dry_run: dryRun});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    await App.route();
    showRun(res.data);
  }

  function showRun(r) {
    const list = r.tags && r.tags.length
      ? `<div class="tbl-wrap" style="max-height:320px;overflow:auto"><table class="tbl">${r.tags.map(x => `<tr><td class="mono small">${esc(x)}</td></tr>`).join('')}</table></div>
         ${r.tags_count > r.tags.length ? `<p class="muted small">${esc(t('gc.more', {n: r.tags_count - r.tags.length}))}</p>` : ''}`
      : `<p class="muted">${esc(t('pol.nothing'))}</p>`;
    const m = App.openModal(`
      <h2>${esc(r.dry_run ? t('pol.resultDry', {n: r.tags_count}) : t('pol.result', {n: r.tags_count}))}</h2>
      ${r.error ? `<p class="err" style="display:block">${esc(r.error)}</p>` : ''}
      ${list}
      ${r.dry_run ? '' : `<p class="muted small" style="margin-top:10px">${esc(t('pol.afterRun'))}</p>`}
      <div class="dialog-actions"><button class="btn" id="m-close">${esc(t('common.close'))}</button></div>`);
    m.querySelector('#m-close').addEventListener('click', App.closeModal);
  }
})();

App.addLang('en', {
  'nav.policies': 'Policies',
  'pol.retention': 'Tag retention',
  'pol.retentionIntro': 'Rules keep some tags of matching repositories; other matching tags are deleted. A tag is deleted only if no rule covering it keeps it. Immutable tags are never deleted.',
  'pol.schedule': 'Applied automatically before each scheduled GC (every {interval}).',
  'pol.scheduleOff': 'Scheduled GC is off, so rules are applied only with "Run now".',
  'pol.immutable': 'Immutable tags',
  'pol.immutableIntro': 'Matching tags cannot be overwritten with another image or deleted — by docker push, the admin or retention. Remove or disable the rule first.',
  'pol.addRule': 'Add rule',
  'pol.dryRun': 'Dry run',
  'pol.runNow': 'Run now',
  'pol.noRetention': 'No retention rules: nothing is deleted automatically.',
  'pol.noImmutable': 'No immutability rules.',
  'pol.repos': 'Repositories',
  'pol.tags': 'Tags',
  'pol.keep': 'Keep',
  'pol.keepLast': 'last {n} pushed',
  'pol.keepDays': 'pushed within {n} days',
  'pol.or': ' or ',
  'pol.enabled': 'Enabled',
  'pol.disabled': 'disabled',
  'pol.edit': 'Edit',
  'pol.newRetention': 'New retention rule',
  'pol.editRetention': 'Edit retention rule',
  'pol.newImmutable': 'New immutability rule',
  'pol.editImmutable': 'Edit immutability rule',
  'pol.globHint': 'Patterns: * — any characters except "/", ** — any path, ? — one character. Examples: team/**, *, v*, dev-*',
  'pol.keepLastLabel': 'Keep the last N pushed tags (0 — not used)',
  'pol.keepDaysLabel': 'Keep tags pushed within N days (0 — not used)',
  'pol.keepHint': 'A tag is kept if it satisfies either condition.',
  'pol.confirmDelete': 'Delete this rule?',
  'pol.confirmRun': 'Apply retention rules now?\nExpired tags are deleted immediately.',
  'pol.saved': 'Rules saved',
  'pol.history': 'Retention runs',
  'pol.noHistory': 'No runs yet.',
  'pol.colDeleted': 'Tags',
  'pol.resultDry': 'Dry run: {n} tag(s) would be deleted',
  'pol.result': '{n} tag(s) deleted',
  'pol.nothing': 'Nothing to delete.',
  'pol.afterRun': 'Disk space is freed by the next GC run.',
});
