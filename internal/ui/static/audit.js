'use strict';
// Audit log page: who did what, with filters and paging.

(() => {
  const {t, esc, fmtTime} = App;
  const PAGE = 200;

  App.page('audit', {title: 'nav.audit', admin: true, render});

  const filter = {user: '', action: '', q: ''};
  let entries = [];
  let actions = [];
  let root = null;

  async function render(el) {
    root = el;
    entries = [];
    const ok = await load();
    if (!ok) return;

    el.innerHTML = `
      <h2 class="page">${esc(t('nav.audit'))}</h2>
      <form class="toolbar form" id="audit-filter">
        <input name="user" placeholder="${esc(t('audit.user'))}" value="${esc(filter.user)}" style="width:160px;margin:0">
        <select name="action" style="width:auto;margin:0">
          <option value="">${esc(t('audit.allActions'))}</option>
          ${actions.map(a => `<option value="${a}" ${a === filter.action ? 'selected' : ''}>${esc(actionName(a))}</option>`).join('')}
        </select>
        <input name="q" class="grow" placeholder="${esc(t('audit.search'))}" value="${esc(filter.q)}" style="margin:0">
        <button class="btn btn-primary">${esc(t('audit.apply'))}</button>
      </form>
      <div id="audit-table"></div>`;
    el.querySelector('#audit-filter').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target.elements;
      filter.user = f.user.value.trim();
      filter.action = f.action.value;
      filter.q = f.q.value.trim();
      entries = [];
      if (await load()) renderTable();
    });
    renderTable();
  }

  async function load(before) {
    const p = new URLSearchParams({limit: PAGE});
    if (filter.user) p.set('user', filter.user);
    if (filter.action) p.set('action', filter.action);
    if (filter.q) p.set('q', filter.q);
    if (before) p.set('before', before);
    const res = await App.api('/ui/api/audit?' + p);
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    actions = res.data.actions;
    entries = entries.concat(res.data.entries);
    return res.data.entries;
  }

  function renderTable() {
    const box = root.querySelector('#audit-table');
    if (!entries.length) { box.innerHTML = `<div class="empty">${esc(t('audit.none'))}</div>`; return; }
    box.innerHTML = `
      <div class="tbl-wrap"><table class="tbl">
        <tr><th>${esc(t('audit.time'))}</th><th>${esc(t('audit.user'))}</th><th>${esc(t('audit.action'))}</th>
          <th>${esc(t('audit.resource'))}</th><th>${esc(t('audit.details'))}</th><th>IP</th></tr>
        ${entries.map(e => `
          <tr>
            <td style="white-space:nowrap">${esc(fmtTime(e.time))}</td>
            <td>${esc(e.user || t('gc.anonymous'))}</td>
            <td><span class="badge ${badgeClass(e)}">${esc(actionName(e.action))}</span></td>
            <td class="mono small" style="word-break:break-all">${esc(e.resource || '')}</td>
            <td class="small">${esc(e.detail || '')}${e.error ? `<div class="err" style="display:block;margin:2px 0 0">${esc(e.error)}</div>` : ''}</td>
            <td class="small muted">${esc(e.ip || '')}</td>
          </tr>`).join('')}
      </table></div>
      ${entries.length % PAGE === 0 ? `<div class="toolbar" style="margin-top:12px"><button class="btn" id="audit-more">${esc(t('audit.more'))}</button></div>` : ''}`;
    const more = box.querySelector('#audit-more');
    if (more) more.addEventListener('click', async () => {
      more.disabled = true;
      const got = await load(entries[entries.length - 1].time);
      renderTable();
      if (!got.length) toast(t('audit.end'));
    });
  }

  const toast = App.toast;

  function badgeClass(e) {
    if (e.error || e.action === 'login_failed') return 'badge-err';
    if (e.action.startsWith('delete') || e.action === 'user_delete') return 'badge-warn';
    if (e.action === 'push') return 'badge-ok';
    return '';
  }

  function actionName(a) { return t('act.' + a); }
})();

App.addLang('en', {
  'nav.audit': 'Audit log',
  'audit.user': 'User',
  'audit.allActions': 'All actions',
  'audit.search': 'Search repository, tag, details, IP…',
  'audit.apply': 'Apply',
  'audit.none': 'No entries.',
  'audit.time': 'Time',
  'audit.action': 'Action',
  'audit.resource': 'Object',
  'audit.details': 'Details',
  'audit.more': 'Load older',
  'audit.end': 'No older entries',
  'act.push': 'push',
  'act.pull': 'pull',
  'act.delete_tag': 'delete tag',
  'act.delete_image': 'delete image',
  'act.delete_repo': 'delete repository',
  'act.login': 'sign in',
  'act.login_failed': 'failed sign-in',
  'act.password_change': 'password change',
  'act.user_create': 'create user',
  'act.user_delete': 'delete user',
  'act.user_role': 'change role',
  'act.user_password_reset': 'reset password',
  'act.gc_run': 'GC run',
  'act.gc_settings': 'GC schedule',
  'act.retention_run': 'retention run',
  'act.policy_change': 'policy change',
  'act.project_create': 'create project',
  'act.project_update': 'update project',
  'act.project_delete': 'delete project',
  'act.project_member': 'project member',
});
