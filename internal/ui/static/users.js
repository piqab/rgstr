'use strict';
// Users page: create users, change roles, reset passwords, delete.

(() => {
  const {t, esc, fmtTime, toast, post} = App;

  App.page('users', {title: 'nav.users', admin: true, render});

  let data = null;

  async function render(el) {
    const res = await App.api('/ui/api/users');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    data = res.data;

    el.innerHTML = `
      <div class="toolbar">
        <h2 class="page grow" style="margin:0">${esc(t('nav.users'))}</h2>
        ${data.auth_enabled ? `<button class="btn btn-primary" data-act="add">${esc(t('users.add'))}</button>` : ''}
      </div>
      ${data.auth_enabled ? '' : `<div class="card"><p>${esc(t('users.authOff'))}</p></div>`}
      <p class="muted small" style="margin-bottom:12px">${esc(t('users.intro'))}</p>
      <div class="tbl-wrap"><table class="tbl">
        <tr><th>${esc(t('users.name'))}</th><th>${esc(t('users.source'))}</th><th>${esc(t('users.role'))}</th>
          <th>${esc(t('users.rights'))}</th><th>${esc(t('users.password'))}</th><th></th></tr>
        ${data.users.map(row).join('')}
      </table></div>`;

    el.addEventListener('click', onClick);
    el.addEventListener('change', onChange);
  }

  function row(u) {
    const me = u.name === data.me;
    const editable = u.source === 'admin' && !me;
    const roleCell = editable
      ? `<select data-act="role" data-name="${esc(u.name)}" style="padding:4px 6px">
          ${['admin', 'user', 'readonly'].map(r => `<option value="${r}" ${r === u.role ? 'selected' : ''}>${esc(t('role.' + r))}</option>`).join('')}
         </select>`
      : esc(t('role.' + u.role));
    const pw = u.must_change
      ? `<span class="badge badge-warn">${esc(t('users.temporary'))}</span>`
      : (u.password_changed ? `<span class="muted small">${esc(t('users.changed', {time: fmtTime(u.password_changed)}))}</span>` : '');
    return `
      <tr>
        <td><b>${esc(u.name)}</b> ${me ? `<span class="badge badge-blue">${esc(t('users.you'))}</span>` : ''}</td>
        <td><span class="badge" title="${esc(t('users.sourceHint.' + u.source))}">${esc(t('users.src.' + u.source))}</span></td>
        <td>${roleCell}</td>
        <td>${u.actions.map(a => `<span class="badge">${esc(a)}</span>`).join(' ')}</td>
        <td>${pw}</td>
        <td class="actions">
          ${data.auth_enabled ? `<button class="btn btn-sm" data-act="reset" data-name="${esc(u.name)}">${esc(t('users.reset'))}</button>` : ''}
          ${editable ? `<button class="btn btn-sm btn-danger" data-act="delete" data-name="${esc(u.name)}">${esc(t('common.delete'))}</button>` : ''}
        </td>
      </tr>`;
  }

  function onClick(e) {
    const el = e.target.closest('[data-act]');
    if (!el || el.tagName === 'SELECT') return;
    const name = el.dataset.name;
    if (el.dataset.act === 'add') addUser();
    else if (el.dataset.act === 'reset') resetPassword(name);
    else if (el.dataset.act === 'delete') deleteUser(name);
  }

  async function onChange(e) {
    if (e.target.dataset.act !== 'role') return;
    const res = await post('/ui/api/users/role', {name: e.target.dataset.name, role: e.target.value});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); App.route(); return; }
    toast(t('users.roleSaved'));
    App.route();
  }

  function passwordFields(withName) {
    return `
      ${withName ? `
        <label>${esc(t('users.name'))}</label>
        <input name="name" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" autocomplete="off">
        <label>${esc(t('users.role'))}</label>
        <select name="role">
          <option value="user">${esc(t('role.user'))}</option>
          <option value="readonly">${esc(t('role.readonly'))}</option>
          <option value="admin">${esc(t('role.admin'))}</option>
        </select>` : ''}
      <label>${esc(t('users.password'))}</label>
      <div style="display:flex;gap:8px">
        <input name="password" required minlength="8" autocomplete="new-password" style="flex:1">
        <button type="button" class="btn" data-gen style="margin-bottom:14px">${esc(t('users.generate'))}</button>
      </div>
      <label class="check"><input type="checkbox" name="must_change" checked>${esc(t('users.mustChange'))}</label>
      <div class="err" id="f-err"></div>
      <div class="dialog-actions">
        <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
        <button class="btn btn-primary">${esc(t('common.save'))}</button>
      </div>`;
  }

  function generatePassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const buf = new Uint32Array(14);
    crypto.getRandomValues(buf);
    return Array.from(buf, x => chars[x % chars.length]).join('');
  }

  function bindForm(m, submit) {
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('[data-gen]').addEventListener('click', () => {
      m.querySelector('[name=password]').value = generatePassword();
    });
    m.querySelector('form').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target;
      const err = await submit(f);
      if (err) {
        m.querySelector('#f-err').textContent = err;
        m.querySelector('#f-err').style.display = 'block';
      }
    });
  }

  function addUser() {
    const m = App.openModal(`<h2>${esc(t('users.add'))}</h2><form class="form">${passwordFields(true)}</form>`);
    bindForm(m, async f => {
      const el = f.elements;
      const req = {name: el.name.value.trim(), role: el.role.value, password: el.password.value, must_change: el.must_change.checked};
      const res = await post('/ui/api/users/create', req);
      if (!res.ok) return res.data.error || t('common.failed', {status: res.status});
      showCredentials(req.name, req.password, req.must_change);
      App.route();
      return '';
    });
  }

  function resetPassword(name) {
    const m = App.openModal(`<h2>${esc(t('users.resetTitle', {name}))}</h2>
      <p class="note">${esc(t('users.resetNote'))}</p><form class="form">${passwordFields(false)}</form>`);
    bindForm(m, async f => {
      const req = {name, password: f.elements.password.value, must_change: f.elements.must_change.checked};
      const res = await post('/ui/api/users/password', req);
      if (!res.ok) return res.data.error || t('common.failed', {status: res.status});
      showCredentials(name, req.password, req.must_change);
      App.route();
      return '';
    });
  }

  // Shows the credentials once so the admin can hand them over.
  function showCredentials(name, password, mustChange) {
    const m = App.openModal(`
      <h2>${esc(t('users.credsTitle'))}</h2>
      <p class="note">${esc(t('users.credsNote'))}</p>
      <div class="card mono" style="user-select:all">${esc(t('users.name'))}: ${esc(name)}<br>${esc(t('users.password'))}: ${esc(password)}</div>
      <p class="muted small">${esc(mustChange ? t('users.credsMustChange') : t('users.credsDocker', {host: App.registryHost(), name}))}</p>
      <div class="dialog-actions">
        <button class="btn" id="m-copy">${esc(t('users.copy'))}</button>
        <button class="btn btn-primary" id="m-close">${esc(t('common.close'))}</button>
      </div>`);
    m.querySelector('#m-close').addEventListener('click', App.closeModal);
    m.querySelector('#m-copy').addEventListener('click', async () => {
      App.copyText(password);
    });
  }

  async function deleteUser(name) {
    if (!confirm(t('users.confirmDelete', {name}))) return;
    const res = await post('/ui/api/users/delete', {name});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    toast(t('users.deleted', {name}));
    App.route();
  }
})();

App.addLang('en', {
  'nav.users': 'Users',
  'users.add': 'Add user',
  'users.intro': 'Users created here are stored in /data/users.json. Users from RGSTR_USERS and the first admin (RGSTR_ADMIN_USER) are configured in env: their role and existence are changed there, but their password can be reset here.',
  'users.authOff': 'Authentication is disabled (RGSTR_AUTH_ENABLED=false): everyone has full access and users have no effect.',
  'users.name': 'Name',
  'users.source': 'Source',
  'users.role': 'Role',
  'users.rights': 'Repository rights',
  'users.password': 'Password',
  'users.you': 'you',
  'users.src.env': 'env',
  'users.src.bootstrap': 'first admin',
  'users.src.admin': 'created here',
  'users.sourceHint.env': 'Defined in RGSTR_USERS',
  'users.sourceHint.bootstrap': 'RGSTR_ADMIN_USER / RGSTR_ADMIN_PASSWORD',
  'users.sourceHint.admin': 'Created in the admin',
  'users.temporary': 'temporary — must be changed',
  'users.changed': 'changed {time}',
  'users.reset': 'Reset password',
  'users.resetTitle': 'Reset password for {name}',
  'users.resetNote': 'The user signs in with this password. Sessions and docker logins that are already open stay valid until their token expires.',
  'users.generate': 'Generate',
  'users.mustChange': 'Require a password change at the first sign-in',
  'users.roleSaved': 'Role changed',
  'users.credsTitle': 'Credentials',
  'users.credsNote': 'Give these to the user now — the password is not shown again.',
  'users.credsMustChange': 'The user must sign in to the web admin first and set their own password; docker login works after that.',
  'users.credsDocker': 'docker login {host} -u {name}',
  'users.copy': 'Copy password',
  'users.copied': 'Password copied',
  'users.copyFailed': 'Copy failed — select the text manually',
  'users.confirmDelete': 'Delete user {name}? They lose access immediately.',
  'users.deleted': 'Deleted user {name}',
  'role.admin': 'Administrator',
  'role.user': 'User',
  'role.readonly': 'Read-only',
});
