'use strict';
// Robot accounts for CI: secrets, per-project permissions, expiry.

(() => {
  const {t, esc, fmtTime, toast, post} = App;

  App.page('robots', {title: 'nav.robots', admin: true, render});

  let data = null;

  async function render(el) {
    const res = await App.api('/ui/api/robots');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    data = res.data;
    el.innerHTML = `
      <div class="toolbar">
        <h2 class="page grow" style="margin:0">${esc(t('nav.robots'))}</h2>
        <button class="btn btn-primary" data-act="add">${esc(t('robots.add'))}</button>
      </div>
      <p class="muted small" style="margin-bottom:12px">${esc(t('robots.intro'))}</p>
      ${data.robots.length ? `<div class="tbl-wrap"><table class="tbl">
        <tr><th>${esc(t('users.name'))}</th><th>${esc(t('robots.permissions'))}</th><th>${esc(t('robots.expires'))}</th><th></th><th></th></tr>
        ${data.robots.map((r, i) => `
          <tr>
            <td><b class="mono">${esc(r.name)}</b>${r.description ? `<div class="muted small">${esc(r.description)}</div>` : ''}
              <div class="muted small">${esc(t('robots.created', {time: fmtTime(r.created_at), user: r.created_by || '—'}))}</div></td>
            <td>${r.permissions.map(p => `<div class="small"><b>${esc(p.project === '*' ? t('robots.allRepos') : p.project)}</b>${p.repos ? ` <span class="mono">${esc(p.repos)}</span>` : ''}: ${p.actions.map(a => `<span class="badge">${esc(a)}</span>`).join(' ')}</div>`).join('')}</td>
            <td>${r.expires_at ? esc(fmtTime(r.expires_at)) : esc(t('robots.never'))}</td>
            <td>${r.expired ? `<span class="badge badge-err">${esc(t('robots.expired'))}</span>`
              : r.disabled ? `<span class="badge">${esc(t('robots.disabled'))}</span>`
              : `<span class="badge badge-ok">${esc(t('robots.active'))}</span>`}</td>
            <td class="actions">
              <button class="btn btn-sm" data-act="edit" data-i="${i}">${esc(t('pol.edit'))}</button>
              <button class="btn btn-sm" data-act="secret" data-i="${i}">${esc(t('robots.newSecret'))}</button>
              <button class="btn btn-sm btn-danger" data-act="delete" data-i="${i}">${esc(t('common.delete'))}</button>
            </td>
          </tr>`).join('')}
      </table></div>` : `<div class="empty">${esc(t('robots.none'))}</div>`}`;
    el.addEventListener('click', onClick);
  }

  function onClick(e) {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const r = b.dataset.i !== undefined ? data.robots[+b.dataset.i] : null;
    if (b.dataset.act === 'add') edit(null);
    else if (b.dataset.act === 'edit') edit(r);
    else if (b.dataset.act === 'secret') regenerate(r);
    else if (b.dataset.act === 'delete') remove(r);
  }

  function permRow(p) {
    const opts = ['*'].concat(data.projects);
    if (p.project && !opts.includes(p.project)) opts.push(p.project);
    return `<div class="perm-row toolbar" style="margin-bottom:8px">
      <select name="project" style="width:auto;margin:0">${opts.map(o =>
        `<option value="${esc(o)}" ${o === p.project ? 'selected' : ''}>${esc(o === '*' ? t('robots.allRepos') : o)}</option>`).join('')}</select>
      <input name="repos" value="${esc(p.repos || '')}" placeholder="${esc(t('robots.reposPlaceholder'))}"
        title="${esc(t('robots.reposHint'))}" style="width:150px;margin:0">
      ${['pull', 'push', 'delete'].map(a => `<label class="check" style="margin:0"><input type="checkbox" value="${a}" ${p.actions.includes(a) ? 'checked' : ''}>${a}</label>`).join('')}
      <button type="button" class="btn btn-sm" data-remove-perm>✕</button>
    </div>`;
  }

  function edit(r) {
    const isNew = !r;
    r = r || {name: '', description: '', permissions: [{project: data.projects[0] || '*', actions: ['pull']}], expires_at: null};
    const m = App.openModal(`
      <h2>${esc(isNew ? t('robots.add') : r.name)}</h2>
      <form class="form" id="f">
        ${isNew ? `
          <label>${esc(t('users.name'))}</label>
          <div style="display:flex;align-items:center;gap:6px"><span class="mono" style="margin-bottom:14px">robot$</span>
            <input name="rname" required pattern="[a-z0-9]+([._-][a-z0-9]+)*" maxlength="64" autocomplete="off"></div>` : ''}
        <label>${esc(t('proj.description'))}</label>
        <input name="description" value="${esc(r.description)}">
        <label>${esc(t('robots.permissions'))}</label>
        <div id="perms">${r.permissions.map(permRow).join('')}</div>
        <button type="button" class="btn btn-sm" id="add-perm" style="margin-bottom:14px">${esc(t('robots.addPerm'))}</button>
        <label>${esc(t('robots.expires'))}</label>
        <select name="expires">
          ${isNew ? '' : `<option value="keep" selected>${esc(t('robots.keepExpiry', {time: r.expires_at ? fmtTime(r.expires_at) : t('robots.never')}))}</option>`}
          <option value="0">${esc(t('robots.never'))}</option>
          ${[30, 90, 180, 365].map(d => `<option value="${d}" ${isNew && d === 90 ? 'selected' : ''}>${esc(t('robots.days', {n: d}))}</option>`).join('')}
        </select>
        ${isNew ? '' : `<label class="check"><input type="checkbox" name="disabled" ${r.disabled ? 'checked' : ''}>${esc(t('robots.disable'))}</label>`}
        <div class="err" id="f-err"></div>
        <div class="dialog-actions">
          <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-primary">${esc(t('common.save'))}</button>
        </div>
      </form>`);
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('#add-perm').addEventListener('click', () =>
      m.querySelector('#perms').insertAdjacentHTML('beforeend', permRow({project: '*', actions: ['pull']})));
    m.querySelector('#perms').addEventListener('click', e => {
      if (e.target.closest('[data-remove-perm]')) e.target.closest('.perm-row').remove();
    });
    m.querySelector('#f').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target.elements;
      const permissions = [...m.querySelectorAll('.perm-row')].map(row => ({
        project: row.querySelector('select').value,
        repos: row.querySelector('[name=repos]').value.trim(),
        actions: [...row.querySelectorAll('input:checked')].map(c => c.value),
      }));
      const body = {name: isNew ? f.rname.value.trim() : r.name, description: f.description.value.trim(), permissions};
      if (f.expires.value !== 'keep') body.expires_days = +f.expires.value;
      if (!isNew) body.disabled = f.disabled.checked;
      const res = await post(isNew ? '/ui/api/robots/create' : '/ui/api/robots/update', body);
      if (!res.ok) {
        const err = m.querySelector('#f-err');
        err.textContent = res.data.error || t('common.failed', {status: res.status});
        err.style.display = 'block';
        return;
      }
      if (isNew) showSecret(res.data.name, res.data.secret); else { App.closeModal(); toast(t('robots.saved')); }
      App.route();
    });
  }

  async function regenerate(r) {
    if (!confirm(t('robots.confirmSecret', {name: r.name}))) return;
    const res = await post('/ui/api/robots/secret', {name: r.name});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    showSecret(res.data.name, res.data.secret);
  }

  async function remove(r) {
    if (!confirm(t('robots.confirmDelete', {name: r.name}))) return;
    const res = await post('/ui/api/robots/delete', {name: r.name});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    toast(t('robots.deleted', {name: r.name}));
    App.route();
  }

  // The secret is shown once; only its hash is stored.
  function showSecret(name, secret) {
    const cmd = `echo '${secret}' | docker login ${App.registryHost()} -u '${name}' --password-stdin`;
    const m = App.openModal(`
      <h2>${esc(t('robots.secretTitle'))}</h2>
      <p class="note">${esc(t('robots.secretNote'))}</p>
      <table class="kv">
        <tr><th>${esc(t('users.name'))}</th><td class="mono">${esc(name)}</td></tr>
        <tr><th>${esc(t('robots.secret'))}</th><td class="mono" style="user-select:all;word-break:break-all">${esc(secret)}</td></tr>
      </table>
      <p class="muted small" style="margin:12px 0 4px">${esc(t('robots.loginHint'))}</p>
      <code class="mono small" style="display:block;background:#f6f6f8;padding:8px;border-radius:4px;word-break:break-all">${esc(cmd)}</code>
      <div class="dialog-actions" style="margin-top:14px">
        <button class="btn" id="m-copy">${esc(t('robots.copySecret'))}</button>
        <button class="btn btn-primary" id="m-close">${esc(t('common.close'))}</button>
      </div>`);
    m.querySelector('#m-close').addEventListener('click', App.closeModal);
    m.querySelector('#m-copy').addEventListener('click', async () => {
      App.copyText(secret);
    });
  }
})();

App.addLang('en', {
  'nav.robots': 'Robots',
  'robots.intro': 'Robot accounts are for CI and automation: a generated secret instead of a password, and only the permissions listed. They work with docker login, not with the web admin.',
  'robots.add': 'New robot account',
  'robots.none': 'No robot accounts.',
  'robots.permissions': 'Permissions',
  'robots.allRepos': 'all repositories',
  'robots.addPerm': '+ permission',
  'robots.reposPlaceholder': 'every repository',
  'robots.reposHint': 'Optional: only repositories matching this pattern, e.g. app-* or web/** (within the project; with "all repositories" the full name)',
  'robots.expires': 'Expires',
  'robots.never': 'never',
  'robots.days': 'in {n} days',
  'robots.keepExpiry': 'keep ({time})',
  'robots.expired': 'expired',
  'robots.disabled': 'disabled',
  'robots.active': 'active',
  'robots.disable': 'Disabled',
  'robots.created': 'created {time} by {user}',
  'robots.newSecret': 'New secret',
  'robots.saved': 'Robot account saved',
  'robots.confirmSecret': 'Issue a new secret for {name}? The current secret stops working immediately.',
  'robots.confirmDelete': 'Delete {name}? It loses access immediately.',
  'robots.deleted': 'Deleted {name}',
  'robots.secretTitle': 'Robot secret',
  'robots.secretNote': 'Copy the secret now — it is not shown again. Store it in your CI secrets.',
  'robots.secret': 'Secret',
  'robots.loginHint': 'Sign in (quote the name: it contains "$"):',
  'robots.copySecret': 'Copy secret',
  'act.robot_create': 'create robot',
  'act.robot_update': 'update robot',
  'act.robot_secret': 'new robot secret',
  'act.robot_delete': 'delete robot',
});

App.addLang('ru', {
  'nav.robots': 'Роботы',
  'robots.intro': 'Robot-аккаунты — для CI и автоматизации: вместо пароля сгенерированный секрет, права — только перечисленные. Работают через docker login, в веб-админку войти не могут.',
  'robots.add': 'Новый robot-аккаунт',
  'robots.none': 'Robot-аккаунтов нет.',
  'robots.permissions': 'Права',
  'robots.allRepos': 'все репозитории',
  'robots.addPerm': '+ право',
  'robots.reposPlaceholder': 'все репозитории',
  'robots.reposHint': 'Необязательно: только репозитории по шаблону, например app-* или web/** (внутри проекта; для «все репозитории» — полное имя)',
  'robots.expires': 'Срок действия',
  'robots.never': 'бессрочно',
  'robots.days': '{n} дней',
  'robots.keepExpiry': 'не менять ({time})',
  'robots.expired': 'истёк',
  'robots.disabled': 'отключён',
  'robots.active': 'активен',
  'robots.disable': 'Отключён',
  'robots.created': 'создан {time}, {user}',
  'robots.newSecret': 'Новый секрет',
  'robots.saved': 'Robot-аккаунт сохранён',
  'robots.confirmSecret': 'Выпустить новый секрет для {name}? Текущий сразу перестанет работать.',
  'robots.confirmDelete': 'Удалить {name}? Он сразу потеряет доступ.',
  'robots.deleted': '{name} удалён',
  'robots.secretTitle': 'Секрет robot-аккаунта',
  'robots.secretNote': 'Скопируйте секрет сейчас — больше он показан не будет. Сохраните его в секретах CI.',
  'robots.secret': 'Секрет',
  'robots.loginHint': 'Вход (имя в кавычках — в нём есть «$»):',
  'robots.copySecret': 'Копировать секрет',
  'act.robot_create': 'создание робота',
  'act.robot_update': 'изменение робота',
  'act.robot_secret': 'новый секрет робота',
  'act.robot_delete': 'удаление робота',
});
