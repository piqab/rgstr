'use strict';
// Projects: list, settings, members, quota.

(() => {
  const {t, esc, fmtBytes, toast, post} = App;
  const GB = 1024 * 1024 * 1024;

  App.page('projects', {title: 'nav.projects', render: renderList});
  App.page('project', {title: 'nav.projects', hidden: true, parent: 'projects', render: renderProject});

  const roles = ['admin', 'maintainer', 'developer', 'guest'];

  function usage(p) {
    if (!p.quota_bytes) return esc(fmtBytes(p.used_bytes));
    const pct = Math.min(100, Math.round(p.used_bytes / p.quota_bytes * 100));
    const cls = pct >= 100 ? 'bar-err' : pct >= 80 ? 'bar-warn' : '';
    return `<div class="small">${esc(t('proj.usageOf', {used: fmtBytes(p.used_bytes), quota: fmtBytes(p.quota_bytes)}))}</div>
      <div class="bar ${cls}"><div style="width:${pct}%"></div></div>`;
  }

  // ── List ──────────────────────────────────────────────────────────────────

  async function renderList(el) {
    const res = await App.api('/ui/api/projects');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    const {projects, can_create} = res.data;
    el.innerHTML = `
      <div class="toolbar">
        <h2 class="page grow" style="margin:0">${esc(t('nav.projects'))}</h2>
        ${can_create ? `<button class="btn btn-primary" id="p-new">${esc(t('proj.new'))}</button>` : ''}
      </div>
      <p class="muted small" style="margin-bottom:12px">${esc(t('proj.intro'))}</p>
      ${projects.length ? `<div class="tbl-wrap"><table class="tbl">
        <tr><th>${esc(t('proj.name'))}</th><th>${esc(t('proj.access'))}</th><th>${esc(t('proj.myRole'))}</th>
          <th>${esc(t('proj.members'))}</th><th>${esc(t('proj.repos'))}</th><th>${esc(t('proj.usage'))}</th></tr>
        ${projects.map(p => `
          <tr>
            <td><a href="#project/${encodeURIComponent(p.name)}"><b>${esc(p.name)}</b></a>
              ${p.proxy ? `<span class="badge badge-blue" title="${esc(p.proxy.url)}">${esc(t('proj.cacheBadge'))}</span>` : ''}
              ${p.description ? `<div class="muted small">${esc(p.description)}</div>` : ''}</td>
            <td>${p.public ? `<span class="badge badge-ok">${esc(t('proj.public'))}</span>` : `<span class="badge">${esc(t('proj.private'))}</span>`}</td>
            <td>${p.my_role ? esc(t('prole.' + p.my_role)) : '—'}</td>
            <td>${p.members}</td>
            <td>${p.repos}</td>
            <td style="min-width:160px">${usage(p)}</td>
          </tr>`).join('')}
      </table></div>` : `<div class="empty">${esc(t('proj.none'))}</div>`}`;
    const btn = el.querySelector('#p-new');
    if (btn) btn.addEventListener('click', newProject);
  }

  function newProject() {
    const m = App.openModal(`
      <h2>${esc(t('proj.new'))}</h2>
      <form class="form" id="f">
        <label>${esc(t('proj.name'))}</label>
        <input name="pname" required pattern="[a-z0-9]+([._-][a-z0-9]+)*" maxlength="64" autocomplete="off">
        <p class="muted small" style="margin:-8px 0 14px">${esc(t('proj.nameHint'))}</p>
        <label>${esc(t('proj.description'))}</label>
        <input name="description">
        <label class="check"><input type="checkbox" name="public">${esc(t('proj.publicLabel'))}</label>
        <label>${esc(t('proj.quotaLabel'))}</label>
        <input name="quota" type="number" min="0" step="0.1" value="0">
        <label class="check"><input type="checkbox" name="cache">${esc(t('proj.cacheLabel'))}</label>
        <div id="cache-fields" style="display:none">${proxyFields(null)}</div>
        <div class="err" id="f-err"></div>
        <div class="dialog-actions">
          <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-primary">${esc(t('common.save'))}</button>
        </div>
      </form>`);
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('[name=cache]').addEventListener('change', e => {
      m.querySelector('#cache-fields').style.display = e.target.checked ? 'block' : 'none';
      m.querySelector('[name=proxy_url]').required = e.target.checked;
    });
    m.querySelector('#f').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target.elements;
      const quota = Math.round((+f.quota.value || 0) * GB);
      const req = {name: f.pname.value.trim(), description: f.description.value.trim(), public: f.public.checked, quota_bytes: quota};
      if (f.cache.checked) req.proxy = proxyRequest(f);
      const res = await post('/ui/api/projects/create', req);
      if (!res.ok) { showErr(m, res.data.error || t('common.failed', {status: res.status})); return; }
      App.closeModal();
      location.hash = '#project/' + encodeURIComponent(f.pname.value.trim());
    });
  }

  // ── Project page ──────────────────────────────────────────────────────────

  async function renderProject(el, name) {
    const res = await App.api('/ui/api/project?' + new URLSearchParams({name}));
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    const {project: p, members, repos, is_admin} = res.data;
    const manage = p.can_manage;

    el.innerHTML = `
      <p style="margin-bottom:10px"><a href="#projects">← ${esc(t('nav.projects'))}</a></p>
      <h2 class="page">${esc(p.name)}
        ${p.public ? `<span class="badge badge-ok">${esc(t('proj.public'))}</span>` : `<span class="badge">${esc(t('proj.private'))}</span>`}</h2>

      <div class="card">
        <h3 style="margin-top:0">${esc(t('proj.settings'))}</h3>
        <form class="form" id="settings">
          <label>${esc(t('proj.description'))}</label>
          <input name="description" value="${esc(p.description)}" ${manage ? '' : 'disabled'}>
          <label class="check"><input type="checkbox" name="public" ${p.public ? 'checked' : ''} ${manage ? '' : 'disabled'}>${esc(t('proj.publicLabel'))}</label>
          <label>${esc(t('proj.quotaLabel'))}</label>
          <input name="quota" type="number" min="0" step="0.1" value="${p.quota_bytes ? +(p.quota_bytes / GB).toFixed(2) : 0}" ${is_admin ? '' : 'disabled'}>
          <div style="margin:-6px 0 14px">${usage(p)}</div>
          <label>${esc(t('proj.blockLabel'))}</label>
          <select name="block" ${manage ? '' : 'disabled'}>
            ${['', 'critical', 'high', 'medium', 'low'].map(v =>
              `<option value="${v}" ${v === p.block_severity ? 'selected' : ''}>${esc(t('proj.block.' + (v || 'off')))}</option>`).join('')}
          </select>
          <p class="muted small" style="margin:-8px 0 14px">${esc(t('proj.blockHint'))}</p>
          ${manage ? `<button class="btn btn-primary">${esc(t('common.save'))}</button>` : ''}
        </form>
      </div>

      ${p.proxy ? `
        <div class="card">
          <h3 style="margin-top:0">${esc(t('proj.cacheTitle'))}</h3>
          <p class="muted small" style="margin-bottom:10px">${esc(t('proj.cacheIntro'))}</p>
          <pre class="mono small" style="user-select:all;margin-bottom:12px">docker pull ${esc(App.registryHost())}/${esc(p.name)}/${esc(/docker\.io/.test(p.proxy.url) ? 'library/nginx:latest' : '<image>:<tag>')}</pre>
          ${p.proxy.from_env ? `<p>${esc(t('proj.cacheUpstream'))}: <span class="mono">${esc(p.proxy.url)}</span>
              ${p.proxy.username ? ` · ${esc(t('proj.cacheUser'))}: ${esc(p.proxy.username)}` : ''}</p>
            <p class="muted small">${esc(t('proj.cacheFromEnv'))}</p>`
          : is_admin ? `<form class="form" id="cache-form">${proxyFields(p.proxy)}
              <button class="btn btn-primary">${esc(t('common.save'))}</button>
              <button type="button" class="btn btn-danger" id="cache-off">${esc(t('proj.cacheOff'))}</button></form>`
          : `<p>${esc(t('proj.cacheUpstream'))}: <span class="mono">${esc(p.proxy.url)}</span></p>`}
        </div>` : ''}

      <div class="card">
        <h3 style="margin-top:0">${esc(t('proj.members'))}</h3>
        <p class="muted small" style="margin-bottom:10px">${esc(t('proj.rolesHint'))}</p>
        ${members.length ? `<div class="tbl-wrap"><table class="tbl">
          <tr><th>${esc(t('users.name'))}</th><th>${esc(t('users.role'))}</th><th></th></tr>
          ${members.map(mb => {
            // Project admins cannot change their own role (registry admins can).
            const edit = manage && (is_admin || mb.user !== App.session.user);
            return `
            <tr>
              <td>${esc(mb.user)}</td>
              <td>${edit ? roleSelect(mb.user, mb.role) : esc(t('prole.' + mb.role))}</td>
              <td class="actions">${edit ? `<button class="btn btn-sm btn-danger" data-remove="${esc(mb.user)}">${esc(t('proj.remove'))}</button>` : ''}</td>
            </tr>`;
          }).join('')}
        </table></div>` : `<div class="empty">${esc(t('proj.noMembers'))}</div>`}
        ${manage ? `
          <form class="form toolbar" id="add-member" style="margin:14px 0 0">
            <input name="user" placeholder="${esc(t('proj.userPlaceholder'))}" required style="width:220px;margin:0">
            <select name="role" style="width:auto;margin:0">${roles.map(r => `<option value="${r}" ${r === 'developer' ? 'selected' : ''}>${esc(t('prole.' + r))}</option>`).join('')}</select>
            <button class="btn btn-primary">${esc(t('proj.addMember'))}</button>
          </form>` : ''}
      </div>

      <div class="card">
        <h3 style="margin-top:0">${esc(t('proj.repos'))}</h3>
        <p class="muted small" style="margin-bottom:10px">${esc(t('proj.pushHint', {host: App.registryHost(), name: p.name}))}</p>
        ${repos.length ? repos.map(r => `<div><a href="#repos/${encodeURIComponent(r)}">${esc(r)}</a></div>`).join('') : `<div class="empty">${esc(t('proj.noRepos'))}</div>`}
      </div>

      ${is_admin ? `
        <div class="card">
          <h3 style="margin-top:0">${esc(t('proj.danger'))}</h3>
          <button class="btn btn-danger" id="p-delete" ${repos.length ? 'disabled' : ''}>${esc(t('proj.delete'))}</button>
          ${repos.length ? `<p class="muted small" style="margin-top:8px">${esc(t('proj.deleteHint'))}</p>` : ''}
        </div>` : ''}`;

    const settings = el.querySelector('#settings');
    settings.addEventListener('submit', async e => {
      e.preventDefault();
      const f = settings.elements;
      const body = {name: p.name, description: f.description.value.trim(), public: f.public.checked, block_severity: f.block.value};
      if (is_admin) body.quota_bytes = Math.round((+f.quota.value || 0) * GB);
      const r = await post('/ui/api/projects/update', body);
      if (!r.ok) { toast(r.data.error || t('common.failed', {status: r.status})); return; }
      toast(t('proj.saved'));
      App.route();
    });

    const saveCache = async proxy => {
      const r = await post('/ui/api/projects/update', {name: p.name, description: p.description, public: p.public, proxy});
      if (!r.ok) { toast(r.data.error || t('common.failed', {status: r.status})); return; }
      toast(t('proj.saved'));
      App.route();
    };
    const cacheForm = el.querySelector('#cache-form');
    if (cacheForm) {
      cacheForm.addEventListener('submit', e => { e.preventDefault(); saveCache(proxyRequest(cacheForm.elements)); });
      el.querySelector('#cache-off').addEventListener('click', () => {
        if (confirm(t('proj.cacheOffConfirm', {name: p.name}))) saveCache({url: ''});
      });
    }

    el.addEventListener('change', e => {
      if (e.target.dataset.member) setMember(p.name, e.target.dataset.member, e.target.value);
    });
    el.addEventListener('click', e => {
      const rm = e.target.closest('[data-remove]');
      if (rm && confirm(t('proj.confirmRemove', {user: rm.dataset.remove}))) setMember(p.name, rm.dataset.remove, '');
    });
    const add = el.querySelector('#add-member');
    if (add) add.addEventListener('submit', e => {
      e.preventDefault();
      setMember(p.name, add.elements.user.value.trim(), add.elements.role.value);
    });
    const del = el.querySelector('#p-delete');
    if (del) del.addEventListener('click', async () => {
      if (!confirm(t('proj.confirmDelete', {name: p.name}))) return;
      const r = await post('/ui/api/projects/delete', {name: p.name});
      if (!r.ok) { toast(r.data.error || t('common.failed', {status: r.status})); return; }
      toast(t('proj.deleted', {name: p.name}));
      location.hash = '#projects';
    });
  }

  // proxyFields are the upstream settings of a pull-through cache.
  function proxyFields(px) {
    return `
      <label>${esc(t('proj.cacheUpstream'))}</label>
      <input name="proxy_url" placeholder="https://registry-1.docker.io" value="${esc(px ? px.url : '')}">
      <p class="muted small" style="margin:-8px 0 14px">${esc(t('proj.cacheUpstreamHint'))}</p>
      <label>${esc(t('proj.cacheUser'))}</label>
      <input name="proxy_user" autocomplete="off" value="${esc(px ? px.username || '' : '')}">
      <label>${esc(t('proj.cachePassword'))}</label>
      <input name="proxy_password" type="password" autocomplete="new-password"
        placeholder="${esc(px && px.has_password ? t('proj.cachePasswordKeep') : '')}">`;
  }

  function proxyRequest(f) {
    return {url: f.proxy_url.value.trim(), username: f.proxy_user.value.trim(), password: f.proxy_password.value};
  }

  function roleSelect(user, role) {
    return `<select data-member="${esc(user)}" style="padding:4px 6px">${roles.map(r =>
      `<option value="${r}" ${r === role ? 'selected' : ''}>${esc(t('prole.' + r))}</option>`).join('')}</select>`;
  }

  async function setMember(project, user, role) {
    const r = await post('/ui/api/projects/member', {name: project, user, role});
    if (!r.ok) { toast(r.data.error || t('common.failed', {status: r.status})); App.route(); return; }
    toast(role ? t('proj.memberSaved', {user}) : t('proj.memberRemoved', {user}));
    App.route();
  }

  function showErr(m, msg) {
    const el = m.querySelector('#f-err');
    el.textContent = msg;
    el.style.display = 'block';
  }
})();

App.addLang('en', {
  'nav.projects': 'Projects',
  'proj.intro': 'A project groups repositories named "<project>/…". Inside a project only its members (and registry administrators) have access, according to their project role. Repositories outside projects use global roles.',
  'proj.new': 'New project',
  'proj.none': 'No projects.',
  'proj.name': 'Name',
  'proj.nameHint': 'Lowercase letters and digits, separated by . _ or -. Repositories "<name>/…" belong to the project.',
  'proj.description': 'Description',
  'proj.access': 'Access',
  'proj.public': 'public',
  'proj.private': 'private',
  'proj.publicLabel': 'Public — anyone can pull without signing in',
  'proj.quotaLabel': 'Storage quota, GB (0 — unlimited)',
  'proj.usage': 'Storage',
  'proj.usageOf': '{used} of {quota}',
  'proj.myRole': 'My role',
  'proj.members': 'Members',
  'proj.repos': 'Repositories',
  'proj.settings': 'Settings',
  'proj.saved': 'Project saved',
  'proj.rolesHint': 'Admin: everything, plus members and webhooks. Maintainer: pull, push, delete. Developer: pull, push. Guest: pull.',
  'proj.noMembers': 'No members yet.',
  'proj.userPlaceholder': 'User name',
  'proj.addMember': 'Add member',
  'proj.remove': 'Remove',
  'proj.confirmRemove': 'Remove {user} from the project?',
  'proj.memberSaved': '{user}: role saved',
  'proj.memberRemoved': '{user} removed',
  'proj.pushHint': 'Push into the project: docker push {host}/{name}/<image>:<tag>',
  'proj.noRepos': 'No repositories yet.',
  'proj.danger': 'Delete project',
  'proj.delete': 'Delete project',
  'proj.deleteHint': 'Delete its repositories first.',
  'proj.confirmDelete': 'Delete project {name}? Its members and settings are lost.',
  'proj.deleted': 'Project {name} deleted',
  'proj.cacheBadge': 'cache',
  'proj.cacheLabel': 'Pull-through cache of another registry (Docker Hub, GHCR, …)',
  'proj.cacheTitle': 'Pull-through cache',
  'proj.cacheIntro': 'Pulls fetch images from the upstream registry on the first request and serve them from here afterwards; tags are re-checked upstream every few minutes. Pushing into this project is not possible.',
  'proj.cacheUpstream': 'Upstream registry',
  'proj.cacheUpstreamHint': 'Docker Hub: https://registry-1.docker.io (images as <project>/library/nginx). GitHub: https://ghcr.io. Quay: https://quay.io.',
  'proj.cacheUser': 'Upstream user',
  'proj.cachePassword': 'Upstream password or token',
  'proj.cachePasswordKeep': 'unchanged',
  'proj.cacheFromEnv': 'Configured in RGSTR_PROXIES; change it there.',
  'proj.cacheOff': 'Stop caching',
  'proj.cacheOffConfirm': 'Make {name} a normal project? Cached images stay.',
  'proj.blockLabel': 'Vulnerable images',
  'proj.block.off': 'Allow every pull',
  'proj.block.critical': 'Refuse pulls with critical vulnerabilities',
  'proj.block.high': 'Refuse pulls with high or critical vulnerabilities',
  'proj.block.medium': 'Refuse pulls with medium or worse vulnerabilities',
  'proj.block.low': 'Refuse pulls with any vulnerability',
  'proj.blockHint': 'Uses the vulnerability scan (RGSTR_SCAN_ENABLED). Images not scanned yet can be pulled.',
  'prole.admin': 'Project admin',
  'prole.maintainer': 'Maintainer',
  'prole.developer': 'Developer',
  'prole.guest': 'Guest',
});

App.addLang('ru', {
  'nav.projects': 'Проекты',
  'proj.intro': 'Проект объединяет репозитории с именами «<проект>/…». Внутри проекта доступ есть только у его участников (и администраторов реестра) — по их роли в проекте. Репозитории вне проектов работают по глобальным ролям.',
  'proj.new': 'Новый проект',
  'proj.none': 'Проектов нет.',
  'proj.name': 'Имя',
  'proj.nameHint': 'Строчные буквы и цифры, разделители . _ -. Репозитории «<имя>/…» относятся к проекту.',
  'proj.description': 'Описание',
  'proj.access': 'Доступ',
  'proj.public': 'публичный',
  'proj.private': 'приватный',
  'proj.publicLabel': 'Публичный — скачивать (pull) может кто угодно без входа',
  'proj.quotaLabel': 'Квота на хранение, ГБ (0 — без ограничений)',
  'proj.usage': 'Занято',
  'proj.usageOf': '{used} из {quota}',
  'proj.myRole': 'Моя роль',
  'proj.members': 'Участники',
  'proj.repos': 'Репозитории',
  'proj.settings': 'Настройки',
  'proj.saved': 'Проект сохранён',
  'proj.rolesHint': 'Админ проекта: всё, а также участники и webhooks. Maintainer: pull, push, удаление. Developer: pull, push. Guest: pull.',
  'proj.noMembers': 'Участников пока нет.',
  'proj.userPlaceholder': 'Имя пользователя',
  'proj.addMember': 'Добавить участника',
  'proj.remove': 'Убрать',
  'proj.confirmRemove': 'Убрать {user} из проекта?',
  'proj.memberSaved': '{user}: роль сохранена',
  'proj.memberRemoved': '{user} убран из проекта',
  'proj.pushHint': 'Push в проект: docker push {host}/{name}/<образ>:<тег>',
  'proj.noRepos': 'Репозиториев пока нет.',
  'proj.danger': 'Удаление проекта',
  'proj.delete': 'Удалить проект',
  'proj.deleteHint': 'Сначала удалите его репозитории.',
  'proj.confirmDelete': 'Удалить проект {name}? Участники и настройки будут потеряны.',
  'proj.deleted': 'Проект {name} удалён',
  'prole.admin': 'Админ проекта',
  'proj.cacheBadge': 'кеш',
  'proj.cacheLabel': 'Pull-through кеш другого реестра (Docker Hub, GHCR, …)',
  'proj.cacheTitle': 'Pull-through кеш',
  'proj.cacheIntro': 'При первом pull образ скачивается из upstream-реестра, дальше отдаётся отсюда; теги перепроверяются в upstream раз в несколько минут. Push в этот проект невозможен.',
  'proj.cacheUpstream': 'Upstream-реестр',
  'proj.cacheUpstreamHint': 'Docker Hub: https://registry-1.docker.io (образы как <проект>/library/nginx). GitHub: https://ghcr.io. Quay: https://quay.io.',
  'proj.cacheUser': 'Пользователь upstream',
  'proj.cachePassword': 'Пароль или токен upstream',
  'proj.cachePasswordKeep': 'без изменений',
  'proj.cacheFromEnv': 'Задан в RGSTR_PROXIES; меняется там.',
  'proj.cacheOff': 'Выключить кеш',
  'proj.cacheOffConfirm': 'Сделать {name} обычным проектом? Закешированные образы останутся.',
  'proj.blockLabel': 'Уязвимые образы',
  'proj.block.off': 'Разрешать любой pull',
  'proj.block.critical': 'Запрещать pull с критическими уязвимостями',
  'proj.block.high': 'Запрещать pull с высокими и критическими',
  'proj.block.medium': 'Запрещать pull со средними и выше',
  'proj.block.low': 'Запрещать pull с любыми уязвимостями',
  'proj.blockHint': 'Работает по результатам сканирования (RGSTR_SCAN_ENABLED). Ещё не просканированные образы можно скачивать.',
  'prole.maintainer': 'Maintainer',
  'prole.developer': 'Developer',
  'prole.guest': 'Guest',
  'act.project_create': 'создание проекта',
  'act.project_update': 'изменение проекта',
  'act.project_delete': 'удаление проекта',
  'act.project_member': 'участник проекта',
});
