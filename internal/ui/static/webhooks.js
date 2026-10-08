'use strict';
// Webhooks: notify HTTP endpoints about pushes, pulls, deletions, quotas.

(() => {
  const {t, esc, fmtTime, toast, post} = App;

  App.page('webhooks', {
    title: 'nav.webhooks', render,
    when: () => App.session.admin || App.session.projectAdmin,
  });

  const EVENTS = ['push', 'pull', 'delete', 'quota_exceeded'];
  let data = null;

  async function render(el) {
    const res = await App.api('/ui/api/webhooks');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    data = res.data;
    el.innerHTML = `
      <div class="toolbar">
        <h2 class="page grow" style="margin:0">${esc(t('nav.webhooks'))}</h2>
        <button class="btn btn-primary" data-act="add">${esc(t('hooks.add'))}</button>
      </div>
      <p class="muted small" style="margin-bottom:12px">${esc(t('hooks.intro'))}</p>
      ${data.webhooks.length ? data.webhooks.map(card).join('') : `<div class="empty">${esc(t('hooks.none'))}</div>`}`;
    el.addEventListener('click', onClick);
  }

  function card(h, i) {
    const last = h.deliveries[0];
    return `
      <div class="card">
        <div class="toolbar" style="margin-bottom:8px">
          <div class="grow"><b>${esc(h.name)}</b>
            ${h.disabled ? `<span class="badge">${esc(t('pol.disabled'))}</span>` : ''}
            ${last ? `<span class="badge ${last.error ? 'badge-err' : 'badge-ok'}" title="${esc(last.error || '')}">${esc(last.error ? t('hooks.lastFailed') : t('hooks.lastOk'))}</span>` : ''}
            <div class="mono small muted" style="word-break:break-all">${esc(h.url)}</div></div>
          <button class="btn btn-sm" data-act="test" data-i="${i}">${esc(t('hooks.test'))}</button>
          <button class="btn btn-sm" data-act="edit" data-i="${i}">${esc(t('pol.edit'))}</button>
          <button class="btn btn-sm btn-danger" data-act="delete" data-i="${i}">${esc(t('common.delete'))}</button>
        </div>
        <div class="small">${esc(t('hooks.scope'))}: <b>${esc(h.project || t('hooks.allRepos'))}</b> ·
          ${esc(t('hooks.events'))}: ${h.events.map(e => `<span class="badge">${esc(t('hooks.ev.' + e))}</span>`).join(' ')} ·
          ${esc(t('hooks.format'))}: ${esc(t('hooks.fmt.' + h.format))}${h.has_auth ? ' · ' + esc(t('hooks.withAuth')) : ''}</div>
        ${h.deliveries.length ? `
          <details style="margin-top:10px"><summary class="small" style="cursor:pointer">${esc(t('hooks.deliveries', {n: h.deliveries.length}))}</summary>
            <div class="tbl-wrap" style="margin-top:8px"><table class="tbl">
              <tr><th>${esc(t('audit.time'))}</th><th>${esc(t('hooks.event'))}</th><th>${esc(t('audit.resource'))}</th><th>${esc(t('hooks.result'))}</th></tr>
              ${h.deliveries.map(d => `<tr>
                <td style="white-space:nowrap">${esc(fmtTime(d.time))}</td>
                <td>${esc(t('hooks.ev.' + d.event))}${d.attempt > 1 ? ` <span class="muted small">#${d.attempt}</span>` : ''}</td>
                <td class="mono small">${esc(d.resource || '')}</td>
                <td>${d.error ? `<span class="badge badge-err">${esc(d.error)}</span>` : `<span class="badge badge-ok">${d.status}</span>`}
                  <span class="muted small">${d.duration_ms} ms</span></td></tr>`).join('')}
            </table></div></details>` : ''}
      </div>`;
  }

  function onClick(e) {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const h = b.dataset.i !== undefined ? data.webhooks[+b.dataset.i] : null;
    if (b.dataset.act === 'add') edit(null);
    else if (b.dataset.act === 'edit') edit(h);
    else if (b.dataset.act === 'test') test(h, b);
    else if (b.dataset.act === 'delete') remove(h);
  }

  function edit(h) {
    const isNew = !h;
    h = h || {name: '', url: '', project: data.is_admin ? '' : data.projects[0], events: ['push'], format: 'default'};
    const scopes = (data.is_admin ? [''] : []).concat(data.projects);
    if (!scopes.includes(h.project)) scopes.push(h.project);
    const m = App.openModal(`
      <h2>${esc(isNew ? t('hooks.add') : h.name)}</h2>
      <form class="form" id="f">
        <label>${esc(t('users.name'))}</label>
        <input name="hname" value="${esc(h.name)}" required>
        <label>URL</label>
        <input name="url" type="url" value="${esc(h.url)}" placeholder="https://example.com/hook" required>
        <label>${esc(t('hooks.scope'))}</label>
        <select name="project">${scopes.map(p => `<option value="${esc(p)}" ${p === h.project ? 'selected' : ''}>${esc(p || t('hooks.allRepos'))}</option>`).join('')}</select>
        <label>${esc(t('hooks.events'))}</label>
        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:6px">${EVENTS.map(ev =>
          `<label class="check"><input type="checkbox" name="ev" value="${ev}" ${h.events.includes(ev) ? 'checked' : ''}>${esc(t('hooks.ev.' + ev))}</label>`).join('')}</div>
        <label>${esc(t('hooks.format'))}</label>
        <select name="format">
          <option value="default" ${h.format === 'default' ? 'selected' : ''}>${esc(t('hooks.fmt.default'))}</option>
          <option value="slack" ${h.format === 'slack' ? 'selected' : ''}>${esc(t('hooks.fmt.slack'))}</option>
        </select>
        <label>${esc(t('hooks.authHeader'))}</label>
        <input name="auth" placeholder="${esc(h.has_auth ? t('hooks.authKeep') : 'Bearer …')}" autocomplete="off">
        <label class="check"><input type="checkbox" name="skip_verify" ${h.skip_verify ? 'checked' : ''}>${esc(t('hooks.skipVerify'))}</label>
        ${isNew ? '' : `<label class="check"><input type="checkbox" name="disabled" ${h.disabled ? 'checked' : ''}>${esc(t('robots.disable'))}</label>`}
        <div class="err" id="f-err"></div>
        <div class="dialog-actions">
          <button type="button" class="btn" id="f-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-primary">${esc(t('common.save'))}</button>
        </div>
      </form>`);
    m.querySelector('#f-cancel').addEventListener('click', App.closeModal);
    m.querySelector('#f').addEventListener('submit', async e => {
      e.preventDefault();
      const f = e.target.elements;
      const body = {
        id: isNew ? '' : h.id, name: f.hname.value, url: f.url.value.trim(), project: f.project.value,
        events: [...m.querySelectorAll('[name=ev]:checked')].map(c => c.value),
        format: f.format.value, skip_verify: f.skip_verify.checked, disabled: isNew ? false : f.disabled.checked,
      };
      if (f.auth.value.trim() || isNew) body.auth_header = f.auth.value.trim();
      const res = await post('/ui/api/webhooks/save', body);
      if (!res.ok) {
        const err = m.querySelector('#f-err');
        err.textContent = res.data.error || t('common.failed', {status: res.status});
        err.style.display = 'block';
        return;
      }
      App.closeModal();
      toast(t('hooks.saved'));
      App.route();
    });
  }

  async function test(h, btn) {
    btn.disabled = true;
    const res = await post('/ui/api/webhooks/test', {id: h.id});
    btn.disabled = false;
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    toast(res.data.error ? t('hooks.testFailed', {error: res.data.error}) : t('hooks.testOk', {status: res.data.status}));
    App.route();
  }

  async function remove(h) {
    if (!confirm(t('hooks.confirmDelete', {name: h.name}))) return;
    const res = await post('/ui/api/webhooks/delete', {id: h.id});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    App.route();
  }
})();

App.addLang('en', {
  'nav.webhooks': 'Webhooks',
  'hooks.intro': 'Webhooks POST a JSON message to a URL when images are pushed, pulled or deleted, or a push hits a project quota. "Slack" sends {"text": …}, which Slack and Mattermost incoming webhooks accept. Failed deliveries are retried 3 times.',
  'hooks.add': 'New webhook',
  'hooks.none': 'No webhooks.',
  'hooks.scope': 'Scope',
  'hooks.allRepos': 'all repositories',
  'hooks.events': 'Events',
  'hooks.event': 'Event',
  'hooks.format': 'Format',
  'hooks.fmt.default': 'JSON (Harbor-style)',
  'hooks.fmt.slack': 'Slack / Mattermost',
  'hooks.ev.push': 'push',
  'hooks.ev.pull': 'pull',
  'hooks.ev.delete': 'delete',
  'hooks.ev.quota_exceeded': 'quota exceeded',
  'hooks.ev.ping': 'test',
  'hooks.authHeader': 'Authorization header (optional)',
  'hooks.authKeep': 'set — leave empty to keep',
  'hooks.withAuth': 'with Authorization',
  'hooks.skipVerify': 'Do not verify the TLS certificate',
  'hooks.test': 'Send test',
  'hooks.testOk': 'Test delivered: HTTP {status}',
  'hooks.testFailed': 'Test failed: {error}',
  'hooks.saved': 'Webhook saved',
  'hooks.confirmDelete': 'Delete webhook {name}?',
  'hooks.lastOk': 'last delivery OK',
  'hooks.lastFailed': 'last delivery failed',
  'hooks.deliveries': 'Recent deliveries ({n})',
  'hooks.result': 'Result',
  'act.webhook_change': 'webhook change',
  'act.webhook_delete': 'delete webhook',
});

App.addLang('ru', {
  'nav.webhooks': 'Webhooks',
  'hooks.intro': 'Webhook отправляет JSON на указанный URL, когда образ запушен, скачан или удалён, либо push упёрся в квоту проекта. Формат «Slack» отправляет {"text": …} — его принимают входящие webhooks Slack и Mattermost. Неудачные отправки повторяются до 3 раз.',
  'hooks.add': 'Новый webhook',
  'hooks.none': 'Webhooks нет.',
  'hooks.scope': 'Область',
  'hooks.allRepos': 'все репозитории',
  'hooks.events': 'События',
  'hooks.event': 'Событие',
  'hooks.format': 'Формат',
  'hooks.fmt.default': 'JSON (как в Harbor)',
  'hooks.fmt.slack': 'Slack / Mattermost',
  'hooks.ev.push': 'push',
  'hooks.ev.pull': 'pull',
  'hooks.ev.delete': 'удаление',
  'hooks.ev.quota_exceeded': 'превышение квоты',
  'hooks.ev.ping': 'тест',
  'hooks.authHeader': 'Заголовок Authorization (необязательно)',
  'hooks.authKeep': 'задан — оставьте пустым, чтобы не менять',
  'hooks.withAuth': 'с Authorization',
  'hooks.skipVerify': 'Не проверять TLS-сертификат',
  'hooks.test': 'Отправить тест',
  'hooks.testOk': 'Тест доставлен: HTTP {status}',
  'hooks.testFailed': 'Тест не доставлен: {error}',
  'hooks.saved': 'Webhook сохранён',
  'hooks.confirmDelete': 'Удалить webhook {name}?',
  'hooks.lastOk': 'последняя отправка успешна',
  'hooks.lastFailed': 'последняя отправка с ошибкой',
  'hooks.deliveries': 'Последние отправки ({n})',
  'hooks.result': 'Результат',
  'act.webhook_change': 'изменение webhook',
  'act.webhook_delete': 'удаление webhook',
});
