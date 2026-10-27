'use strict';
// Core of the rgstr admin: session, routing, i18n and shared helpers.
// Pages register themselves with App.page(); see repos.js.

const App = (() => {
  const $ = id => document.getElementById(id);

  // ── i18n ──────────────────────────────────────────────────────────────────
  // English strings live here; other languages add dictionaries via
  // App.addLang(). t('key', {n: 1}) substitutes {n}.
  const langs = {en: {}};
  let lang = 'en';

  function addLang(code, dict) {
    langs[code] = Object.assign(langs[code] || {}, dict);
  }

  // Language pickers: a select in the header, links on the sign-in form.
  function renderLangs() {
    const codes = Object.keys(langs);
    $('lang-select').innerHTML = codes
      .map(c => `<option value="${c}" ${c === lang ? 'selected' : ''}>${esc(langs[c]['lang.name'] || c)}</option>`).join('');
    $('login-langs').innerHTML = codes
      .map(c => `<a href="#" data-lang="${c}" class="${c === lang ? 'active' : ''}">${esc(langs[c]['lang.name'] || c)}</a>`).join(' · ');
  }

  function t(key, params) {
    let s = (langs[lang] && langs[lang][key]) || langs.en[key] || key;
    if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in params ? params[k] : m));
    return s;
  }

  function setLang(code) {
    if (!langs[code]) return;
    lang = code;
    try { localStorage.setItem('rgstr_lang', code); } catch (e) { /* storage unavailable */ }
    document.documentElement.lang = code;
    document.querySelectorAll('[data-t]').forEach(el => { el.textContent = t(el.dataset.t); });
    renderLangs();
    renderNav();
    if (session.ready) route();
  }

  // ── Session ───────────────────────────────────────────────────────────────
  // The session token (never the password) lives in localStorage, shared by
  // all tabs and kept across browser restarts until the session ends.
  const TOKEN_KEY = 'rgstr_token';
  const store = {
    get() { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; } },
    set(v) { try { localStorage.setItem(TOKEN_KEY, v); } catch (e) { /* private mode: tab only */ } },
    clear() { try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ } },
  };
  const session = {
    token: store.get(),
    user: '',
    admin: false,
    projectAdmin: false, // manages at least one project
    source: '',          // 'ldap' or 'oidc' for directory users
    authEnabled: true,
    ready: false,
    // Set while a temporary password must be replaced: the credentials the
    // user signed in with, kept only until the change succeeds.
    forced: null,
  };

  async function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (session.token) opts.headers['Authorization'] = 'Bearer ' + session.token;
    if (opts.json !== undefined) {
      opts.method = opts.method || 'POST';
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.json);
    }
    const res = await fetch(path, opts);
    let data = null;
    const text = await res.text();
    if (text) { try { data = JSON.parse(text); } catch (e) { data = {error: text}; } }
    if (res.status === 401 && session.ready && session.authEnabled && path.startsWith('/ui/api/')
        && path !== '/ui/api/password') {
      showLogin(t('login.expired'));
    }
    return {ok: res.ok, status: res.status, data: data || {}};
  }

  const post = (path, body) => api(path, {json: body});

  async function boot() {
    let code = 'en';
    try { code = localStorage.getItem('rgstr_lang') || ''; } catch (e) { /* ignore */ }
    if (!code) code = (navigator.language || 'en').slice(0, 2);
    setLang(langs[code] ? code : 'en');

    $('login-form').addEventListener('submit', doLogin);
    $('lang-select').addEventListener('change', e => setLang(e.target.value));
    $('login-langs').addEventListener('click', e => {
      const a = e.target.closest('[data-lang]');
      if (a) { e.preventDefault(); setLang(a.dataset.lang); }
    });
    $('btn-logout').addEventListener('click', logout);
    window.addEventListener('storage', onStorage);
    setInterval(refreshSession, 60 * 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshSession(); });
    $('btn-password').addEventListener('click', () => openPasswordForm());
    $('btn-cli').addEventListener('click', openCLISecret);
    $('li-sso-link').addEventListener('click', rememberPlace);
    $('pw-form').addEventListener('submit', doChangePassword);
    $('pw-cancel').addEventListener('click', closePasswordForm);
    $('modal-overlay').addEventListener('click', e => { if (e.target.id === 'modal-overlay') closeModal(); });
    window.addEventListener('hashchange', route);

    const params = takeRedirect();
    const me = await api('/ui/api/me');
    session.authEnabled = me.data.auth_enabled;
    session.version = me.data.version || '';
    session.sso = me.data.sso || '';
    if (session.sso) {
      $('li-sso').style.display = 'block';
      $('li-sso-link').textContent = t('login.sso', {name: session.sso});
    }
    if (session.version) {
      $('footer').textContent = 'rgstr ' + session.version;
      $('login-version').textContent = 'rgstr ' + session.version;
    }
    if (!session.authEnabled) {
      session.admin = true;
      $('hdr-user').textContent = t('hdr.noauth');
      showApp();
    } else if (me.data.user) {
      session.source = me.data.source || '';
      signedIn(me.data.user, me.data.admin, me.data.project_admin);
      if (params.get('pw') === 'changed') toast(t('pw.changed'));
      if (params.get('pw_error')) openPasswordForm({error: params.get('pw_error')});
    } else if (params.get('must_change') || (params.get('pw_error') && params.get('mode') === 'forced')) {
      showLogin('');
      $('login-overlay').classList.remove('show');
      openPasswordForm({forced: params.get('user') || '', error: params.get('pw_error')});
    } else {
      const user = params.get('user');
      if (user) $('li-user').value = user;
      const err = params.get('error');
      showLogin(err === 'sso' ? t('login.ssoErr.' + (params.get('reason') || 'provider'))
        : err ? t('login.invalid') : (session.token ? t('login.expired') : ''));
      if (user) $('li-pass').focus();
    }
  }

  // Sign-in and password changes are real form submissions (so password
  // managers offer to save the password). The server answers with a
  // redirect back to /ui: on success the session token arrives in the
  // short-lived rgstr_handoff cookie, otherwise the query says what failed.
  function doLogin() {
    rememberPlace();
    // no preventDefault: the browser submits the form to /ui/login
  }

  function rememberPlace() {
    try { sessionStorage.setItem('rgstr_return', location.hash); } catch (e) { /* ignore */ }
  }

  // takeRedirect reads the result of a form submission and cleans the URL.
  function takeRedirect() {
    const params = new URLSearchParams(location.search);
    const m = document.cookie.match(/(?:^|; )rgstr_handoff=([^;]*)/);
    if (m) {
      session.token = decodeURIComponent(m[1]);
      store.set(session.token);
      document.cookie = 'rgstr_handoff=; Max-Age=0; Path=/ui; SameSite=Strict';
    }
    let back = '';
    try { back = sessionStorage.getItem('rgstr_return') || ''; sessionStorage.removeItem('rgstr_return'); } catch (e) { /* ignore */ }
    if (location.search || (back && !location.hash)) history.replaceState(null, '', '/ui' + (location.hash || back));
    return params;
  }

  function signedIn(name, admin, projectAdmin) {
    session.user = name;
    session.admin = !!admin;
    session.projectAdmin = !!projectAdmin;
    $('hdr-user').textContent = name;
    // Directory users change their password in the directory; for docker
    // login they make a CLI secret.
    $('btn-password').style.display = session.source ? 'none' : 'block';
    $('btn-cli').style.display = session.source ? 'block' : 'none';
    $('btn-logout').style.display = 'block';
    showApp();
  }

  function showApp() {
    session.ready = true;
    $('app').style.display = 'block';
    $('footer').style.display = 'block';
    renderNav();
    route();
  }

  function showLogin(msg) {
    session.token = '';
    session.user = '';
    session.admin = false;
    session.projectAdmin = false;
    session.source = '';
    session.ready = false;
    store.clear();
    $('app').style.display = 'none';
    $('footer').style.display = 'none';
    $('btn-password').style.display = 'none';
    $('btn-cli').style.display = 'none';
    $('btn-logout').style.display = 'none';
    $('hdr-user').textContent = '';
    $('nav').innerHTML = '';
    $('disk-banner').innerHTML = '';
    closeModal();
    $('login-overlay').classList.add('show');
    showLoginError(msg);
    $('li-user').focus();
  }

  // Sign out: end the session on the server, then everywhere locally (other
  // tabs follow through the storage event).
  async function logout() {
    if (session.token) await api('/ui/api/logout', {method: 'POST'});
    showLogin('');
  }

  // Another tab signed in, refreshed or signed out.
  function onStorage(e) {
    if (e.key !== TOKEN_KEY) return;
    if (!e.newValue) {
      if (session.ready && session.authEnabled) showLogin('');
    } else if (session.ready) {
      session.token = e.newValue;
    } else {
      location.reload();
    }
  }

  // Sessions last RGSTR_SESSION_TTL and are extended while the admin is
  // open: once a quarter of the token's lifetime has passed it is renewed.
  let refreshing = false;
  async function refreshSession() {
    if (!session.ready || !session.token || refreshing) return;
    let claims;
    try { claims = JSON.parse(atob(session.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch (e) { return; }
    if (!claims.sid) return;
    const now = Date.now() / 1000;
    if (now - claims.iat < (claims.exp - claims.iat) / 4) return;
    refreshing = true;
    try {
      const res = await api('/ui/api/session/refresh', {method: 'POST'});
      if (res.ok) { session.token = res.data.token; store.set(res.data.token); }
      else if (res.status === 401) showLogin(t('login.expired'));
    } finally { refreshing = false; }
  }

  function showLoginError(msg) {
    $('li-err').textContent = msg || '';
    $('li-err').style.display = msg ? 'block' : 'none';
  }

  // ── Password change ───────────────────────────────────────────────────────

  // openPasswordForm shows the password form; with o.forced (a user name)
  // it is the forced change of a temporary password, entered as "current".
  function openPasswordForm(o) {
    o = o || {};
    session.forced = o.forced !== undefined ? o.forced : null;
    const forced = session.forced !== null;
    $('pw-form').reset();
    $('pw-user').value = forced ? session.forced : session.user;
    $('pw-mode').value = forced ? 'forced' : 'change';
    showPasswordError(o.error ? t('pw.err.' + o.error) : '');
    $('pw-title').textContent = forced ? t('pw.forcedTitle') : t('pw.title');
    $('pw-note').textContent = forced ? t('pw.forcedNote', {user: session.forced}) : '';
    $('pw-note').style.display = forced ? 'block' : 'none';
    $('pw-current-label').textContent = forced ? t('pw.temporary') : t('pw.current');
    $('pw-current').required = true;
    $('pw-overlay').classList.add('show');
    $('pw-current').focus();
  }

  function closePasswordForm() {
    $('pw-overlay').classList.remove('show');
    if (session.forced !== null) { session.forced = null; showLogin(''); }
  }

  function doChangePassword(e) {
    if ($('pw-new').value !== $('pw-repeat').value) {
      e.preventDefault();
      showPasswordError(t('pw.mismatch'));
      return;
    }
    rememberPlace();
    // no preventDefault: the browser submits the form to /ui/password,
    // which changes the password and signs in with the new one
  }

  function showPasswordError(msg) {
    $('pw-err').textContent = msg || '';
    $('pw-err').style.display = msg ? 'block' : 'none';
  }

  // ── CLI secret ────────────────────────────────────────────────────────────
  // LDAP and SSO users have no rgstr password; docker login takes a secret
  // made here (LDAP users may also use their directory password).

  function openCLISecret() {
    const m = openModal(`
      <h2>${esc(t('cli.title'))}</h2>
      <p class="note">${esc(t(session.source === 'ldap' ? 'cli.noteLdap' : 'cli.note'))}</p>
      <div id="cli-out"></div>
      <div class="dialog-actions">
        <button class="btn" id="cli-close">${esc(t('common.close'))}</button>
        <button class="btn btn-primary" id="cli-new">${esc(t('cli.generate'))}</button>
      </div>`);
    m.querySelector('#cli-close').addEventListener('click', closeModal);
    m.querySelector('#cli-new').addEventListener('click', async () => {
      const res = await api('/ui/api/cli-secret', {method: 'POST'});
      if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
      const cmd = `echo '${res.data.secret}' | docker login ${registryHost()} -u '${res.data.user}' --password-stdin`;
      m.querySelector('#cli-out').innerHTML = `
        <p class="muted small">${esc(t('cli.once'))}</p>
        <div class="card mono" style="user-select:all;word-break:break-all">${esc(res.data.secret)}</div>
        <p class="muted small">${esc(t('cli.usage'))}</p>
        <div class="card mono" style="user-select:all;word-break:break-all">${esc(cmd)}</div>`;
      m.querySelector('#cli-new').textContent = t('cli.copy');
      m.querySelector('#cli-new').onclick = e => { e.stopImmediatePropagation(); copyText(res.data.secret); };
    }, {once: true});
  }

  // ── Routing ───────────────────────────────────────────────────────────────
  // Pages: App.page(id, {title: 'nav.key', admin: bool, hidden: bool,
  // render(el, arg)}). Hidden pages are reachable by URL but not in the menu.
  // URL: #id or #id/arg.
  const pages = [];

  function page(id, def) { pages.push(Object.assign({id}, def)); }

  function visiblePages() {
    return pages.filter(p => (!p.admin || session.admin) && (!p.when || p.when()));
  }

  function renderNav() {
    if (!session.ready) return;
    const cur = currentRoute().id;
    $('nav').innerHTML = visiblePages()
      .filter(p => !p.hidden)
      .map(p => `<a href="#${p.id}" class="${p.id === cur ? 'active' : ''}">${esc(t(p.title))}</a>`)
      .join('');
  }

  function currentRoute() {
    const h = decodeURIComponent(location.hash.slice(1));
    const i = h.indexOf('/');
    return i < 0 ? {id: h, arg: ''} : {id: h.slice(0, i), arg: h.slice(i + 1)};
  }

  let renderSeq = 0;
  async function route() {
    if (!session.ready) return;
    const r = currentRoute();
    const p = visiblePages().find(x => x.id === r.id) || visiblePages()[0];
    renderNav();
    refreshDiskBanner();
    if (p.hidden && p.parent) {
      const a = document.querySelector(`#nav a[href="#${p.parent}"]`);
      if (a) a.classList.add('active');
    }
    const el = $('app');
    const seq = ++renderSeq;
    el.innerHTML = `<div class="loading">${esc(t('common.loading'))}</div>`;
    const content = document.createElement('div');
    try {
      await p.render(content, r.arg);
    } catch (e) {
      content.innerHTML = `<div class="err" style="display:block">${esc(e.message || e)}</div>`;
    }
    // A newer navigation may have started while this page loaded.
    if (seq === renderSeq) { el.innerHTML = ''; el.appendChild(content); }
  }

  // ── Modal dialog ──────────────────────────────────────────────────────────

  function openModal(html) {
    $('modal').innerHTML = html;
    $('modal-overlay').classList.add('show');
    return $('modal');
  }

  function closeModal() { $('modal-overlay').classList.remove('show'); $('modal').innerHTML = ''; }

  // confirmDialog asks to confirm a dangerous action. Options:
  //   title, message (multi-line), danger: button label,
  //   check: label of an optional checkbox (checkDefault), typeToConfirm:
  //   text the user must type to enable the button.
  // Resolves to {ok, checked}.
  function confirmDialog(o) {
    return new Promise(resolve => {
      const m = openModal(`
        <h2>${esc(o.title)}</h2>
        ${(o.message || '').split('\n').filter(Boolean).map(l => `<p class="note" style="margin:0 0 10px">${esc(l)}</p>`).join('')}
        ${o.typeToConfirm ? `<input id="cd-type" autocomplete="off" placeholder="${esc(o.typeToConfirm)}" style="margin-top:6px">` : ''}
        ${o.check ? `<label class="check" style="margin-top:6px"><input type="checkbox" id="cd-check" ${o.checkDefault ? 'checked' : ''}>${esc(o.check)}</label>
          ${o.checkHint ? `<p class="muted small" style="margin:-8px 0 12px">${esc(o.checkHint)}</p>` : ''}` : ''}
        <div class="dialog-actions">
          <button class="btn" id="cd-cancel">${esc(t('common.cancel'))}</button>
          <button class="btn btn-danger-solid" id="cd-ok" ${o.typeToConfirm ? 'disabled' : ''}>${esc(o.danger || t('common.delete'))}</button>
        </div>`);
      const done = ok => {
        const c = m.querySelector('#cd-check');
        closeModal();
        resolve({ok, checked: !!(c && c.checked)});
      };
      m.querySelector('#cd-cancel').addEventListener('click', () => done(false));
      m.querySelector('#cd-ok').addEventListener('click', () => done(true));
      const typed = m.querySelector('#cd-type');
      if (typed) {
        typed.addEventListener('input', () => { m.querySelector('#cd-ok').disabled = typed.value !== o.typeToConfirm; });
        typed.focus();
      } else {
        m.querySelector('#cd-ok').focus();
      }
    });
  }

  // Low-disk warning for administrators, refreshed on every page change.
  async function refreshDiskBanner() {
    const el = $('disk-banner');
    if (!session.ready || !session.admin) { el.innerHTML = ''; return; }
    const res = await api('/ui/api/disk');
    if (!res.ok || !res.data.low) { el.innerHTML = ''; return; }
    const d = res.data;
    el.innerHTML = `<div class="banner">${esc(t('disk.lowBanner', {free: fmtBytes(d.free), total: fmtBytes(d.total)}))}
      <a href="#gc">${esc(t('disk.lowAction'))}</a></div>`;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  }

  function fmtBytes(b) {
    if (!b) return '0 B';
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + ' MB';
    return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function fmtTime(iso) {
    if (!iso || iso.startsWith('0001')) return '—';
    const d = new Date(iso);
    return d.toLocaleString(lang === 'en' ? 'en-GB' : lang, {dateStyle: 'short', timeStyle: 'short'});
  }

  function fmtAgo(iso) {
    if (!iso || iso.startsWith('0001')) return '—';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return t('time.now');
    if (s < 3600) return t('time.min', {n: Math.floor(s / 60)});
    if (s < 86400) return t('time.hour', {n: Math.floor(s / 3600)});
    return t('time.day', {n: Math.floor(s / 86400)});
  }

  let toastTimer;
  function toast(msg) {
    const el = $('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 3500);
  }

  // copyText copies to the clipboard. navigator.clipboard only works on
  // HTTPS or localhost, so plain-HTTP registries fall back to execCommand.
  async function copyText(text) {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (e) { /* fall back */ }
    if (!ok) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
    }
    toast(ok ? t('common.copied', {text: text.length > 60 ? text.slice(0, 57) + '…' : text}) : t('common.copyFailed'));
    return ok;
  }

  // Registry host as clients address it, for docker commands.
  function registryHost() { return location.host; }

  return {
    boot, api, post, page, route, t, addLang, setLang, lang: () => lang, langs: () => Object.keys(langs),
    session, openModal, closeModal, confirmDialog, copyText, esc, fmtBytes, fmtTime, fmtAgo, toast, registryHost, $,
  };
})();

App.addLang('en', {
  'lang.name': 'English',
  'login.title': 'rgstr — sign in',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.submit': 'Sign in',
  'login.invalid': 'Invalid credentials',
  'login.expired': 'Session expired, please sign in again',
  'pw.title': 'Change password',
  'pw.forcedTitle': 'Set a new password',
  'pw.forcedNote': 'User {user} has a temporary password. Enter it and choose a new password (at least 8 characters) to continue.',
  'pw.temporary': 'Temporary password',
  'pw.err.mismatch': 'Passwords do not match',
  'pw.err.current': 'The current password is wrong',
  'pw.err.weak': 'The new password must be at least 8 characters',
  'pw.err.same': 'The new password must differ from the current one',
  'pw.err.failed': 'The password could not be changed',
  'pw.current': 'Current password',
  'pw.new': 'New password',
  'pw.repeat': 'Repeat new password',
  'pw.save': 'Save password',
  'pw.mismatch': 'Passwords do not match',
  'pw.changed': 'Password changed',
  'pw.signInNew': 'Sign in with your new password',
  'hdr.password': 'Change password',
  'hdr.cli': 'CLI secret',
  'login.or': 'or',
  'login.sso': 'Sign in with {name}',
  'login.ssoErr.provider': 'Single sign-on failed. Try again or ask an administrator.',
  'login.ssoErr.state': 'The sign-in expired. Please try again.',
  'login.ssoErr.denied': 'Your account is not in a group allowed to use this registry.',
  'login.ssoErr.username': 'The identity provider sent no usable user name.',
  'login.ssoErr.local': 'A local user with your name exists. Sign in with its password.',
  'cli.title': 'CLI secret',
  'cli.note': 'Your account signs in through single sign-on and has no password here. For docker login, helm and CI use a CLI secret. Generating a new one revokes the previous secret.',
  'cli.noteLdap': 'docker login accepts your directory password. A CLI secret is an alternative that does not expose it (for CI and scripts). Generating a new one revokes the previous secret.',
  'cli.generate': 'Generate new secret',
  'cli.once': 'Copy it now — it is not shown again:',
  'cli.usage': 'Usage:',
  'cli.copy': 'Copy secret',
  'hdr.logout': 'Sign out',
  'hdr.noauth': 'auth disabled',
  'common.cancel': 'Cancel',
  'common.save': 'Save',
  'common.delete': 'Delete',
  'common.loading': 'Loading…',
  'common.failed': 'Failed: {status}',
  'common.close': 'Close',
  'common.copied': 'Copied: {text}',
  'common.copyFailed': 'Copy failed — select the text and copy it manually',
  'common.copy': 'Copy',
  'time.now': 'just now',
  'time.min': '{n} min ago',
  'time.hour': '{n} h ago',
  'time.day': '{n} d ago',
  'disk.lowBanner': 'Low disk space: {free} free of {total}.',
  'disk.lowAction': 'Free space →',
});
