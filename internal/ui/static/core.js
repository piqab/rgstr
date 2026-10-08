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
    renderNav();
    if (session.ready) route();
  }

  // ── Session ───────────────────────────────────────────────────────────────
  // The session token (never the password) lives in sessionStorage.
  const session = {
    token: sessionStorage.getItem('rgstr_token') || '',
    user: '',
    admin: false,
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
    $('btn-logout').addEventListener('click', () => showLogin(''));
    $('btn-password').addEventListener('click', () => openPasswordForm());
    $('pw-form').addEventListener('submit', doChangePassword);
    $('pw-cancel').addEventListener('click', closePasswordForm);
    $('modal-overlay').addEventListener('click', e => { if (e.target.id === 'modal-overlay') closeModal(); });
    window.addEventListener('hashchange', route);

    const me = await api('/ui/api/me');
    session.authEnabled = me.data.auth_enabled;
    if (!session.authEnabled) {
      session.admin = true;
      $('hdr-user').textContent = t('hdr.noauth');
      showApp();
    } else if (me.data.user) {
      signedIn(me.data.user, me.data.admin);
    } else {
      showLogin(session.token ? t('login.expired') : '');
    }
  }

  async function doLogin(e) {
    e.preventDefault();
    const username = $('li-user').value, password = $('li-pass').value;
    const res = await post('/ui/api/login', {username, password});
    if (res.status === 403 && res.data.must_change) {
      // Temporary password: it only allows setting a new one.
      session.forced = {username, password};
      $('li-pass').value = '';
      $('login-overlay').classList.remove('show');
      openPasswordForm();
      return;
    }
    if (!res.ok) { showLoginError(t('login.invalid')); return; }
    startSession(res.data);
  }

  function startSession(s) {
    session.token = s.token;
    sessionStorage.setItem('rgstr_token', s.token);
    $('li-pass').value = '';
    $('login-overlay').classList.remove('show');
    signedIn(s.user, s.admin);
  }

  function signedIn(name, admin) {
    session.user = name;
    session.admin = !!admin;
    $('hdr-user').textContent = name;
    $('btn-password').style.display = 'block';
    $('btn-logout').style.display = 'block';
    showApp();
  }

  function showApp() {
    session.ready = true;
    $('app').style.display = 'block';
    renderNav();
    route();
  }

  function showLogin(msg) {
    session.token = '';
    session.user = '';
    session.admin = false;
    session.ready = false;
    sessionStorage.removeItem('rgstr_token');
    $('app').style.display = 'none';
    $('btn-password').style.display = 'none';
    $('btn-logout').style.display = 'none';
    $('hdr-user').textContent = '';
    $('nav').innerHTML = '';
    closeModal();
    $('login-overlay').classList.add('show');
    showLoginError(msg);
    $('li-user').focus();
  }

  function showLoginError(msg) {
    $('li-err').textContent = msg || '';
    $('li-err').style.display = msg ? 'block' : 'none';
  }

  // ── Password change ───────────────────────────────────────────────────────

  function openPasswordForm() {
    const forced = session.forced;
    $('pw-form').reset();
    showPasswordError('');
    $('pw-title').textContent = forced ? t('pw.forcedTitle') : t('pw.title');
    $('pw-note').textContent = forced ? t('pw.forcedNote') : '';
    $('pw-note').style.display = forced ? 'block' : 'none';
    $('pw-current-wrap').style.display = forced ? 'none' : 'block';
    $('pw-current').required = !forced;
    $('pw-overlay').classList.add('show');
    (forced ? $('pw-new') : $('pw-current')).focus();
  }

  function closePasswordForm() {
    $('pw-overlay').classList.remove('show');
    if (session.forced) { session.forced = null; showLogin(''); }
  }

  async function doChangePassword(e) {
    e.preventDefault();
    const next = $('pw-new').value;
    if (next !== $('pw-repeat').value) { showPasswordError(t('pw.mismatch')); return; }
    const forced = session.forced;
    const username = forced ? forced.username : session.user;
    const password = forced ? forced.password : $('pw-current').value;
    const res = await post('/ui/api/password', {username, password, new_password: next});
    if (!res.ok) { showPasswordError(res.data.error || t('common.failed', {status: res.status})); return; }
    $('pw-overlay').classList.remove('show');
    if (forced) {
      session.forced = null;
      const s = await post('/ui/api/login', {username, password: next});
      if (s.ok) startSession(s.data); else showLogin(t('pw.signInNew'));
    }
    toast(t('pw.changed'));
  }

  function showPasswordError(msg) {
    $('pw-err').textContent = msg || '';
    $('pw-err').style.display = msg ? 'block' : 'none';
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

  // Registry host as clients address it, for docker commands.
  function registryHost() { return location.host; }

  return {
    boot, api, post, page, route, t, addLang, setLang, lang: () => lang, langs: () => Object.keys(langs),
    session, openModal, closeModal, esc, fmtBytes, fmtTime, fmtAgo, toast, registryHost, $,
  };
})();

App.addLang('en', {
  'login.title': 'rgstr — sign in',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.submit': 'Sign in',
  'login.invalid': 'Invalid credentials',
  'login.expired': 'Session expired, please sign in again',
  'pw.title': 'Change password',
  'pw.forcedTitle': 'Set a new password',
  'pw.forcedNote': 'You signed in with a temporary password. Choose a new password (at least 8 characters) to continue.',
  'pw.current': 'Current password',
  'pw.new': 'New password',
  'pw.repeat': 'Repeat new password',
  'pw.save': 'Save password',
  'pw.mismatch': 'Passwords do not match',
  'pw.changed': 'Password changed',
  'pw.signInNew': 'Sign in with your new password',
  'hdr.password': 'Change password',
  'hdr.logout': 'Sign out',
  'hdr.noauth': 'auth disabled',
  'common.cancel': 'Cancel',
  'common.save': 'Save',
  'common.delete': 'Delete',
  'common.loading': 'Loading…',
  'common.failed': 'Failed: {status}',
  'common.close': 'Close',
  'time.now': 'just now',
  'time.min': '{n} min ago',
  'time.hour': '{n} h ago',
  'time.day': '{n} d ago',
});
