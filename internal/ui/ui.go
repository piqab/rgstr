// Package ui serves a minimal web interface for the registry.
// The entire UI is a single embedded HTML page with vanilla JS.
package ui

import (
	"net/http"

	"rgstr/internal/auth"
	"rgstr/internal/config"
)

// Handler serves the web UI.
type Handler struct {
	cfg         *config.Config
	authHandler *auth.Handler
}

// New creates a UI handler.
func New(cfg *config.Config, authHandler *auth.Handler) *Handler {
	return &Handler{cfg: cfg, authHandler: authHandler}
}

// Mount registers the UI handler on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/ui", h.serve)
	mux.HandleFunc("/ui/", h.serve)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
}

// page is the entire single-page UI.
// Credentials are stored in sessionStorage and sent as Basic auth on every fetch.
// When auth is disabled the login form is still shown but any credentials pass.
const page = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>rgstr</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f5f5f5;color:#222}
header{background:#1a1a2e;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:1.2rem;font-weight:600;letter-spacing:.05em}
header span{font-size:.8rem;opacity:.5;margin-left:auto}
#login-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:100}
.login-box{background:#fff;border-radius:8px;padding:32px;width:320px;box-shadow:0 4px 24px rgba(0,0,0,.2)}
.login-box h2{margin-bottom:20px;font-size:1.1rem}
.login-box label{display:block;font-size:.85rem;margin-bottom:4px;color:#555}
.login-box input{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:4px;font-size:.95rem;margin-bottom:14px}
.login-box button{width:100%;padding:9px;background:#1a1a2e;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.95rem}
.login-box .err{color:#c00;font-size:.82rem;margin-top:8px;display:none}
#app{max-width:1100px;margin:0 auto;padding:24px}
.stats-bar{display:flex;gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border-radius:8px;padding:16px 24px;flex:1;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.stat-card .val{font-size:2rem;font-weight:700;color:#1a1a2e}
.stat-card .lbl{font-size:.8rem;color:#888;margin-top:2px}
.repo-grid{display:flex;flex-direction:column;gap:12px}
.repo-card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.repo-header{padding:14px 18px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
.repo-header:hover{background:#fafafa}
.repo-name{font-weight:600;font-size:.95rem;flex:1}
.repo-pulls{font-size:.82rem;color:#888}
.repo-arrow{transition:transform .2s;font-size:.8rem;color:#aaa}
.repo-body{display:none;border-top:1px solid #f0f0f0;padding:12px 18px}
.repo-body.open{display:block}
.tag-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #f5f5f5}
.tag-row:last-child{border:none}
.tag-name{font-family:monospace;font-size:.88rem;flex:1}
.tag-digest{font-family:monospace;font-size:.75rem;color:#999;flex:2;word-break:break-all}
.tag-size{font-size:.78rem;color:#aaa;white-space:nowrap}
.btn-del{background:none;border:1px solid #e0e0e0;border-radius:4px;padding:3px 10px;cursor:pointer;font-size:.78rem;color:#c00}
.btn-del:hover{background:#fff0f0;border-color:#c00}
.loading{color:#999;font-size:.9rem;padding:16px 0}
.empty{color:#bbb;font-size:.85rem;padding:8px 0}
.search{margin-bottom:16px}
.search input{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:.9rem}
#toast{position:fixed;bottom:24px;right:24px;background:#222;color:#fff;padding:10px 18px;border-radius:6px;font-size:.88rem;opacity:0;transition:opacity .3s;pointer-events:none}
#toast.show{opacity:1}
</style>
</head>
<body>

<div id="login-overlay">
  <div class="login-box">
    <h2>rgstr &mdash; sign in</h2>
    <label>Username</label>
    <input id="li-user" type="text" autocomplete="username">
    <label>Password</label>
    <input id="li-pass" type="password" autocomplete="current-password">
    <button onclick="doLogin()">Sign in</button>
    <div class="err" id="li-err">Invalid credentials</div>
  </div>
</div>

<header>
  <h1>rgstr</h1>
  <span id="hdr-user"></span>
</header>

<div id="app" style="display:none">
  <div class="stats-bar">
    <div class="stat-card"><div class="val" id="s-repos">—</div><div class="lbl">repositories</div></div>
    <div class="stat-card"><div class="val" id="s-pulls">—</div><div class="lbl">total pulls</div></div>
  </div>
  <div class="search"><input type="search" placeholder="Filter repositories…" oninput="filterRepos(this.value)"></div>
  <div class="repo-grid" id="repo-grid"><div class="loading">Loading…</div></div>
</div>

<div id="toast"></div>

<script>
'use strict';

let creds = '';   // base64(user:pass)
let allRepos = [];

// ── Auth ──────────────────────────────────────────────────────────────────────

async function doLogin() {
  const user = document.getElementById('li-user').value;
  const pass = document.getElementById('li-pass').value;
  const b64 = btoa(user + ':' + pass);
  const res = await fetch('/stats', {headers: {Authorization: 'Basic ' + b64}});
  if (res.status === 401) {
    document.getElementById('li-err').style.display = 'block';
    return;
  }
  creds = b64;
  sessionStorage.setItem('rgstr_creds', b64);
  sessionStorage.setItem('rgstr_user', user);
  document.getElementById('li-err').style.display = 'none';
  document.getElementById('login-overlay').style.display = 'none';
  document.getElementById('hdr-user').textContent = user;
  document.getElementById('app').style.display = 'block';
  loadAll();
}

function api(path, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (creds) opts.headers['Authorization'] = 'Basic ' + creds;
  return fetch(path, opts);
}

// ── Data loading ──────────────────────────────────────────────────────────────

async function loadAll() {
  const [statsRes] = await Promise.all([api('/stats')]);
  if (!statsRes.ok) { toast('Failed to load stats'); return; }
  const stats = await statsRes.json();

  document.getElementById('s-repos').textContent = stats.total_repos;
  document.getElementById('s-pulls').textContent = stats.total_pulls;

  // Build pull map
  const pullMap = {};
  (stats.repositories || []).forEach(r => { pullMap[r.name] = r.pulls; });

  // Load all repos with tags from catalog
  const catRes = await api('/v2/_catalog?n=1000');
  const cat = catRes.ok ? await catRes.json() : {repositories: []};
  const repos = cat.repositories || [];

  // Load tags for each repo in parallel (batch of 10)
  const results = [];
  for (let i = 0; i < repos.length; i += 10) {
    const batch = repos.slice(i, i + 10);
    const settled = await Promise.all(batch.map(async name => {
      const r = await api('/v2/' + name + '/tags/list');
      const j = r.ok ? await r.json() : {tags: []};
      return {name, tags: j.tags || [], pulls: pullMap[name] || 0};
    }));
    results.push(...settled);
  }

  allRepos = results;
  renderRepos(allRepos);
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function renderRepos(repos) {
  const grid = document.getElementById('repo-grid');
  if (!repos.length) { grid.innerHTML = '<div class="empty">No repositories found.</div>'; return; }
  grid.innerHTML = repos.map(repoCard).join('');
}

function repoCard(r) {
  const tags = (r.tags || []).map(t => tagRow(r.name, t)).join('');
  return ` + "`" + `
  <div class="repo-card">
    <div class="repo-header" onclick="toggleRepo(this)">
      <span class="repo-name">${esc(r.name)}</span>
      <span class="repo-pulls">${r.pulls} pulls</span>
      <span class="repo-arrow">▶</span>
    </div>
    <div class="repo-body">
      ${tags || '<div class="empty">No tags.</div>'}
    </div>
  </div>` + "`" + `;
}

function tagRow(repo, tag) {
  return ` + "`" + `
  <div class="tag-row" id="row-${esc(repo)}-${esc(tag)}">
    <span class="tag-name">:${esc(tag)}</span>
    <span class="tag-digest" id="digest-${esc(repo)}-${esc(tag)}">loading…</span>
    <span class="tag-size"  id="size-${esc(repo)}-${esc(tag)}"></span>
    <button class="btn-del" onclick="deleteTag('${esc(repo)}','${esc(tag)}')">delete</button>
  </div>` + "`" + `;
}

function toggleRepo(header) {
  const body = header.nextElementSibling;
  const arrow = header.querySelector('.repo-arrow');
  const open = body.classList.toggle('open');
  arrow.style.transform = open ? 'rotate(90deg)' : '';
  if (open) loadTagDetails(header);
}

async function loadTagDetails(header) {
  const repo = header.querySelector('.repo-name').textContent;
  const body = header.nextElementSibling;
  const rows = body.querySelectorAll('.tag-row');
  for (const row of rows) {
    const tag = row.querySelector('.tag-name').textContent.slice(1);
    const digestEl = row.querySelector('[id^="digest-"]');
    const sizeEl = row.querySelector('[id^="size-"]');
    if (digestEl.textContent !== 'loading…') continue;
    try {
      const res = await api('/v2/' + repo + '/manifests/' + tag, {
        headers: {'Accept': 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'}
      });
      if (!res.ok) { digestEl.textContent = 'error'; continue; }
      const digest = res.headers.get('Docker-Content-Digest') || '—';
      const json = await res.json();
      const size = calcSize(json);
      digestEl.textContent = digest.slice(0, 19) + '…';
      digestEl.title = digest;
      sizeEl.textContent = size ? fmtBytes(size) : '';
    } catch { digestEl.textContent = 'error'; }
  }
}

function calcSize(manifest) {
  let total = 0;
  if (manifest.config && manifest.config.size) total += manifest.config.size;
  (manifest.layers || []).forEach(l => { if (l.size) total += l.size; });
  return total;
}

// ── Delete ────────────────────────────────────────────────────────────────────

async function deleteTag(repo, tag) {
  if (!confirm('Delete ' + repo + ':' + tag + '?\nThis will remove the manifest. Blobs are cleaned up by GC.')) return;
  // 1. Get digest
  const headRes = await api('/v2/' + repo + '/manifests/' + tag);
  if (!headRes.ok) { toast('Could not resolve manifest digest'); return; }
  const digest = headRes.headers.get('Docker-Content-Digest');
  if (!digest) { toast('No digest in response'); return; }
  // 2. Delete by digest
  const delRes = await api('/v2/' + repo + '/manifests/' + digest, {method: 'DELETE'});
  if (delRes.ok || delRes.status === 202) {
    const row = document.getElementById('row-' + repo + '-' + tag);
    if (row) row.remove();
    toast('Deleted ' + repo + ':' + tag);
  } else {
    toast('Delete failed: ' + delRes.status);
  }
}

// ── Filter ────────────────────────────────────────────────────────────────────

function filterRepos(q) {
  const filtered = q ? allRepos.filter(r => r.name.includes(q)) : allRepos;
  renderRepos(filtered);
}

// ── Utils ─────────────────────────────────────────────────────────────────────

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
  if (b < 1024*1024*1024) return (b/1024/1024).toFixed(1) + ' MB';
  return (b/1024/1024/1024).toFixed(2) + ' GB';
}

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ── Boot ──────────────────────────────────────────────────────────────────────

(function init() {
  const saved = sessionStorage.getItem('rgstr_creds');
  const user  = sessionStorage.getItem('rgstr_user');
  if (saved) {
    creds = saved;
    document.getElementById('login-overlay').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    if (user) document.getElementById('hdr-user').textContent = user;
    loadAll();
  }
  // Allow Enter key in login form
  ['li-user','li-pass'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  });
})();
</script>
</body>
</html>`
