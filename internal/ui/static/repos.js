'use strict';
// Repositories page: list, filter, tag/image/repository deletion.

(() => {
  const {t, esc, fmtBytes, fmtAgo, toast, post} = App;

  let allRepos = [];
  let totalPulls = 0;
  const openRepos = new Set();
  const selected = new Map(); // repo → Set of tag names
  let filter = '';
  let root = null;

  App.page('repos', {title: 'nav.repos', render});

  // arg (from #repos/<name>) presets the filter and opens that repository.
  async function render(el, arg) {
    root = el;
    if (arg) { filter = arg; openRepos.add(arg); }
    const res = await App.api('/ui/api/repos');
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    allRepos = res.data.repositories;
    totalPulls = res.data.total_pulls;
    selected.clear();

    el.innerHTML = `
      <div class="stats-bar">
        <div class="stat-card"><div class="val">${allRepos.length}</div><div class="lbl">${esc(t('repos.count'))}</div></div>
        <div class="stat-card"><div class="val">${totalPulls}</div><div class="lbl">${esc(t('repos.pulls'))}</div></div>
        ${App.session.admin ? '<div class="stat-card" id="disk-card" style="flex:2"></div>' : ''}
      </div>
      <div class="toolbar"><input type="search" class="search" id="repo-filter" placeholder="${esc(t('repos.filter'))}"></div>
      <div class="repo-grid" id="repo-grid"></div>`;
    const input = el.querySelector('#repo-filter');
    input.value = filter;
    input.addEventListener('input', () => { filter = input.value; renderGrid(); });
    el.querySelector('#repo-grid').addEventListener('click', onClick);
    el.querySelector('#repo-grid').addEventListener('change', onChange);
    renderGrid();
    if (App.session.admin) loadDisk(el.querySelector('#disk-card'));
  }

  // Disk card: free space of the storage volume and the registry's share.
  async function loadDisk(card) {
    const res = await App.api('/ui/api/disk?data=1');
    if (!res.ok || !card.isConnected) return;
    const d = res.data;
    if (!d.supported) {
      card.innerHTML = `<div class="val">${esc(fmtBytes(d.data_bytes))}</div><div class="lbl">${esc(t('disk.registry'))}</div>`;
      return;
    }
    const used = d.total - d.free;
    const pct = d.total ? Math.round(used / d.total * 100) : 0;
    card.innerHTML = `
      <div class="val">${esc(fmtBytes(d.free))}</div>
      <div class="lbl">${esc(t('disk.freeOf', {total: fmtBytes(d.total)}))} · ${esc(t('disk.registryUses', {size: fmtBytes(d.data_bytes)}))}</div>
      <div class="bar ${d.low ? 'bar-err' : pct >= 80 ? 'bar-warn' : ''}"><div style="width:${pct}%"></div></div>`;
  }

  // The "free space now" option of delete dialogs (administrators only).
  function freeOption() {
    return App.session.admin
      ? {check: t('repos.freeNow'), checkDefault: true, checkHint: t('repos.freeNowHint')}
      : {};
  }

  function deletedToast(base, gc) {
    if (gc && gc.error) toast(base + ' ' + t('repos.gcFailed', {error: gc.error}));
    else if (gc) toast(base + ' ' + t('repos.freed', {size: fmtBytes(gc.bytes_freed)}));
    else toast(base + (App.session.admin ? '' : ' ' + t('repos.freedLater')));
  }

  async function reload() {
    if (root && root.isConnected) await render(root, '');
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  function renderGrid() {
    const grid = root.querySelector('#repo-grid');
    const q = filter.trim().toLowerCase();
    const repos = q ? allRepos.filter(r => r.name.toLowerCase().includes(q)) : allRepos;
    grid.innerHTML = repos.length ? repos.map(repoCard).join('') : `<div class="empty">${esc(t('repos.none'))}</div>`;
  }

  function repoCard(r) {
    const n = r.tags.length;
    const sel = selected.get(r.name) || new Set();
    const tools = r.can_delete ? `
      <div class="repo-tools">
        <label class="check" style="margin:0"><input type="checkbox" data-act="select-all" ${sel.size && sel.size === r.tags.filter(x => !x.immutable).length ? 'checked' : ''}>${esc(t('repos.selectAll'))}</label>
        <button class="btn btn-sm btn-danger" data-act="delete-selected" ${sel.size ? '' : 'disabled'}>${esc(t('repos.deleteSelected', {n: sel.size}))}</button>
      </div>` : '';
    return `
    <div class="repo-card${openRepos.has(r.name) ? ' open' : ''}" data-repo="${esc(r.name)}">
      <div class="repo-header" data-act="toggle">
        <span class="repo-name" title="${esc(t('repos.selectHint'))}">${esc(r.name)}</span>
        <button class="btn btn-sm" data-act="copy" title="${esc(t('repos.copyHint', {path: App.registryHost() + '/' + r.name}))}">⧉ ${esc(t('common.copy'))}</button>
        <span class="repo-meta">${esc(t('repos.meta', {tags: n, pulls: r.pulls}))}</span>
        ${r.can_delete ? `<button class="btn btn-sm btn-danger" data-act="delete-repo">${esc(t('repos.deleteRepo'))}</button>` : ''}
        <span class="repo-arrow">▶</span>
      </div>
      <div class="repo-body">${tools}${r.tags.map(tg => tagRow(r, tg, sel)).join('')}</div>
    </div>`;
  }

  function tagRow(repo, tg, sel) {
    const check = repo.can_delete && !tg.immutable
      ? `<input type="checkbox" data-act="select" data-tag="${esc(tg.name)}" ${sel.has(tg.name) ? 'checked' : ''}>` : '';
    const lock = tg.immutable ? `<span class="badge badge-warn" title="${esc(t('repos.immutableHint'))}">🔒 ${esc(t('repos.immutable'))}</span>` : '';
    const del = repo.can_delete && !tg.immutable ? `
      <button class="btn btn-sm btn-danger" data-act="delete-tag" data-tag="${esc(tg.name)}" title="${esc(t('repos.deleteTagHint'))}">${esc(t('repos.deleteTag'))}</button>
      ${tg.digest ? `<button class="btn btn-sm btn-danger" data-act="delete-image" data-tag="${esc(tg.name)}" title="${esc(t('repos.deleteImageHint'))}">${esc(t('repos.deleteImage'))}</button>` : ''}` : '';
    const link = `#image/${encodeURIComponent(repo.name + ':' + tg.name)}`;
    const name = `<span class="tag-name">${check} <a href="${link}" title="${esc(t('repos.openImage'))}">:${esc(tg.name)}</a></span>${lock}`;
    if (tg.error) return `<div class="tag-row">${name}<span class="tag-err">${esc(tg.error)}</span>${del}</div>`;

    const same = sameDigest(repo, tg).map(x => ':' + x);
    const plats = tg.platforms.map(p => {
      const nm = p.os + '/' + p.architecture + (p.variant ? '/' + p.variant : '');
      const size = tg.platforms.length > 1 && p.size ? ' · ' + fmtBytes(p.size) : '';
      return `<span class="badge">${esc(nm + size)}</span>`;
    }).join('');
    return `
    <div class="tag-row">
      ${name}
      <span class="tag-digest" title="${esc(tg.digest)}">${esc(tg.digest.slice(0, 19))}…</span>
      ${same.length ? `<span class="tag-same">${esc(t('repos.sameAs', {tags: same.join(', ')}))}</span>` : ''}
      <span class="platforms">${plats}</span>
      <span class="tag-size">${tg.size ? fmtBytes(tg.size) : ''}</span>
      <span class="tag-time" title="${esc(App.fmtTime(tg.pushed_at))}">${esc(fmtAgo(tg.pushed_at))}</span>
      ${del}
    </div>`;
  }

  function sameDigest(repo, tg) {
    return repo.tags.filter(x => x.name !== tg.name && x.digest && x.digest === tg.digest).map(x => x.name);
  }

  // ── Events ────────────────────────────────────────────────────────────────

  function onClick(e) {
    const card = e.target.closest('.repo-card');
    if (!card) return;
    const repo = allRepos.find(r => r.name === card.dataset.repo);
    const btn = e.target.closest('[data-act]');
    if (!btn || btn.tagName === 'INPUT') return;
    const act = btn.dataset.act;
    if (act === 'toggle') {
      // The name is text to select and copy; it does not fold the card.
      if (e.target.closest('.repo-name') || String(window.getSelection()).trim()) return;
      if (card.classList.toggle('open')) openRepos.add(repo.name); else openRepos.delete(repo.name);
    } else if (act === 'copy') {
      e.stopPropagation();
      App.copyText(App.registryHost() + '/' + repo.name);
    } else if (act === 'delete-repo') {
      e.stopPropagation();
      deleteRepo(repo);
    } else if (act === 'delete-tag') {
      deleteTags(repo, [btn.dataset.tag]);
    } else if (act === 'delete-image') {
      deleteImage(repo, repo.tags.find(x => x.name === btn.dataset.tag));
    } else if (act === 'delete-selected') {
      deleteTags(repo, [...(selected.get(repo.name) || [])]);
    }
  }

  function onChange(e) {
    const card = e.target.closest('.repo-card');
    if (!card) return;
    const repo = allRepos.find(r => r.name === card.dataset.repo);
    const sel = selected.get(repo.name) || new Set();
    if (e.target.dataset.act === 'select-all') {
      if (e.target.checked) repo.tags.filter(x => !x.immutable).forEach(x => sel.add(x.name)); else sel.clear();
    } else if (e.target.dataset.act === 'select') {
      if (e.target.checked) sel.add(e.target.dataset.tag); else sel.delete(e.target.dataset.tag);
    } else {
      return;
    }
    selected.set(repo.name, sel);
    card.outerHTML = repoCard(repo);
  }

  // ── Deletion ──────────────────────────────────────────────────────────────

  async function deleteTags(repo, tags) {
    if (!tags.length) return;
    // Images that lose their last tag here will be removed by GC.
    const remaining = new Set(repo.tags.filter(x => !tags.includes(x.name)).map(x => x.digest));
    const orphaned = new Set(repo.tags.filter(x => tags.includes(x.name) && !remaining.has(x.digest)).map(x => x.digest));
    const c = await App.confirmDialog(Object.assign({
      title: tags.length === 1
        ? t('repos.confirmTag', {ref: repo.name + ':' + tags[0]})
        : t('repos.confirmTags', {n: tags.length, repo: repo.name}),
      message: orphaned.size ? t('repos.noteOrphaned', {n: orphaned.size}) : t('repos.noteKept'),
    }, orphaned.size ? freeOption() : {}));
    if (!c.ok) return;

    const res = await post('/ui/api/tags/delete', {repo: repo.name, tags, free_space: c.checked});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    const failed = res.data.results.filter(x => x.error);
    if (failed.length) {
      toast(t('repos.someFailed', {n: failed.length}) + ' ' + failed.map(x => `:${x.tag} (${x.error})`).join(', '));
    } else {
      deletedToast(t('repos.deletedTags', {n: tags.length}), res.data.gc);
    }
    await reload();
  }

  async function deleteImage(repo, tg) {
    const tags = repo.tags.filter(x => x.digest === tg.digest).map(x => ':' + x.name);
    const c = await App.confirmDialog(Object.assign({
      title: t('repos.confirmImageTitle', {digest: tg.digest.slice(0, 19) + '…'}),
      message: t('repos.confirmImage', {tags: tags.join(', ')}),
    }, freeOption()));
    if (!c.ok) return;
    const res = await post('/ui/api/images/delete', {repo: repo.name, digest: tg.digest, free_space: c.checked});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    deletedToast(t('repos.deletedImage', {tags: tags.join(', ')}), res.data.gc);
    await reload();
  }

  async function deleteRepo(repo) {
    const c = await App.confirmDialog(Object.assign({
      title: t('repos.confirmRepoTitle', {repo: repo.name}),
      message: t('repos.confirmRepo', {n: repo.tags.length}),
      typeToConfirm: repo.name,
    }, freeOption()));
    if (!c.ok) return;
    const res = await post('/ui/api/repos/delete', {repo: repo.name, free_space: c.checked});
    if (!res.ok) { toast(res.data.error || t('common.failed', {status: res.status})); return; }
    openRepos.delete(repo.name);
    deletedToast(t('repos.deletedRepo', {repo: repo.name}), res.data.gc);
    await reload();
  }
})();

App.addLang('en', {
  'nav.repos': 'Repositories',
  'repos.count': 'repositories',
  'repos.pulls': 'total pulls',
  'repos.filter': 'Filter repositories…',
  'repos.none': 'No repositories found.',
  'repos.meta': '{tags} tags · {pulls} pulls',
  'repos.selectAll': 'Select all',
  'repos.deleteSelected': 'Delete selected ({n})',
  'repos.deleteRepo': 'Delete repository',
  'repos.deleteTag': 'delete tag',
  'repos.deleteTagHint': 'Remove only this tag; other tags of the image stay',
  'repos.deleteImage': 'delete image',
  'repos.deleteImageHint': 'Remove the image and every tag pointing to it',
  'repos.sameAs': 'same as {tags}',
  'repos.confirmTag': 'Delete tag {ref}?',
  'repos.confirmTags': 'Delete {n} tags in {repo}?',
  'repos.noteOrphaned': '{n} image(s) will have no tags left; GC will remove their data.',
  'repos.noteKept': 'The images stay available under their other tags.',
  'repos.confirmImageTitle': 'Delete image {digest}?',
  'repos.confirmImage': 'These tags will be removed: {tags}',
  'repos.confirmRepoTitle': 'Delete repository {repo}?',
  'repos.confirmRepo': 'All {n} tags will be deleted.\nType the repository name to confirm:',
  'repos.freeNow': 'Free the disk space now',
  'repos.freeNowHint': 'Runs garbage collection for the deleted data right away. Otherwise the space is freed by the next GC (data pushed within the grace period waits until it ends).',
  'repos.freed': '{size} freed.',
  'repos.freedLater': 'The disk space is freed by the next garbage collection.',
  'repos.gcFailed': 'Space not freed yet: {error}',
  'disk.freeOf': 'free of {total}',
  'disk.registryUses': 'registry data {size}',
  'disk.registry': 'registry data',
  'repos.someFailed': '{n} tag(s) not deleted:',
  'repos.deletedTags': 'Deleted {n} tag(s)',
  'repos.deletedImage': 'Deleted image ({tags})',
  'repos.deletedRepo': 'Deleted repository {repo}',
  'repos.immutable': 'immutable',
  'repos.copyHint': 'Copy {path}',
  'repos.selectHint': 'The name can be selected and copied',
  'repos.openImage': 'Open image details',
  'repos.immutableHint': 'Protected by an immutability policy: cannot be overwritten or deleted',
});
