'use strict';
// Image page: pull commands, platforms, config, layers with build history.

(() => {
  const {t, esc, fmtBytes, fmtTime, toast} = App;

  App.page('image', {title: 'nav.image', hidden: true, parent: 'repos', render});

  // arg: "repo:tag" or "repo@sha256:…"
  function parseRef(arg) {
    const at = arg.indexOf('@');
    if (at >= 0) return {repo: arg.slice(0, at), ref: arg.slice(at + 1), byDigest: true};
    const c = arg.lastIndexOf(':');
    return {repo: arg.slice(0, c), ref: arg.slice(c + 1), byDigest: false};
  }

  async function get(repo, ref) {
    const res = await App.api('/ui/api/image?' + new URLSearchParams({repo, ref}));
    if (!res.ok) throw new Error(res.data.error || t('common.failed', {status: res.status}));
    return res.data;
  }

  async function render(el, arg) {
    const {repo, ref, byDigest} = parseRef(arg);
    const img = await get(repo, ref);
    const host = App.registryHost();
    const title = byDigest ? `${repo}@${ref.slice(0, 19)}…` : `${repo}:${ref}`;
    const pullTag = byDigest ? '' : `docker pull ${host}/${repo}:${ref}`;
    const pullDigest = `docker pull ${host}/${repo}@${img.digest}`;

    el.innerHTML = `
      <p style="margin-bottom:10px"><a href="#repos">← ${esc(t('nav.repos'))}</a></p>
      <h2 class="page" style="word-break:break-all">${esc(title)}
        ${img.immutable ? `<span class="badge badge-warn">🔒 ${esc(t('repos.immutable'))}</span>` : ''}</h2>

      <div class="card">
        ${pullTag ? cmdRow(pullTag) : ''}
        ${cmdRow(pullDigest)}
        <table class="kv" style="margin-top:10px">
          ${kv(t('img.digest'), `<span class="mono small">${esc(img.digest)}</span>`)}
          ${kv(t('img.tags'), img.tags.length ? img.tags.map(x => `<a class="badge" href="#image/${encodeURIComponent(repo + ':' + x)}">:${esc(x)}</a>`).join(' ') : '—')}
          ${kv(t('img.type'), `<span class="small">${esc(mediaName(img.media_type))}</span>`)}
          ${kv(t('img.size'), esc(fmtBytes(img.size)) + (img.platforms ? ` <span class="muted small">${esc(t('img.sizeAll'))}</span>` : ''))}
        </table>
      </div>

      ${img.platforms ? `
        <h3>${esc(t('img.platforms'))}</h3>
        <div class="toolbar" id="plat-tabs">${img.platforms.map((p, i) => `
          <button class="btn ${i === 0 ? 'btn-primary' : ''}" data-i="${i}">${esc(platName(p))} <span class="small" style="opacity:.7">${esc(fmtBytes(p.size))}</span></button>`).join('')}
        </div>` : ''}
      <div id="img-details"></div>

      <details class="card" style="margin-top:16px">
        <summary style="cursor:pointer">${esc(t('img.raw'))}</summary>
        <pre class="mono small" style="overflow:auto;margin-top:10px;max-height:400px">${esc(JSON.stringify(img.manifest, null, 2))}</pre>
      </details>`;

    el.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copy(b.dataset.copy)));
    const box = el.querySelector('#img-details');
    box.addEventListener('click', e => {
      const step = e.target.closest('.step');
      if (step) step.classList.toggle('clamp');
    });
    if (img.image) {
      box.innerHTML = details(img.image);
    } else if (img.platforms && img.platforms.length) {
      const show = async i => {
        el.querySelectorAll('#plat-tabs .btn').forEach(b => b.classList.toggle('btn-primary', +b.dataset.i === i));
        box.innerHTML = `<div class="loading">${esc(t('common.loading'))}</div>`;
        const child = await get(repo, img.platforms[i].digest);
        box.innerHTML = `<p class="muted small" style="margin:4px 0 0">${esc(t('img.platformDigest'))} <span class="mono">${esc(child.digest)}</span></p>` +
          (child.image ? details(child.image) : '');
      };
      el.querySelector('#plat-tabs').addEventListener('click', e => {
        const b = e.target.closest('[data-i]');
        if (b) show(+b.dataset.i);
      });
      await show(0);
    }
  }

  function details(d) {
    const layers = d.layers.filter(l => !l.empty);
    const total = layers.reduce((s, l) => s + l.size, 0);
    const list = arr => arr.length ? arr.map(x => `<div class="mono small">${esc(x)}</div>`).join('') : '—';
    const labels = Object.keys(d.labels).sort();
    return `
      <div class="card">
        <h3 style="margin-top:0">${esc(t('img.config'))}</h3>
        <table class="kv">
          ${kv(t('img.platform'), esc(platName(d)))}
          ${kv(t('img.created'), esc(d.created ? fmtTime(d.created) : '—'))}
          ${d.author ? kv(t('img.author'), esc(d.author)) : ''}
          ${kv('Entrypoint', d.entrypoint.length ? `<span class="mono small">${esc(JSON.stringify(d.entrypoint))}</span>` : '—')}
          ${kv('Cmd', d.cmd.length ? `<span class="mono small">${esc(JSON.stringify(d.cmd))}</span>` : '—')}
          ${kv(t('img.workdir'), d.working_dir ? `<span class="mono small">${esc(d.working_dir)}</span>` : '—')}
          ${kv(t('img.user'), d.user ? `<span class="mono small">${esc(d.user)}</span>` : '—')}
          ${kv(t('img.ports'), d.exposed_ports.length ? d.exposed_ports.map(p => `<span class="badge">${esc(p)}</span>`).join(' ') : '—')}
          ${kv(t('img.volumes'), list(d.volumes))}
          ${kv(t('img.env'), list(d.env))}
          ${kv(t('img.labels'), labels.length ? labels.map(k => `<div class="mono small">${esc(k)}=${esc(d.labels[k])}</div>`).join('') : '—')}
        </table>
      </div>
      <h3>${esc(t('img.layers', {n: layers.length, size: fmtBytes(total)}))}</h3>
      <div class="tbl-wrap"><table class="tbl">
        <tr><th>#</th><th>${esc(t('img.step'))}</th><th>${esc(t('img.size'))}</th></tr>
        ${d.layers.map((l, i) => `
          <tr${l.empty ? ' class="muted"' : ''}>
            <td>${i + 1}</td>
            <td><div class="mono small step clamp" title="${esc(t('img.expand'))}">${esc(prettyCmd(l.created_by || l.comment || (l.digest ? l.digest : '—')))}</div>
              ${l.digest ? `<div class="muted small mono" title="${esc(l.digest)}">${esc(l.digest.slice(0, 19))}…</div>` : ''}</td>
            <td style="white-space:nowrap">${l.empty ? `<span class="muted small">${esc(t('img.noLayer'))}</span>` : esc(fmtBytes(l.size))}</td>
          </tr>`).join('')}
      </table></div>`;
  }

  // Collapse whitespace runs and put each "&&" step on its own line.
  function prettyCmd(c) {
    return c.replace(/\s+/g, ' ').replace(/ && /g, '\n  && ').replace(/ ; /g, ';\n  ').trim();
  }

  function cmdRow(cmd) {
    return `<div class="toolbar" style="margin-bottom:6px">
      <code class="grow mono small" style="background:#f6f6f8;padding:7px 10px;border-radius:4px;word-break:break-all">${esc(cmd)}</code>
      <button class="btn btn-sm" data-copy="${esc(cmd)}">${esc(t('img.copy'))}</button></div>`;
  }

  function kv(k, v) { return `<tr><th>${esc(k)}</th><td>${v}</td></tr>`; }

  function platName(p) {
    if (!p.os) return '—';
    return p.os + '/' + p.architecture + (p.variant ? '/' + p.variant : '');
  }

  function mediaName(mt) {
    if (/index|manifest\.list/.test(mt)) return t('img.multi') + ' (' + mt + ')';
    return mt;
  }

  async function copy(text) {
    App.copyText(text);
  }
})();

App.addLang('en', {
  'nav.image': 'Image',
  'img.digest': 'Digest',
  'img.tags': 'Tags',
  'img.type': 'Type',
  'img.size': 'Size',
  'img.sizeAll': '(all platforms, shared layers counted once)',
  'img.platforms': 'Platforms',
  'img.platform': 'Platform',
  'img.platformDigest': 'Platform manifest:',
  'img.config': 'Configuration',
  'img.created': 'Created',
  'img.author': 'Author',
  'img.workdir': 'Working directory',
  'img.user': 'User',
  'img.ports': 'Exposed ports',
  'img.volumes': 'Volumes',
  'img.env': 'Environment',
  'img.labels': 'Labels',
  'img.layers': 'Build steps — {n} layers, {size}',
  'img.step': 'Command',
  'img.noLayer': 'no layer',
  'img.raw': 'Raw manifest',
  'img.copy': 'Copy',
  'img.copied': 'Copied',
  'img.multi': 'multi-platform index',
  'img.expand': 'Click to expand or collapse',
});
