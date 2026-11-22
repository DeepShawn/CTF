// CTFKit Web 版。界面全部使用 TesseraUI 组件；工具页由 manifest.json（ctfkit 导出的工具描述文件）自动生成，
// 计算交给 worker.js 中的 Python（Pyodide）完成。
import Tessera from './tessera/tessera.js';
import { renderMarkdown, esc } from './md.js';

const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');
const ICONS = { encoding: 'code', classical: 'key', hash: 'shield', misc: 'sparkle' };

let manifest = null;
const toolsById = new Map();

// ------------------------------------------------------------------ Python Worker

class Python {
  constructor() { this.start(); }
  start() {
    this.worker = new Worker('worker.js', { type: 'module' });
    this.pending = new Map();
    this.seq = 0;
    this.worker.onmessage = (e) => {
      const p = this.pending.get(e.data.id);
      if (p) { this.pending.delete(e.data.id); p(e.data); }
    };
    this.worker.onerror = (e) => {
      for (const p of this.pending.values()) p({ ok: false, fatal: true, error: e.message || 'Python 运行环境加载失败' });
      this.pending.clear();
    };
    this.ready = this.call({ type: 'ping' });
  }
  call(msg) {
    const id = ++this.seq;
    return new Promise((resolve) => { this.pending.set(id, resolve); this.worker.postMessage({ id, ...msg }); });
  }
  /** 中止正在运行的工具：直接结束 Worker 并重新加载（爆破类工具可能运行很久） */
  restart() {
    this.worker.terminate();
    for (const p of this.pending.values()) p({ ok: false, error: '已停止' });
    this.start();
    watchStatus();
  }
}
const python = new Python();

function watchStatus() {
  const el = $('#py-status');
  el.dataset.state = 'loading';
  el.innerHTML = '<span class="ts-spinner ts-sm"></span><span class="py-status-text">Python 加载中</span>';
  python.ready.then((r) => {
    if (r.ok) {
      el.dataset.state = 'ready';
      el.innerHTML = `<i data-icon="success"></i><span class="py-status-text">Python ${esc(r.version)}</span>`;
      el.dataset.tooltip = `Python ${r.version}（Pyodide）已就绪，全部计算在本机完成，数据不会上传`;
    } else {
      el.dataset.state = 'error';
      el.innerHTML = '<i data-icon="error"></i><span class="py-status-text">加载失败</span>';
      el.dataset.tooltip = r.error;
    }
    Tessera.init(el);
  });
}

// ------------------------------------------------------------------ 外观设置

const appearance = Object.assign({ theme: 'system', shape: 'tile', contrast: false },
  JSON.parse(localStorage.getItem('ctfkit:appearance') || '{}'));

const saveAppearance = () => localStorage.setItem('ctfkit:appearance', JSON.stringify(appearance));

/** 启动时恢复外观。主题与拼贴 / 圆融已由 index.html 中的内联脚本提前写好，这里只处理需要检测设备的部分，
 *  避免连续触发多个视图过渡动画 */
function restoreAppearance() {
  if (appearance.shape === 'flow') Tessera.setShape('flow');
  if (appearance.contrast) Tessera.setContrast(true);
}

function setupSettings() {
  const dlg = $('#settings');
  $(`#set-theme input[value="${appearance.theme}"]`).checked = true;
  $(`#set-shape input[value="${appearance.shape}"]`).checked = true;
  $('#set-contrast').checked = appearance.contrast;
  $('#open-settings').addEventListener('click', () => Tessera.openDialog(dlg));
  dlg.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => Tessera.closeDialog(dlg)));
  $('#set-theme').addEventListener('change', (e) => { appearance.theme = e.target.value; Tessera.setTheme(appearance.theme); saveAppearance(); });
  $('#set-shape').addEventListener('change', (e) => {
    appearance.shape = e.target.value;
    const actual = Tessera.setShape(appearance.shape);
    saveAppearance();
    if (appearance.shape === 'flow' && actual !== 'flow') Tessera.toast('这台设备不适合流韵外观，已改用圆融', { type: 'warning' });
  });
  $('#set-contrast').addEventListener('change', (e) => { appearance.contrast = e.target.checked; Tessera.setContrast(appearance.contrast); saveAppearance(); });
}

// ------------------------------------------------------------------ 侧边栏

function toolMatches(t, q) {
  if (!q) return true;
  const hay = [t.id, t.title, t.summary, t.chapter, ...(t.keywords || [])].join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function renderSidebar(q = '') {
  const nav = $('#side-nav');
  const cur = currentToolId();
  let html = `<a class="ts-sidebar-item" href="#/"${cur === null ? ' aria-current="page"' : ''}><i data-icon="home"></i><span class="ts-sidebar-label">首页</span></a>`;
  for (const [cat, meta] of Object.entries(manifest.categories)) {
    const tools = manifest.tools.filter((t) => t.category === cat && toolMatches(t, q));
    if (!tools.length) continue;
    html += `<span class="ts-overline ts-sidebar-section">${esc(meta.title)}${meta.chapter ? ' · ' + esc(meta.chapter) : ''}</span>`;
    for (const t of tools) {
      html += `<a class="ts-sidebar-item" href="#/tool/${esc(t.id)}"${t.id === cur ? ' aria-current="page"' : ''}>`
        + `<i data-icon="${ICONS[cat] || 'file'}"></i><span class="ts-sidebar-label">${esc(t.title)}</span></a>`;
    }
  }
  nav.innerHTML = html;
  Tessera.init(nav);
}

// ------------------------------------------------------------------ 首页

function toolCard(t) {
  return `<a class="ts-card ts-pressable ts-state tool-card" href="#/tool/${esc(t.id)}">
    <span class="tool-card-head"><span class="ts-title-3">${esc(t.title)}</span>${t.chapter ? `<span class="ts-tag">${esc(t.chapter)}</span>` : ''}</span>
    <span class="ts-body-sm ts-secondary">${esc(t.summary)}</span></a>`;
}

function renderHome() {
  setTitle('');
  const q = sessionStorage.getItem('ctfkit:q') || '';
  let cats = '';
  for (const [cat, meta] of Object.entries(manifest.categories)) {
    const tools = manifest.tools.filter((t) => t.category === cat);
    if (!tools.length) continue;
    cats += `<section class="cat" data-cat="${cat}"><h2 class="ts-title-2">${esc(meta.title)} <span class="ts-badge">${tools.length}</span>
      ${meta.chapter ? `<span class="ts-caption ts-secondary">教材 ${esc(meta.chapter)}</span>` : ''}</h2>
      <div class="tool-grid">${tools.map(toolCard).join('')}</div></section>`;
  }
  view.innerHTML = `
    <section class="hero">
      <h1 class="ts-title-1">CTF 工具包</h1>
      <p class="ts-body ts-secondary">面向初学者：每个工具都附原理讲解与实际运行的 Python 代码。全部计算在浏览器中完成，数据不会上传。</p>
      <div class="ts-banner" data-tone="warning"><i data-icon="warning"></i><div class="ts-banner-body"><span class="ts-banner-title">使用声明</span>
        本工具包仅用于学习、CTF 比赛与已获授权的安全测试。未经授权对他人计算机系统进行扫描、入侵或破坏，违反《中华人民共和国网络安全法》等法律法规。</div></div>
    </section>
    <section class="ts-card quick">
      <div class="ts-field"><label class="ts-field-label" for="quick-in">智能识别：粘贴一段密文，自动尝试 20 种编码并逐层解开</label>
        <div class="ts-input ts-textarea" data-autosize><textarea id="quick-in" rows="2" placeholder="例如 Wm14aFozdHRZV2RwWTE5bGJtTnZaR2x1WjMwPQ=="></textarea></div></div>
      <div class="ts-tiles"><button class="ts-button ts-primary ts-pressable ts-state" id="quick-go"><i data-icon="sparkle"></i>识别</button></div>
    </section>
    <section class="search-row mobile-search">
      <div class="ts-input"><i data-icon="search"></i><input type="search" id="home-search" placeholder="搜索 ${manifest.tools.length} 个工具" aria-label="搜索工具" value="${esc(q)}"></div>
    </section>
    <div id="home-cats">${cats}</div>
    <section class="ts-card about">
      <h2 class="ts-title-3">关于 v${esc(manifest.version)}</h2>
      <p class="ts-body-sm">本版本包含教材 1.1 编码、3.1 古典密码、3.4 哈希三部分，共 ${manifest.tools.length} 个工具。Python 2 与 Python 3 并存的完整环境（含 pwntools 等库）请使用
      <a class="ts-link" href="https://github.com/DeepShawn/CTF/tree/main/env/docker">Docker 镜像</a>；后续版本计划见
      <a class="ts-link" href="https://github.com/DeepShawn/CTF/blob/main/plan/README.md">计划文档</a>。</p>
    </section>`;
  Tessera.init(view);
  const go = () => {
    const v = $('#quick-in').value;
    if (!v.trim()) return Tessera.toast('请先粘贴要识别的内容', { type: 'warning' });
    sessionStorage.setItem('ctfkit:prefill', JSON.stringify({ tool: 'encoding.magic', text: v }));
    location.hash = '#/tool/encoding.magic';
  };
  $('#quick-go').addEventListener('click', go);
  const search = $('#home-search');
  const filter = () => {
    const q = search.value.trim();
    sessionStorage.setItem('ctfkit:q', q);
    for (const sec of view.querySelectorAll('.cat')) {
      let n = 0;
      sec.querySelectorAll('.tool-card').forEach((card) => {
        const t = toolsById.get(card.getAttribute('href').slice(7));
        const show = toolMatches(t, q);
        card.hidden = !show;
        n += show;
      });
      sec.hidden = n === 0;
    }
  };
  Tessera.onCommittedInput(search, filter);
  filter();
}

// ------------------------------------------------------------------ 工具页

function fieldHtml(f, prefix) {
  const id = `${prefix}-${f.id}`;
  const label = `<label class="ts-field-label" for="${id}">${esc(f.label)}</label>`;
  const help = f.help ? `<div class="ts-field-help">${esc(f.help)}</div>` : '';
  const ph = f.placeholder ? ` placeholder="${esc(f.placeholder)}"` : '';
  const d = f.default ?? '';
  let body = '';
  switch (f.type) {
    case 'text':
      body = `${label}<div class="ts-input ts-textarea mono" data-autosize><textarea id="${id}" data-field="${f.id}" rows="4" spellcheck="false"${ph}>${esc(String(d))}</textarea></div>`;
      break;
    case 'string':
      body = `${label}<div class="ts-input mono"><input id="${id}" data-field="${f.id}" value="${esc(String(d))}" spellcheck="false" autocomplete="off"${ph}></div>`;
      break;
    case 'number':
      body = `<span class="ts-field-label" id="${id}-l">${esc(f.label)}</span><div class="ts-number"><input aria-labelledby="${id}-l" data-field="${f.id}" data-kind="number"`
        + ` min="${f.min ?? ''}" max="${f.max ?? ''}" step="1" value="${esc(String(d))}"></div>`;
      break;
    case 'select':
      body = `${label}<div class="ts-input ts-select"><select id="${id}" data-field="${f.id}">`
        + f.choices.map((c) => `<option${c === d ? ' selected' : ''}>${esc(String(c))}</option>`).join('') + '</select></div>';
      break;
    case 'segmented':
      body = `<span class="ts-field-label">${esc(f.label)}</span><div class="ts-segmented" role="radiogroup" aria-label="${esc(f.label)}" data-field="${f.id}">`
        + f.choices.map((c) => `<label><input type="radio" name="${id}" value="${esc(String(c))}"${c === d ? ' checked' : ''}><span>${esc(String(c))}</span></label>`).join('') + '</div>';
      break;
    case 'switch':
      body = `<label class="ts-check"><input type="checkbox" role="switch" class="ts-switch" data-field="${f.id}" data-kind="switch"${d ? ' checked' : ''}>${esc(f.label)}</label>`;
      break;
    default:
      body = `${label}<div class="ts-input"><input id="${id}" data-field="${f.id}" value="${esc(String(d))}"></div>`;
  }
  const vw = f.visibleWhen ? ` data-visible-when='${esc(JSON.stringify(f.visibleWhen))}'` : '';
  return `<div class="ts-field field-${f.type}" data-wrap="${f.id}"${vw}>${body}${help}</div>`;
}

function readParams(form) {
  const p = {};
  form.querySelectorAll('[data-field]').forEach((el) => {
    const k = el.dataset.field;
    if (el.classList.contains('ts-segmented')) p[k] = el.querySelector('input:checked')?.value;
    else if (el.dataset.kind === 'switch') p[k] = el.checked;
    else if (el.dataset.kind === 'number') p[k] = Number(el.value);
    else p[k] = el.value;
  });
  return p;
}

function writeParams(form, params) {
  for (const [k, v] of Object.entries(params)) {
    const el = form.querySelector(`[data-field="${k}"]`);
    if (!el) continue;
    if (el.classList.contains('ts-segmented')) {
      const r = el.querySelector(`input[value="${CSS.escape(String(v))}"]`);
      if (r) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); }
    } else if (el.dataset.kind === 'switch') el.checked = !!v;
    else { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }
  }
}

function updateVisibility(form) {
  const p = readParams(form);
  form.querySelectorAll('[data-visible-when]').forEach((w) => {
    const cond = JSON.parse(w.dataset.visibleWhen);
    w.hidden = !Object.entries(cond).every(([k, v]) => (Array.isArray(v) ? v.includes(p[k]) : p[k] === v));
  });
}

function outputHtml(o) {
  if (o.type === 'text') {
    return `<div class="ts-code output-text" data-lang="结果"><pre><code>${esc(o.value)}</code></pre></div>`;
  }
  if (o.type === 'fields') {
    return `<dl class="ts-dl">${o.items.map(([k, v]) => `<div><dt>${esc(String(k))}</dt><dd class="mono selectable">${esc(String(v))}</dd></div>`).join('')}</dl>`;
  }
  if (o.type === 'table') {
    const num = o.rows.length ? o.columns.map((_, i) => o.rows.every((r) => typeof r[i] === 'number')) : [];
    return `<div class="ts-table-wrap output-table"><table class="ts-table"><thead><tr>${o.columns.map((c, i) => `<th${num[i] ? ' class="ts-num"' : ''}>${esc(String(c))}</th>`).join('')}</tr></thead>`
      + `<tbody>${o.rows.map((r) => `<tr>${r.map((c, i) => `<td class="${num[i] ? 'ts-num' : 'mono selectable'}">${esc(String(c))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
      + `<p class="ts-caption ts-secondary">共 ${o.rows.length} 行</p>`;
  }
  if (o.type === 'group') return o.items.map(outputHtml).join('');
  return `<pre>${esc(JSON.stringify(o))}</pre>`;
}

function outputText(o) {
  if (o.type === 'text') return o.value;
  if (o.type === 'fields') return o.items.map(([k, v]) => `${k}: ${v}`).join('\n');
  if (o.type === 'table') return [o.columns, ...o.rows].map((r) => r.join('\t')).join('\n');
  if (o.type === 'group') return o.items.map(outputText).join('\n\n');
  return '';
}

function renderTool(id) {
  const t = toolsById.get(id);
  if (!t) { view.innerHTML = `<div class="ts-empty"><h4 class="ts-empty-title">没有这个工具</h4><p class="ts-empty-text">${esc(id)}</p><a class="ts-button ts-pressable ts-state" href="#/">返回首页</a></div>`; Tessera.init(view); return; }
  setTitle(t.title);
  const prefix = 'f-' + t.id.replace(/\W/g, '-');
  const cat = manifest.categories[t.category];
  view.innerHTML = `
    <section class="tool-head">
      <div class="ts-breadcrumb-lite ts-caption ts-secondary"><a class="ts-link" href="#/">工具</a> / ${esc(cat.title)}</div>
      <h1 class="ts-title-1">${esc(t.title)}</h1>
      <div class="ts-tiles tags">
        ${t.chapter ? `<span class="ts-tag ts-accent">教材 ${esc(t.chapter)}</span>` : ''}
        <span class="ts-tag ts-success"><i data-icon="check"></i>离线可用</span>
        <span class="ts-tag ts-pigment-lapis">Python</span>
      </div>
      <p class="ts-body ts-secondary">${esc(t.summary)}</p>
    </section>
    <div class="tool-layout">
      <section class="ts-card tool-form" id="tool-form">
        ${t.inputs.map((f) => fieldHtml(f, prefix)).join('')}
        ${t.options.length ? `<div class="options">${t.options.map((f) => fieldHtml(f, prefix)).join('')}</div>` : ''}
        <div class="ts-tiles actions">
          <button class="ts-button ts-primary ts-pressable ts-state" id="run"><i data-icon="play-fill"></i>运行</button>
          ${t.examples.length ? `<button class="ts-button ts-pressable ts-state" id="example"><i data-icon="lightbulb"></i>填入示例</button>` : ''}
          <button class="ts-button ts-text ts-pressable ts-state" id="clear">清空</button>
        </div>
        ${t.live ? '<p class="ts-caption ts-secondary">输入后自动计算</p>' : '<p class="ts-caption ts-secondary">此工具计算量较大，点击“运行”开始</p>'}
      </section>
      <section class="ts-card tool-output" aria-live="polite">
        <div class="output-head"><span class="ts-title-3">结果</span><span class="ts-spacer"></span>
          <button class="ts-button ts-sm ts-pressable ts-state" id="copy-out" disabled><i data-icon="copy"></i>复制结果</button></div>
        <div id="output"><div class="ts-empty compact"><p class="ts-empty-text">${t.live ? '在左侧输入内容' : '填好参数后点击“运行”'}</p></div></div>
      </section>
    </div>
    <section class="ts-card explain">
      <div class="ts-tabs" role="tablist" aria-label="讲解" id="explain-tabs">
        <button class="ts-tab" role="tab" aria-selected="true" data-panel="p-principle">原理</button>
        <button class="ts-tab" role="tab" data-panel="p-source">Python 代码</button>
      </div>
      <div class="panel md" id="p-principle">${renderMarkdown(t.principle)}</div>
      <div class="panel" id="p-source" hidden>
        <p class="ts-body-sm ts-secondary">这是工具实际运行的代码（模块 <code>${esc(t.module)}</code>）。可以复制到自己电脑上用 Python 3 运行，也可以在 Docker 环境中用 <code>ctfkit info ${esc(t.id)} --source</code> 查看。</p>
        <div id="source-box"><div class="ts-skeleton" style="height:240px"></div></div>
      </div>
    </section>`;
  Tessera.init(view);

  const form = $('#tool-form');
  const out = $('#output');
  const copyBtn = $('#copy-out');
  let lastOutput = null;
  let timer = null;
  let running = 0;

  updateVisibility(form);
  form.addEventListener('change', () => { updateVisibility(form); if (t.live) schedule(); });

  async function run() {
    const ticket = ++running;
    const params = readParams(form);
    const slow = setTimeout(() => {
      if (ticket !== running) return;
      out.innerHTML = `<div class="running"><div class="ts-progress" data-indeterminate></div><p class="ts-body-sm">正在计算…</p>
        <button class="ts-button ts-sm ts-danger ts-pressable ts-state" id="stop">停止</button></div>`;
      Tessera.init(out);
      $('#stop', out)?.addEventListener('click', () => python.restart());
    }, 400);
    if (!(await python.ready).ok) {
      clearTimeout(slow);
      out.innerHTML = `<div class="ts-banner" data-tone="danger"><i data-icon="error"></i><div class="ts-banner-body"><span class="ts-banner-title">Python 运行环境加载失败</span>
        请检查网络后刷新页面（首次使用需要从 cdn.jsdelivr.net 下载约 10 MB）。</div></div>`;
      Tessera.init(out);
      return;
    }
    const r = await python.call({ type: 'run', tool: t.id, params });
    clearTimeout(slow);
    if (ticket !== running) return;   // 已有更新的计算
    if (r.ok) {
      lastOutput = r.output;
      out.innerHTML = outputHtml(r.output);
      copyBtn.disabled = false;
    } else {
      lastOutput = null;
      copyBtn.disabled = true;
      out.innerHTML = `<div class="ts-banner" data-tone="${r.error === '已停止' ? 'warning' : 'danger'}"><i data-icon="${r.error === '已停止' ? 'info' : 'error'}"></i><div class="ts-banner-body">${esc(r.error)}</div></div>`;
    }
    Tessera.init(out);
  }

  function schedule() {
    clearTimeout(timer);
    const p = readParams(form);
    const main = p[t.inputs[0].id];
    if (typeof main === 'string' && !main.trim()) {
      out.innerHTML = '<div class="ts-empty compact"><p class="ts-empty-text">在左侧输入内容</p></div>';
      copyBtn.disabled = true;
      return;
    }
    if (typeof main === 'string' && main.length > 1_000_000) return;   // 超过 1 MB 改为手动运行
    timer = setTimeout(run, 300);
  }

  if (t.live) form.querySelectorAll('textarea, input:not([type=radio]):not([type=checkbox])').forEach((el) => Tessera.onCommittedInput(el, schedule));
  $('#run').addEventListener('click', run);
  form.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
  $('#clear').addEventListener('click', () => {
    form.querySelectorAll('textarea').forEach((el) => { el.value = ''; el.dispatchEvent(new Event('input', { bubbles: true })); });
    form.querySelector('textarea, input')?.focus();
  });
  let exIndex = 0;
  $('#example')?.addEventListener('click', () => {
    writeParams(form, t.examples[exIndex % t.examples.length]);
    exIndex++;
    updateVisibility(form);
    run();
  });
  copyBtn.addEventListener('click', async () => {
    if (!lastOutput) return;
    try { await navigator.clipboard.writeText(outputText(lastOutput)); Tessera.toast('已复制', { type: 'success' }); }
    catch { Tessera.toast('浏览器不允许复制，请手动选择文字', { type: 'warning' }); }
  });

  // 讲解标签页
  let sourceLoaded = false;
  $('#explain-tabs').addEventListener('click', async (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (!tab) return;
    view.querySelectorAll('.explain .panel').forEach((p) => { p.hidden = p.id !== tab.dataset.panel; });
    if (tab.dataset.panel === 'p-source' && !sourceLoaded) {
      sourceLoaded = true;
      const r = await python.call({ type: 'source', tool: t.id });
      const box = $('#source-box');
      box.innerHTML = r.ok ? `<div class="ts-code" data-lang="Python" data-lines><pre><code>${esc(r.source)}</code></pre></div>`
        : `<div class="ts-banner" data-tone="danger"><i data-icon="error"></i><div class="ts-banner-body">${esc(r.error)}</div></div>`;
      Tessera.init(box);
    }
  });

  // 从首页“智能识别”带过来的输入
  const pre = JSON.parse(sessionStorage.getItem('ctfkit:prefill') || 'null');
  if (pre && pre.tool === t.id) {
    sessionStorage.removeItem('ctfkit:prefill');
    writeParams(form, { [t.inputs[0].id]: pre.text });
    run();
  }
}

// ------------------------------------------------------------------ 路由

function currentToolId() {
  const m = location.hash.match(/^#\/tool\/(.+)$/);
  return m ? decodeURIComponent(m[1]) : null;
}

function setTitle(title) {
  $('#page-title').textContent = title;
  document.title = title ? `${title} · CTFKit` : 'CTFKit · CTF 工具包';
  $('#back').hidden = !title;
  $('#mobile-brand').classList.toggle('has-back', !!title);
}

function route() {
  const id = currentToolId();
  if (id) renderTool(id); else renderHome();
  renderSidebar($('#side-search').value.trim());
  window.scrollTo({ top: 0 });
  view.focus({ preventScroll: true });
}

async function main() {
  Tessera.init();
  restoreAppearance();
  setupSettings();
  watchStatus();
  try {
    manifest = await (await fetch('manifest.json')).json();
  } catch (e) {
    view.innerHTML = '<div class="ts-banner" data-tone="danger"><i data-icon="error"></i><div class="ts-banner-body">工具列表加载失败，请刷新页面。</div></div>';
    Tessera.init(view);
    return;
  }
  manifest.tools.forEach((t) => toolsById.set(t.id, t));
  $('#version').textContent = 'v' + manifest.version;
  Tessera.onCommittedInput($('#side-search'), (v) => renderSidebar(v.trim()));
  $('#back').addEventListener('click', () => { if (history.length > 1) history.back(); else location.hash = '#/'; });
  window.addEventListener('hashchange', route);
  route();
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
}

main();
