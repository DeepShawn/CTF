// Python 运行环境：在 Web Worker（模块类型）中加载 Pyodide（CPython 编译为 WebAssembly）并运行 ctfkit。
// 放在 Worker 里，工具计算（如爆破）时页面不会卡住；需要中止时由页面直接结束这个 Worker。

const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/v314.0.8/full/';
let registry = null;

const ready = (async () => {
  const { loadPyodide } = await import(PYODIDE + 'pyodide.mjs');
  const py = await loadPyodide({ indexURL: PYODIDE });
  const res = await fetch(new URL('py/ctfkit.zip', self.location.href));
  if (!res.ok) throw new Error('下载 ctfkit 失败：HTTP ' + res.status);
  py.unpackArchive(await res.arrayBuffer(), 'zip', { extractDir: '/home/pyodide/lib' });
  py.runPython('import sys; sys.path.insert(0, "/home/pyodide/lib")');
  registry = py.pyimport('ctfkit.registry');
  registry.all_tools();   // 预先导入全部工具模块
  return py.runPython('import sys; sys.version.split()[0]');
})();

ready.catch(() => {});   // 失败原因在收到请求时再返回给页面

self.onmessage = async (e) => {
  const { id, type, tool, params } = e.data;
  try {
    const version = await ready;
    if (type === 'ping') return self.postMessage({ id, ok: true, version });
    if (type === 'run') return self.postMessage({ id, ...JSON.parse(registry.run_json(tool, JSON.stringify(params))) });
    if (type === 'source') return self.postMessage({ id, ok: true, source: registry.source(tool) });
    self.postMessage({ id, ok: false, error: '未知请求：' + type });
  } catch (err) {
    self.postMessage({ id, ok: false, fatal: true, error: String(err && err.message || err) });
  }
};
