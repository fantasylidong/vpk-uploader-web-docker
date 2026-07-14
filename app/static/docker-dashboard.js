(() => {
  const root = document.querySelector('[data-docker-dashboard]');
  if (!root) return;
  const containers = root.querySelector('[data-containers]');
  const summary = root.querySelector('[data-summary]');
  const error = root.querySelector('[data-error]');
  const dialog = document.querySelector('[data-file-dialog]');
  let fileContainer = null;
  let currentPath = '/';
  const bytes = value => {
    if (!value) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
    return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
  };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function request(url, options) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || '请求失败');
    return data;
  }
  async function load() {
    error.hidden = true;
    try {
      const data = await request('/api/admin/docker/containers');
      const running = data.containers.filter(item => item.status === 'running').length;
      summary.innerHTML = `<strong>${data.containers.length}</strong> 个容器 · <strong>${running}</strong> 个运行中 · ${esc(new Date(data.generated_at).toLocaleString())}`;
      containers.innerHTML = data.containers.map(item => `<article class="container-card">
        <div class="container-title"><div><h3>${esc(item.name)}</h3><code>${esc(item.short_id)} · ${esc(item.image)}</code></div><span class="status status-${esc(item.status)}">${esc(item.status)}</span></div>
        <div class="metric-grid"><div><span>CPU</span><strong>${item.cpu_percent.toFixed(1)}%</strong></div><div><span>内存</span><strong>${bytes(item.memory_usage)} / ${bytes(item.memory_limit)}</strong></div><div><span>网络 ↓ / ↑</span><strong>${bytes(item.network_rx)} / ${bytes(item.network_tx)}</strong></div><div><span>磁盘读 / 写</span><strong>${bytes(item.block_read)} / ${bytes(item.block_write)}</strong></div></div>
        <div class="mount-list"><span class="muted">挂载</span>${item.mounts.length ? item.mounts.map(m => `<code title="${esc(m.source)}">${esc(m.destination)} ${m.writable ? '读写' : '只读'}</code>`).join('') : '<code>无</code>'}</div>
        <div class="row container-actions"><button data-action="start" data-id="${esc(item.id)}" ${item.status === 'running' ? 'disabled' : ''}>启动</button><button class="secondary" data-action="restart" data-id="${esc(item.id)}" ${item.status !== 'running' ? 'disabled' : ''}>重启</button><button class="danger" data-action="stop" data-id="${esc(item.id)}" ${item.status !== 'running' ? 'disabled' : ''}>停止</button><button class="secondary" data-files-id="${esc(item.id)}" data-name="${esc(item.name)}" ${item.status !== 'running' ? 'disabled' : ''}>文件</button></div>
      </article>`).join('') || '<p class="muted">没有容器</p>';
    } catch (err) { error.textContent = err.message; error.hidden = false; containers.innerHTML = ''; }
  }
  async function action(id, action, button) {
    button.disabled = true;
    try { await request(`/api/admin/docker/containers/${encodeURIComponent(id)}/${action}`, {method: 'POST'}); await load(); }
    catch (err) { error.textContent = err.message; error.hidden = false; button.disabled = false; }
  }
  async function loadFiles(path) {
    currentPath = path;
    dialog.querySelector('[data-current-path]').textContent = path;
    const data = await request(`/api/admin/docker/containers/${encodeURIComponent(fileContainer)}/files?path=${encodeURIComponent(path)}`);
    dialog.querySelector('[data-parent]').disabled = !data.parent;
    dialog.querySelector('[data-parent]').dataset.path = data.parent || '';
    dialog.querySelector('[data-files]').innerHTML = data.entries.map(item => `<button type="button" class="file-entry" ${item.type === 'directory' ? `data-path="${esc(item.path)}"` : 'disabled'}><span>${item.type === 'directory' ? '目录' : '文件'} · ${esc(item.name)}</span><small>${item.type === 'file' ? bytes(item.size) : ''}</small></button>`).join('') || '<p class="muted">目录为空</p>';
  }
  root.addEventListener('click', event => { const actionButton = event.target.closest('[data-action]'); if (actionButton) action(actionButton.dataset.id, actionButton.dataset.action, actionButton); const fileButton = event.target.closest('[data-files-id]'); if (fileButton) { fileContainer = fileButton.dataset.filesId; dialog.querySelector('[data-file-title]').textContent = `${fileButton.dataset.name} 文件`; dialog.showModal(); loadFiles('/'); } });
  dialog.addEventListener('click', event => { const entry = event.target.closest('[data-path]'); if (entry) loadFiles(entry.dataset.path); });
  root.querySelector('[data-refresh]').addEventListener('click', load);
  dialog.querySelector('[data-close]').addEventListener('click', () => dialog.close());
  dialog.querySelector('[data-parent]').addEventListener('click', event => loadFiles(event.currentTarget.dataset.path));
  dialog.querySelector('[data-file-refresh]').addEventListener('click', () => loadFiles(currentPath));
  load();
  setInterval(load, 15000);
})();
