'use strict';
const $ = id => document.getElementById(id);
let csrf = '', role = '', config = null, tlsFiles = [], busy = false;
const controls = new Map(), secretControls = new Map();

function message(text, error = false) { $('notice').textContent = text; $('notice').dataset.error = String(error); }

async function api(path, body) {
  const response = await fetch('/api/' + path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: body === undefined ? {} : {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) { $('workspace').hidden = true; $('login').hidden = false; }
    throw new Error(data.message || '操作失败');
  }
  return data;
}

async function perform(action) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(e => e.disabled = true);
  try { await action(); } catch (e) { message(e.message, true); } finally {
    busy = false;
    document.querySelectorAll('button').forEach(e => e.disabled = false);
  }
}

function get(object, path) { return path.split('.').reduce((value, key) => value?.[key], object); }
function set(object, path, value) {
  const keys = path.split('.'), last = keys.pop();
  keys.reduce((value, key) => value[key], object)[last] = value;
}

function input(label, value, type = 'text', options) {
  const container = document.createElement('label');
  container.textContent = label;
  const element = document.createElement(options ? 'select' : type === 'textarea' ? 'textarea' : 'input');
  if (options) {
    for (const [v, title] of options) { const option = document.createElement('option'); option.value = v; option.textContent = title; element.append(option); }
  } else if (type !== 'textarea') element.type = type;
  if (type === 'checkbox') element.checked = !!value; else element.value = value ?? '';
  element.autocomplete = 'off';
  container.append(element);
  return {container, element};
}

// field binds a control to a dotted config path, e.g. "singBox.inbound.listen_port".
function field(parent, key, label, type = 'text', options, value = get(config, key)) {
  const {container, element} = input(label, value, type, options);
  $(parent).append(container);
  controls.set(key, {input: element, type});
  return element;
}

function readControl(element, type) {
  return type === 'number' ? Number(element.value) : type === 'checkbox' ? element.checked : element.value.trim();
}

function tlsOptions(value) {
  const options = [['', '选择已导入 TLS 文件'], ...tlsFiles.map(n => [n, n])];
  if (value && !tlsFiles.includes(value)) options.push([value, value + '（不可用）']);
  return options;
}
function tlsField(parent, key, label, value = get(config, key)) {
  const element = field(parent, key, label, 'text', tlsOptions(value), value);
  element.value = value || '';
  return element;
}

function randomUUID() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = b[6] & 0x0f | 0x40; b[8] = b[8] & 0x3f | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function secretInput(placeholder, generate) {
  const wrap = document.createElement('div');
  const {container, element} = input('', '', 'password');
  element.autocomplete = 'new-password';
  element.placeholder = placeholder;
  wrap.append(container);
  if (generate) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = '生成 UUID';
    button.addEventListener('click', () => { element.type = 'text'; element.value = randomUUID(); });
    wrap.append(button);
  }
  return {wrap, element};
}

// secretField is a fixed credential (Home uuid, frp token).
function secretField(parent, key, label, generate = false) {
  const wrap = document.createElement('div');
  const title = document.createElement('label');
  title.textContent = label;
  const {wrap: inner, element} = secretInput('留空保留已有凭据', generate);
  title.append(inner);
  const clearLabel = document.createElement('label');
  const clear = document.createElement('input');
  clear.type = 'checkbox';
  clearLabel.append(clear, document.createTextNode('明确清除此凭据'));
  wrap.append(title, clearLabel);
  $(parent).append(wrap);
  secretControls.set(key, {input: element, clear});
}

function row(parent, definitions, item, extra) {
  const container = document.createElement('div');
  container.className = 'service';
  const fields = document.createElement('div');
  fields.className = 'service-fields';
  for (const [key, label, type] of definitions) {
    const {container: l, element} = input(label, item[key], type);
    element.dataset.field = key;
    element.dataset.type = type;
    fields.append(l);
  }
  container.append(fields);
  if (extra) extra(container, fields);
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.textContent = '移除';
  remove.addEventListener('click', () => container.remove());
  container.append(remove);
  $(parent).append(container);
  return container;
}

function rowValues(element) {
  const item = {};
  element.querySelectorAll('[data-field]').forEach(i => item[i.dataset.field] = readControl(i, i.dataset.type));
  return item;
}

const csv = value => (value ?? []).join(', ');
const parseCSV = text => text.split(',').map(s => s.trim()).filter(Boolean);

function userRow(user = {name: '', uuid: ''}) {
  const element = row('users', [['name', '身份名称', 'text']], user, (container, fields) => {
    const label = document.createElement('label');
    label.textContent = '认证 UUID';
    const {wrap, element: secret} = secretInput(user.uuid ? '留空保留已有 UUID' : '新 user 必须设置 UUID', true);
    secret.dataset.secret = 'uuid';
    label.append(wrap);
    fields.append(label);
  });
  element.dataset.ref = user.uuid || '';
}

function ruleRow(rule = {auth_user: [], port: [18096]}) {
  row('rules', [['auth_user', '身份名称', 'text'], ['port', '端口', 'text'], ['port_range', '端口范围', 'text']],
    {auth_user: csv(rule.auth_user), port: csv(rule.port), port_range: csv(rule.port_range)});
}

function allowRow(entry = {single: 18096}) {
  row('frp-list', [['start', '起始端口', 'number'], ['end', '结束端口（单个端口留空）', 'text']],
    {start: entry.single ?? entry.start, end: entry.single === undefined ? entry.end : ''});
}

function proxyRow(proxy = {name: '', type: 'tcp', localIP: '192.168.1.10', localPort: 8096, remotePort: 18096}) {
  row('frp-list', [['name', '服务名称', 'text'], ['localIP', '家庭设备 IP', 'text'], ['localPort', '家庭服务端口', 'number'], ['remotePort', '中继映射端口', 'number']], proxy);
}

function summaryItem(parent, title, value) {
  const item = document.createElement('div');
  const label = document.createElement('dt'); label.textContent = title;
  const content = document.createElement('dd'); content.textContent = value;
  item.append(label, content); parent.append(item);
}

function renderOverview() {
  const relay = role === 'relay';
  const transport = $('transport-summary'), services = $('services-summary');
  transport.replaceChildren(); services.replaceChildren();
  $('transport-note').textContent = relay
    ? 'Home 与 App → Relay 加密入口 → 服务注册与转发'
    : '家庭服务 → Home → 加密连接 → Relay';
  $('services-note').textContent = relay
    ? '此端管理服务端口范围与访问权限。实际家庭服务列表在 Home 配置。'
    : 'App 通过 Relay 的映射端口访问这些家庭服务。';
  $('management-note').textContent = relay
    ? '公网访问须使用 HTTPS 和管理员认证。管理页可与加密连接共用 443 端口。修改管理入口后需要在机器上重启管理服务。'
    : '家庭局域网通过本机 IP 访问，仍需管理员登录。修改管理入口后需要在机器上重启管理服务。';
  if (relay) {
    const inbound = config.singBox.inbound;
    const frontend = config.management.frontend;
    summaryItem(transport, '加密入口', `${frontend?.listen || inbound.listen}:${frontend?.port || inbound.listen_port}`);
    summaryItem(transport, 'TLS 服务器名称', inbound.tls.server_name);
    summaryItem(transport, '接入身份', inbound.users.map(u => u.name).join('、') || '尚未配置');
    summaryItem(transport, '服务注册入口', `127.0.0.1:${config.frps.bindPort}`);
    const summary = document.createElement('dl'); summary.className = 'summary-grid';
    summaryItem(summary, '允许的映射端口', config.frps.allowPorts.map(p => p.single ?? `${p.start}–${p.end}`).join('、') || '无');
    for (const rule of config.singBox.route.rules) {
      summaryItem(summary, rule.auth_user.join('、'), [...(rule.port || []), ...(rule.port_range || [])].join('、') || '无允许端口');
    }
    services.append(summary);
  } else {
    const out = config.singBox.outbound;
    summaryItem(transport, 'Relay', `${out.server}:${out.server_port}`);
    summaryItem(transport, 'TLS 服务器名称', out.tls.server_name);
    summaryItem(transport, '家庭标识', config.frpc.user || '未设置');
    summaryItem(transport, '认证凭据', '已配置，修改时留空保留');
    if (!config.frpc.proxies.length) {
      const empty = document.createElement('p'); empty.textContent = '尚未添加服务'; services.append(empty);
    }
    for (const proxy of config.frpc.proxies) {
      const summary = document.createElement('dl'); summary.className = 'summary-grid service-summary';
      summaryItem(summary, '服务名称', proxy.name);
      summaryItem(summary, '家庭地址', `${proxy.localIP}:${proxy.localPort}`);
      summaryItem(summary, '中继映射端口', proxy.remotePort);
      services.append(summary);
    }
  }
}

function render(data) {
  config = data.config; role = data.role; tlsFiles = data.tlsFiles;
  controls.clear(); secretControls.clear();
  for (const id of ['singbox-fields', 'singbox-secrets', 'users', 'rules', 'frp-fields', 'frp-secrets', 'frp-list', 'log-fields', 'management-fields']) $(id).replaceChildren();
  const relay = role === 'relay';
  renderOverview();
  $('title').textContent = relay ? 'Relay 配置' : '家庭端配置';
  document.title = 'OpenPlayX · ' + $('title').textContent;
  $('users-block').hidden = $('rules-block').hidden = !relay;

  if (relay) {
    $('singbox-note').textContent = 'Home 和 App 通过此加密入口连接 Relay。';
    field('singbox-fields', 'singBox.inbound.listen', '监听地址');
    field('singbox-fields', 'singBox.inbound.listen_port', '加密连接端口', 'number');
    field('singbox-fields', 'singBox.inbound.tls.server_name', 'TLS 服务器名称');
    tlsField('singbox-fields', 'singBox.inbound.tls.certificate_path', '服务器证书');
    tlsField('singbox-fields', 'singBox.inbound.tls.key_path', '服务器私钥');
    for (const user of config.singBox.inbound.users) userRow(user);
    for (const rule of config.singBox.route.rules) ruleRow(rule);

    $('frp-title').textContent = '服务注册入口';
    $('frp-note').textContent = '接收 Home 的服务注册，仅监听本机回环，并验证加密连接。';
    field('frp-fields', 'frps.bindPort', '服务注册控制端口', 'number');
    tlsField('frp-fields', 'frps.transport.tls.certFile', '注册连接证书');
    tlsField('frp-fields', 'frps.transport.tls.keyFile', '注册连接私钥');
    secretField('frp-secrets', 'token', '服务注册凭据（至少 32 字符）');
    $('frp-list-title').textContent = '允许注册的映射端口';
    $('frp-list-note').textContent = '允许 Home 注册的端口范围；单个端口不填结束端口。';
    $('add-frp-item').textContent = '添加端口范围';
    for (const entry of config.frps.allowPorts) allowRow(entry);
  } else {
    $('singbox-note').textContent = '家庭端通过加密连接访问 Relay，本机转发入口仅供服务注册使用。';
    field('singbox-fields', 'singBox.outbound.server', 'Relay 地址');
    field('singbox-fields', 'singBox.outbound.server_port', 'Relay 端口', 'number');
    field('singbox-fields', 'singBox.outbound.tls.server_name', 'TLS 服务器名称');
    field('singbox-fields', 'singBox.inbound.listen_port', '本机转发端口（仅回环）', 'number');
    const ca = field('singbox-fields', 'singBox.outbound.tls.certificate', '受信任 CA（可选，公开内容）', 'textarea');
    ca.parentElement.classList.add('wide');
    secretField('singbox-secrets', 'uuid', 'Home 认证 UUID');

    $('frp-title').textContent = '服务注册连接';
    $('frp-note').textContent = '通过上面的加密链路注册家庭服务，家庭标识用于区分服务名称。';
    field('frp-fields', 'frpc.user', '家庭标识');
    field('frp-fields', 'frpc.serverPort', 'Relay 控制端口', 'number');
    field('frp-fields', 'frpc.transport.tls.serverName', '注册连接 TLS 名称');
    tlsField('frp-fields', 'frpc.transport.tls.trustedCaFile', '注册连接 CA 文件');
    secretField('frp-secrets', 'token', '服务注册凭据（与 Relay 一致）');
    $('frp-list-title').textContent = '家庭服务映射';
    $('frp-list-note').textContent = '填写家庭服务的实际地址和端口。中继映射端口须在 Relay 允许的范围内，App 使用服务名称和映射端口连接。';
    $('add-frp-item').textContent = '添加服务';
    for (const proxy of config.frpc.proxies) proxyRow(proxy);
  }
  field('log-fields', 'log.level', '组件日志', 'text', [['error', '错误'], ['warn', '警告'], ['info', '信息']]);

  const m = config.management;
  field('management-fields', 'management.listen', '管理监听 IP');
  field('management-fields', 'management.port', '管理端口', 'number');
  field('management-fields', 'management.https', '启用管理 HTTPS', 'checkbox');
  field('management-fields', 'management.allowedHosts', '允许的访问主机名（逗号分隔，不含端口）', 'text', undefined, m.allowedHosts.join(', '));
  tlsField('management-fields', 'management.certificateFile', '管理 HTTPS 证书', m.certificateFile || '');
  tlsField('management-fields', 'management.keyFile', '管理 HTTPS 私钥', m.keyFile || '');
  if (relay) {
    field('management-fields', 'frontend.listen', '公网 TLS 入口 IP（留空关闭；与 inbound 共用端口，按 SNI 分流）', 'text', undefined, m.frontend?.listen ?? '');
    field('management-fields', 'frontend.port', '公网 TLS 入口端口（须等于 inbound.listen_port）', 'number', undefined, m.frontend?.port ?? config.singBox.inbound.listen_port);
  }
}

function numbers(text) { return parseCSV(text).map(Number); }

function draft() {
  const c = structuredClone(config);
  for (const [key, {input: element, type}] of controls) {
    if (key.startsWith('frontend.')) continue;
    const value = readControl(element, type);
    if (key === 'management.allowedHosts') c.management.allowedHosts = parseCSV(value);
    else if (key === 'management.certificateFile' || key === 'management.keyFile') { if (value) set(c, key, value); else delete c.management[key.split('.')[1]]; }
    else set(c, key, value);
  }
  if (!c.management.https) { delete c.management.certificateFile; delete c.management.keyFile; }
  if (controls.has('frontend.listen')) {
    const listen = readControl(controls.get('frontend.listen').input, 'text');
    if (listen) c.management.frontend = {listen, port: readControl(controls.get('frontend.port').input, 'number')};
    else delete c.management.frontend;
  }
  if (role === 'relay') {
    c.singBox.inbound.users = [...$('users').children].map(r => ({name: rowValues(r).name, uuid: r.dataset.ref}));
    c.singBox.route.rules = [...$('rules').children].map(r => {
      const v = rowValues(r), rule = {auth_user: parseCSV(v.auth_user)};
      if (v.port) rule.port = numbers(v.port);
      if (v.port_range) rule.port_range = parseCSV(v.port_range);
      return rule;
    });
    c.frps.allowPorts = [...$('frp-list').children].map(r => {
      const v = rowValues(r);
      return v.end === '' ? {single: Number(v.start)} : {start: Number(v.start), end: Number(v.end)};
    });
  } else {
    c.frpc.proxies = [...$('frp-list').children].map(r => ({type: 'tcp', ...rowValues(r)}))
      .map(p => ({name: p.name, type: 'tcp', localIP: p.localIP, localPort: p.localPort, remotePort: p.remotePort}));
  }
  return c;
}

function collectSecrets() {
  const values = {};
  for (const [key, {input: element, clear}] of secretControls) {
    if (clear.checked) values[key] = '';
    else if (element.value !== '') values[key] = element.value;
  }
  if (role === 'relay') {
    for (const r of $('users').children) {
      const secret = r.querySelector('[data-secret]');
      if (secret.value !== '') values['uuid:' + rowValues(r).name] = secret.value;
    }
  }
  return values;
}

async function status() {
  const s = await api('status');
  $('status').textContent = `期望修订 ${s.desiredRevision} · 实际生效修订 ${s.appliedRevision ?? '无'} · ${s.savedIsApplied ? '已应用' : '已保存但未生效'}${s.error ? ' · ' + s.error : ''}${s.managementRestartRequired ? ' · 管理入口待本机重启' : ''}`;
  $('components').replaceChildren();
  for (const [name, state] of Object.entries(s.components)) {
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = name + ' · ' + state;
    $('components').append(badge);
  }
}

async function load() {
  try {
    render(await api('config'));
    $('workspace').hidden = false; $('recovery').hidden = true;
    await status();
  } catch (e) {
    $('workspace').hidden = true; $('recovery').hidden = false;
    throw e;
  }
}

async function signedIn(session) {
  csrf = session.csrfToken; role = session.role;
  $('login').hidden = true; $('account').hidden = !session.needsPassword;
  $('workspace').hidden = false; $('logout').hidden = false;
  await load();
}

function signedOut() {
  csrf = '';
  $('workspace').hidden = true; $('recovery').hidden = true; $('account').hidden = true; $('login').hidden = false;
}

$('login-button').addEventListener('click', () => perform(async () => {
  await signedIn(await api('login', {password: $('password').value}));
  $('password').value = '';
  message('已登录。保存只更新本端 JSON，应用才切换运行配置。');
}));
$('password').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); $('login-button').click(); } });

$('password-button').addEventListener('click', () => perform(async () => {
  const result = await api('password', {password: $('new-password').value});
  $('new-password').value = '';
  signedOut();
  message(result.message);
}));

$('logout').addEventListener('click', () => perform(async () => {
  await api('logout', {});
  signedOut();
  $('logout').hidden = true;
  message('已退出。');
}));

$('refresh').addEventListener('click', () => perform(async () => {
  if (confirm('丢弃未保存草稿并重新加载？')) { await load(); message('已重新加载。'); }
}));

$('add-user').addEventListener('click', () => userRow());
$('add-rule').addEventListener('click', () => ruleRow());
$('add-frp-item').addEventListener('click', () => role === 'relay' ? allowRow() : proxyRow());

for (const action of ['validate', 'test']) $(action).addEventListener('click', () => perform(async () => {
  const result = await api(action, {config: draft(), secrets: collectSecrets()});
  message(result.message || `草稿修订 ${result.draftRevision} 字段校验通过；尚未保存或应用，组件检查请使用测试草稿。`);
}));

$('configuration').addEventListener('submit', event => {
  event.preventDefault();
  perform(async () => {
    const result = await api('save', {expectedRevision: config.revision, config: draft(), secrets: collectSecrets()});
    await load();
    message(result.message);
  });
});

$('apply').addEventListener('click', () => perform(async () => {
  if (!confirm('应用已保存配置将重启本端组件，可能中断活动播放。确认继续？')) return;
  try {
    await api('apply', {expectedRevision: config.revision});
    message('本端组件已应用此修订；仍需实际验证其他端和媒体服务。');
  } finally { await status(); }
}));

$('restore').addEventListener('click', () => perform(async () => {
  if (!confirm('将上一份配置恢复为新修订？恢复后还需要应用。')) return;
  const result = await api('restore', {expectedRevision: config.revision});
  await load();
  message(result.message);
}));

$('export').addEventListener('click', () => perform(async () => {
  const result = await api('export');
  const url = URL.createObjectURL(new Blob([JSON.stringify(result.config, null, 2)], {type: 'application/json'}));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = role + '.redacted.json'; anchor.click();
  URL.revokeObjectURL(url);
  message('已导出普通配置和机密引用，不含实际 UUID、token 或私钥。');
}));

$('tls-upload-button').addEventListener('click', () => perform(async () => {
  const file = $('tls-upload').files[0];
  if (!file || file.size > 131072) throw new Error('请选择最多 128 KiB 的 PEM 文件。');
  const draftConfig = draft();
  const result = await api('tls', {kind: $('tls-kind').value, content: await file.text()});
  const metadata = await api('config');
  metadata.config = draftConfig;
  render(metadata);
  message('TLS 文件已导入：' + result.file + '。请选择对应字段，再保存和应用。未保存的机密输入需要重新填写。');
}));

$('recover-button').addEventListener('click', () => perform(async () => {
  const info = await api('recovery');
  if (!confirm('保留无法识别的原文件，并把备份修订 ' + info.backupRevision + ' 保存为新修订？恢复后仍需应用。')) return;
  const result = await api('recover', {fileHash: info.fileHash});
  await load();
  message(result.message);
}));

perform(async () => {
  try { await signedIn(await api('session')); } catch (e) { if (!e.message.includes('登录')) message(e.message, true); }
});
