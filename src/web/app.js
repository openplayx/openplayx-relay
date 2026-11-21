'use strict';
// Strings live in i18n/<locale>/ui.json (served as /i18n.js for ui/opx-i18n.js).
const t = (key, vars) => opxI18n.t(key, vars);
const $ = id => document.getElementById(id);
let csrf = '', role = '', config = null, tlsFiles = [], busy = false;
const controls = new Map(), secretControls = new Map();

function message(text, error = false) { opxI18n.mark($('notice'), null); $('notice').textContent = text; $('notice').dataset.error = String(error); }
// note shows a localized notice that follows language switches.
function note(key, vars, error = false) { message('', error); opxI18n.mark($('notice'), key, vars); }

async function api(path, body) {
  const response = await fetch('/api/' + path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: body === undefined ? {'Accept-Language': opxI18n.locale()} : {'Accept-Language': opxI18n.locale(), 'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) { $('workspace').hidden = true; $('login').hidden = false; }
    const failure = new Error(data.message || t('error.generic'));
    failure.status = response.status;
    throw failure;
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
  const options = [['', t('tls.choose')], ...tlsFiles.map(n => [n, n])];
  if (value && !tlsFiles.includes(value)) options.push([value, t('tls.unavailable', {file: value})]);
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
    button.textContent = t('secret.generateUUID');
    button.addEventListener('click', () => { element.type = 'text'; element.value = randomUUID(); });
    wrap.append(button);
  }
  return {wrap, element};
}

// secretField is a fixed credential (Connector uuid, frp token).
function secretField(parent, key, label, generate = false) {
  const wrap = document.createElement('div');
  const title = document.createElement('label');
  title.textContent = label;
  const {wrap: inner, element} = secretInput(t('secret.keep'), generate);
  title.append(inner);
  const clearLabel = document.createElement('label');
  const clear = document.createElement('input');
  clear.type = 'checkbox';
  clearLabel.append(clear, document.createTextNode(t('secret.clear')));
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
  remove.textContent = t('common.remove');
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
  const element = row('users', [['name', t('field.identityName'), 'text']], user, (container, fields) => {
    const label = document.createElement('label');
    label.textContent = t('field.authUUID');
    const {wrap, element: secret} = secretInput(user.uuid ? t('secret.keepUUID') : t('secret.newUUID'), true);
    secret.dataset.secret = 'uuid';
    label.append(wrap);
    fields.append(label);
  });
  element.dataset.ref = user.uuid || '';
}

function ruleRow(rule = {auth_user: [], port: [18096]}) {
  row('rules', [['auth_user', t('field.identityName'), 'text'], ['port', t('field.port'), 'text'], ['port_range', t('field.portRange'), 'text']],
    {auth_user: csv(rule.auth_user), port: csv(rule.port), port_range: csv(rule.port_range)});
}

function allowRow(entry = {single: 18096}) {
  row('frp-list', [['start', t('field.startPort'), 'number'], ['end', t('field.endPort'), 'text']],
    {start: entry.single ?? entry.start, end: entry.single === undefined ? entry.end : ''});
}

function proxyRow(proxy = {name: '', type: 'tcp', localIP: '192.168.1.10', localPort: 8096, remotePort: 18096}) {
  row('frp-list', [['name', t('field.serviceName'), 'text'], ['localIP', t('field.homeIP'), 'text'], ['localPort', t('field.homePort'), 'number'], ['remotePort', t('field.relayPort'), 'number']], proxy);
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
    ? t('overview.relayFlow')
    : t('overview.homeFlow');
  $('services-note').textContent = relay
    ? t('overview.relayServices')
    : t('overview.homeServices');
  $('management-note').textContent = relay
    ? t('overview.relayManagement')
    : t('overview.homeManagement');
  if (relay) {
    const inbound = config.singBox.inbound;
    const frontend = config.management.frontend;
    summaryItem(transport, t('overview.entry'), `${frontend?.listen || inbound.listen}:${frontend?.port || inbound.listen_port}`);
    summaryItem(transport, t('field.tlsServerName'), inbound.tls.server_name);
    summaryItem(transport, t('overview.identities'), inbound.users.map(u => u.name).join(t('list.sep')) || t('common.notConfigured'));
    summaryItem(transport, t('overview.registration'), `127.0.0.1:${config.frps.bindPort}`);
    const summary = document.createElement('dl'); summary.className = 'summary-grid';
    summaryItem(summary, t('overview.allowedPorts'), config.frps.allowPorts.map(p => p.single ?? `${p.start}–${p.end}`).join(t('list.sep')) || t('common.none'));
    for (const rule of config.singBox.route.rules) {
      summaryItem(summary, rule.auth_user.join(t('list.sep')), [...(rule.port || []), ...(rule.port_range || [])].join(t('list.sep')) || t('overview.noPorts'));
    }
    services.append(summary);
  } else {
    const out = config.singBox.outbound;
    summaryItem(transport, 'Relay', `${out.server}:${out.server_port}`);
    summaryItem(transport, t('field.tlsServerName'), out.tls.server_name);
    summaryItem(transport, t('field.homeId'), config.frpc.user || t('common.notSet'));
    summaryItem(transport, t('overview.credential'), t('overview.credentialSet'));
    if (!config.frpc.proxies.length) {
      const empty = document.createElement('p'); empty.textContent = t('overview.noServices'); services.append(empty);
    }
    for (const proxy of config.frpc.proxies) {
      const summary = document.createElement('dl'); summary.className = 'summary-grid service-summary';
      summaryItem(summary, t('field.serviceName'), proxy.name);
      summaryItem(summary, t('overview.homeAddress'), `${proxy.localIP}:${proxy.localPort}`);
      summaryItem(summary, t('field.relayPort'), proxy.remotePort);
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
  $('title').textContent = relay ? t('title.relay') : t('title.home');
  document.title = 'OpenPlayX · ' + $('title').textContent;
  $('users-block').hidden = $('rules-block').hidden = !relay;

  if (relay) {
    $('singbox-note').textContent = t('relay.singboxNote');
    field('singbox-fields', 'singBox.inbound.listen', t('field.listen'));
    field('singbox-fields', 'singBox.inbound.listen_port', t('field.encryptedPort'), 'number');
    field('singbox-fields', 'singBox.inbound.tls.server_name', t('field.tlsServerName'));
    tlsField('singbox-fields', 'singBox.inbound.tls.certificate_path', t('field.serverCert'));
    tlsField('singbox-fields', 'singBox.inbound.tls.key_path', t('field.serverKey'));
    for (const user of config.singBox.inbound.users) userRow(user);
    for (const rule of config.singBox.route.rules) ruleRow(rule);

    $('frp-title').textContent = t('overview.registration');
    $('frp-note').textContent = t('relay.frpNote');
    field('frp-fields', 'frps.bindPort', t('field.registrationPort'), 'number');
    tlsField('frp-fields', 'frps.transport.tls.certFile', t('field.registrationCert'));
    tlsField('frp-fields', 'frps.transport.tls.keyFile', t('field.registrationKey'));
    secretField('frp-secrets', 'token', t('field.tokenRelay'));
    $('frp-list-title').textContent = t('relay.allowTitle');
    $('frp-list-note').textContent = t('relay.allowNote');
    $('add-frp-item').textContent = t('relay.addRange');
    for (const entry of config.frps.allowPorts) allowRow(entry);
  } else {
    $('singbox-note').textContent = t('home.singboxNote');
    field('singbox-fields', 'singBox.outbound.server', t('field.relayAddress'));
    field('singbox-fields', 'singBox.outbound.server_port', t('field.relayServerPort'), 'number');
    field('singbox-fields', 'singBox.outbound.tls.server_name', t('field.tlsServerName'));
    field('singbox-fields', 'singBox.inbound.listen_port', t('field.localForward'), 'number');
    const ca = field('singbox-fields', 'singBox.outbound.tls.certificate', t('field.trustedCA'), 'textarea');
    ca.parentElement.classList.add('wide');
    secretField('singbox-secrets', 'uuid', t('field.connectorUUID'));

    $('frp-title').textContent = t('home.frpTitle');
    $('frp-note').textContent = t('home.frpNote');
    field('frp-fields', 'frpc.user', t('field.homeId'));
    field('frp-fields', 'frpc.serverPort', t('field.relayControlPort'), 'number');
    field('frp-fields', 'frpc.transport.tls.serverName', t('field.registrationTLSName'));
    tlsField('frp-fields', 'frpc.transport.tls.trustedCaFile', t('field.registrationCA'));
    secretField('frp-secrets', 'token', t('field.tokenHome'));
    $('frp-list-title').textContent = t('home.listTitle');
    $('frp-list-note').textContent = t('home.listNote');
    $('add-frp-item').textContent = t('home.addService');
    for (const proxy of config.frpc.proxies) proxyRow(proxy);
  }
  field('log-fields', 'log.level', t('field.logLevel'), 'text', [['error', t('log.error')], ['warn', t('log.warn')], ['info', t('log.info')]]);

  const m = config.management;
  field('management-fields', 'management.listen', t('field.managementListen'));
  field('management-fields', 'management.port', t('field.managementPort'), 'number');
  field('management-fields', 'management.https', t('field.managementHTTPS'), 'checkbox');
  field('management-fields', 'management.allowedHosts', t('field.allowedHosts'), 'text', undefined, m.allowedHosts.join(', '));
  tlsField('management-fields', 'management.certificateFile', t('field.managementCert'), m.certificateFile || '');
  tlsField('management-fields', 'management.keyFile', t('field.managementKey'), m.keyFile || '');
  if (relay) {
    field('management-fields', 'frontend.listen', t('field.frontendListen'), 'text', undefined, m.frontend?.listen ?? '');
    field('management-fields', 'frontend.port', t('field.frontendPort'), 'number', undefined, m.frontend?.port ?? config.singBox.inbound.listen_port);
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

let lastStatus = null;
async function status() {
  showStatus(await api('status'));
}
function showStatus(s) {
  lastStatus = s;
  $('status').textContent = t('status.line', {desired: s.desiredRevision, applied: s.appliedRevision ?? t('common.none'), state: s.savedIsApplied ? t('status.applied') : t('status.savedNotApplied')}) + (s.error ? ' · ' + s.error : '') + (s.managementRestartRequired ? ' · ' + t('status.restartManager') : '');
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
  note('notice.signedIn');
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
  note('notice.signedOut');
}));

$('refresh').addEventListener('click', () => perform(async () => {
  if (confirm(t('confirm.reload'))) { await load(); note('notice.reloaded'); }
}));

$('add-user').addEventListener('click', () => userRow());
$('add-rule').addEventListener('click', () => ruleRow());
$('add-frp-item').addEventListener('click', () => role === 'relay' ? allowRow() : proxyRow());

for (const action of ['validate', 'test']) $(action).addEventListener('click', () => perform(async () => {
  const result = await api(action, {config: draft(), secrets: collectSecrets()});
  if (result.message) message(result.message); else note('notice.validated', {revision: result.draftRevision});
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
  if (!confirm(t('confirm.apply'))) return;
  try {
    await api('apply', {expectedRevision: config.revision});
    note('notice.applied');
  } finally { await status(); }
}));

$('restore').addEventListener('click', () => perform(async () => {
  if (!confirm(t('confirm.restore'))) return;
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
  note('notice.exported');
}));

$('tls-upload-button').addEventListener('click', () => perform(async () => {
  const file = $('tls-upload').files[0];
  if (!file || file.size > 131072) throw new Error(t('error.pemSize'));
  const draftConfig = draft();
  const result = await api('tls', {kind: $('tls-kind').value, content: await file.text()});
  const metadata = await api('config');
  metadata.config = draftConfig;
  render(metadata);
  note('notice.tlsImported', {file: result.file});
}));

$('recover-button').addEventListener('click', () => perform(async () => {
  const info = await api('recovery');
  if (!confirm(t('confirm.recover', {revision: info.backupRevision}))) return;
  const result = await api('recover', {fileHash: info.fileHash});
  await load();
  message(result.message);
}));

perform(async () => {
  try { await signedIn(await api('session')); } catch (e) { if (e.status !== 401) message(e.message, true); }
});

// Language switch: rebuild the localized form from the current (unsaved) draft, keep typed secrets.
document.addEventListener('opx:langchange', () => {
  document.title = 'OpenPlayX · ' + t(config ? (role === 'relay' ? 'title.relay' : 'title.home') : 'title.default');
  if (!config || $('workspace').hidden) return;
  const secrets = [...secretControls].map(([key, {input: element, clear}]) => [key, element.value, clear.checked]);
  const userSecrets = [...$('users').children].map(r => r.querySelector('[data-secret]')?.value || '');
  const saved = config;
  render({config: draft(), role, tlsFiles});
  config = saved;
  renderOverview();
  for (const [key, value, cleared] of secrets) { const c = secretControls.get(key); if (c) { c.input.value = value; c.clear.checked = cleared; } }
  [...$('users').children].forEach((r, i) => { const secret = r.querySelector('[data-secret]'); if (secret && userSecrets[i]) secret.value = userSecrets[i]; });
  if (lastStatus) showStatus(lastStatus);
});
