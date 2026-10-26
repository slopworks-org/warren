// Warren admin UI: a dependency-free single-page app over /api/v1.
// All DOM is built with h(); server data never goes through innerHTML.
'use strict';

const root = document.getElementById('app');
let me = null;
let server = null;
let refreshTimer = null;

// ---------- helpers ----------

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 2600);
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (me && me.csrf && method !== 'GET') opts.headers['X-CSRF-Token'] = me.csrf;
  const r = await fetch('/api/v1' + path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) throw new ApiError(r.status, data && data.error, (data && data.message) || r.statusText);
  return data;
}

// Runs an action, turning API errors into a toast (or a redirect).
async function attempt(fn, errorEl) {
  try {
    return await fn();
  } catch (e) {
    if (e.status === 401 && e.code === 'unauthorized') {
      me = null;
      go('/login');
    } else if (e.code === '2fa_required') {
      go('/profile');
    }
    if (errorEl) errorEl.textContent = e.message;
    else toast(e.message);
    return undefined;
  }
}

function fmtTime(t) {
  return t ? new Date(t * 1000).toLocaleString() : '—';
}

function ago(t) {
  if (!t) return 'never';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - t));
  if (s < 60) return s + ' s ago';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}

function bytes(n) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

function can(perm) {
  return !!me && (me.permissions.includes('*') || me.permissions.includes(perm));
}

function copyButton(text) {
  return h('button', {
    class: 'small', type: 'button', text: 'Copy',
    onclick: async () => { await navigator.clipboard.writeText(text); toast('Copied'); },
  });
}

function codeBlock(text) {
  return h('div', { class: 'copyline' }, h('div', { class: 'code', text }), copyButton(text));
}

function qrImage(svg) {
  return h('div', { class: 'qr' }, h('img', { alt: 'QR code', src: 'data:image/svg+xml;base64,' + btoa(svg) }));
}

function field(label, input, hint) {
  return h('div', {}, h('label', { text: label }), input, hint ? h('div', { class: 'hint', text: hint }) : null);
}

function select(options, value) {
  return h('select', {}, options.map(([v, t]) => h('option', { value: v, text: t, selected: String(v) === String(value) })));
}

// A modal with a form. `build(form)` fills it and returns an async submit
// handler; returning `true` from it closes the dialog.
function modal(title, build, submitText = 'Save') {
  const error = h('div', { class: 'error' });
  const body = h('div');
  const submit = h('button', { class: 'primary', type: 'submit', text: submitText });
  const close = () => { dlg.close(); dlg.remove(); };
  const form = h('form', { method: 'dialog' }, h('h3', { text: title }), body, error,
    h('div', { class: 'buttons' }, h('button', { type: 'button', text: 'Cancel', onclick: close }), submitText ? submit : null));
  const dlg = h('dialog', {}, form);
  const onSubmit = build(body, { error, submit, close });
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!onSubmit) return close();
    error.textContent = '';
    submit.disabled = true;
    try {
      if (await onSubmit()) close();
    } catch (e) {
      error.textContent = e.message;
    } finally {
      submit.disabled = false;
    }
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  return { close, body, submit };
}

function confirmDialog(title, text, action, danger = true) {
  modal(title, (body) => {
    body.append(h('p', { text }));
    return async () => { await action(); return true; };
  }, danger ? 'Confirm' : 'OK');
}

// ---------- routing and layout ----------

function parseHash() {
  const raw = location.hash.replace(/^#/, '') || '/devices';
  const [path, query] = raw.split('?');
  return { path, params: new URLSearchParams(query || '') };
}

function go(path) {
  if (location.hash !== '#' + path) location.hash = path;
  else route();
}

const NAV = [
  ['/devices', 'Devices', null],
  ['/resources', 'Resources', null],
  ['/users', 'Users', 'users.manage'],
  ['/settings', 'Settings', 'settings.manage'],
  ['/audit', 'Audit log', null],
  ['/profile', 'Profile', null],
];

function shell(active, content) {
  const nav = h('nav', { class: 'side' },
    h('div', { class: 'brand' }, h('img', { src: '/icon.svg', alt: '' }), 'Warren'),
    NAV.filter(([, , perm]) => !perm || can(perm)).map(([path, label]) =>
      h('a', { href: '#' + path, class: path === active ? 'active' : null, text: label,
        onclick: () => nav.classList.remove('open') })),
    h('div', { class: 'spacer' }),
    h('div', { class: 'who', text: me.user.username + ' · ' + me.user.role }),
    h('a', { href: '#', text: 'Sign out', onclick: async (e) => {
      e.preventDefault();
      await attempt(() => api('POST', '/auth/logout'));
      me = null;
      go('/login');
    } }));
  const top = h('div', { class: 'topbar' },
    h('div', { class: 'brand' }, h('img', { src: '/icon.svg', alt: '' }), 'Warren'),
    h('button', { class: 'small', text: 'Menu', onclick: () => nav.classList.toggle('open') }));
  const banner = me.must_setup_2fa
    ? h('div', { class: 'notice warn', text: 'The administrator requires two-factor authentication. Set it up below to use Warren.' })
    : null;
  root.replaceChildren(top, h('div', { class: 'layout' }, nav, h('main', {}, banner, updateNotice(), content)));
}

function updateNotice() {
  if (!server || !server.update || !can('settings.manage')) return null;
  return h('div', { class: 'notice' }, 'Warren ' + server.update.version + ' is available; this server runs ' + server.version + '. ',
    h('a', { href: server.update.url, target: '_blank', rel: 'noopener', text: 'Release notes' }));
}

async function loadMe() {
  try {
    me = await api('GET', '/me');
    server = await api('GET', '/server').catch(() => null);
  } catch (_) {
    me = null;
  }
  return me;
}

const PAGES = {
  '/devices': devicesPage,
  '/resources': resourcesPage,
  '/users': usersPage,
  '/settings': settingsPage,
  '/audit': auditPage,
  '/profile': profilePage,
};

async function route() {
  clearInterval(refreshTimer);
  const { path, params } = parseHash();
  if (path === '/login') return loginPage(params);
  if (path === '/setup') return setupPage(params);
  if (path === '/register') return registerPage(params);
  if (!me && !(await loadMe())) return go('/login');
  if (me.must_setup_2fa && path !== '/profile') return go('/profile');
  const page = PAGES[path] || devicesPage;
  const content = h('div');
  shell(PAGES[path] ? path : '/devices', content);
  await page(content, params);
}

// ---------- sign-in pages ----------

function authCard(title, ...children) {
  root.replaceChildren(h('div', { class: 'auth-wrap' }, h('div', { class: 'panel auth' },
    h('div', { class: 'brand' }, h('img', { src: '/icon.svg', alt: '' }), 'Warren'),
    h('h1', { text: title }), ...children)));
}

function safeNext(n) {
  return n && n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n : null;
}

async function afterLogin(params) {
  await loadMe();
  const next = safeNext(params.get('next'));
  if (next) location.href = next;
  else go('/devices');
}

async function loginPage(params) {
  const status = await api('GET', '/auth/status').catch(() => ({}));
  if (status.setup_required) {
    authCard('Welcome', h('p', { class: 'lead', text: 'No administrator exists yet. Use the setup link from the server log, or run `warren-server create-admin <name>` on the server.' }));
    return;
  }
  const error = h('div', { class: 'error' });
  const user = h('input', { autocomplete: 'username', required: true, autofocus: true });
  const pass = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]{6,7}', placeholder: '123 456' });
  const codeField = field('Authentication code', code, 'From your authenticator app.');
  codeField.hidden = true;
  let step = 'password';
  const form = h('form', {}, field('User name', user), field('Password', pass), codeField, error,
    h('div', { class: 'buttons' }, h('button', { class: 'primary', type: 'submit', text: 'Sign in' })));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    error.textContent = '';
    try {
      if (step === 'password') {
        const r = await api('POST', '/auth/login', { username: user.value, password: pass.value });
        if (r.mfa_required) {
          step = 'code';
          codeField.hidden = false;
          code.required = true;
          code.focus();
          return;
        }
      } else {
        await api('POST', '/auth/totp', { code: code.value });
      }
      await afterLogin(params);
    } catch (e) {
      error.textContent = e.message;
    }
  });
  const reg = status.registration === 'invite' ? h('p', { class: 'hint', text: 'Have an invite link? Open it to create your account.' }) : null;
  authCard('Sign in', form, reg);
}

function credentialsForm(submitText, onSubmit) {
  const error = h('div', { class: 'error' });
  const user = h('input', { autocomplete: 'username', required: true, autofocus: true, maxlength: 32 });
  const pass = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const again = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const form = h('form', {}, field('User name', user, 'Letters, digits, dots, dashes, underscores.'),
    field('Password', pass, 'At least 10 characters.'), field('Repeat password', again), error,
    h('div', { class: 'buttons' }, h('button', { class: 'primary', type: 'submit', text: submitText })));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    error.textContent = '';
    if (pass.value !== again.value) { error.textContent = 'The passwords differ.'; return; }
    try { await onSubmit(user.value, pass.value); } catch (e) { error.textContent = e.message; }
  });
  return form;
}

function setupPage(params) {
  authCard('Create the administrator',
    h('p', { class: 'lead', text: 'This account manages users, devices and settings.' }),
    credentialsForm('Create', async (username, password) => {
      await api('POST', '/auth/setup', { token: params.get('token') || '', username, password });
      await api('POST', '/auth/login', { username, password });
      await afterLogin(new URLSearchParams());
    }));
}

function registerPage(params) {
  authCard('Create your account',
    credentialsForm('Create account', async (username, password) => {
      await api('POST', '/auth/register', { invite: params.get('invite') || '', username, password });
      await api('POST', '/auth/login', { username, password });
      await afterLogin(new URLSearchParams());
    }));
}

// ---------- devices ----------

async function usersForPicker() {
  return can('users.manage') ? (await api('GET', '/users')).filter((u) => !u.disabled) : [];
}

function ownerSelect(users) {
  if (!users.length) return null;
  return select(users.map((u) => [u.id, u.username + (u.id === me.user.id ? ' (you)' : '')]), me.user.id);
}

async function devicesPage(el) {
  const list = h('div', { class: 'panel' });
  el.append(h('div', { class: 'head' },
    h('div', {}, h('h1', { text: 'Devices' }), h('p', { class: 'lead', text: 'Machines connected to your Warren network.' })),
    h('button', { class: 'primary', text: 'Add device', onclick: () => addDeviceDialog(load) })), list);

  async function load() {
    const devices = await attempt(() => api('GET', '/devices'));
    if (!devices) return;
    if (!devices.length) {
      list.replaceChildren(h('div', { class: 'empty', text: 'No devices yet. Add one to get started.' }));
      return;
    }
    const showOwner = can('devices.all');
    list.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Device' }), h('th', { text: 'Status' }), h('th', { text: 'Address' }),
        h('th', { class: 'hide-sm', text: 'Last handshake' }), h('th', { class: 'hide-sm', text: 'Traffic' }),
        showOwner ? h('th', { class: 'hide-sm', text: 'Owner' }) : null, h('th'))),
      h('tbody', {}, devices.map((d) => h('tr', {},
        h('td', {}, h('div', { text: d.name }), h('div', { class: 'sub', text: [d.kind === 'agent' ? 'agent' : 'WireGuard config', d.os, d.agent_version && 'v' + d.agent_version].filter(Boolean).join(' · ') })),
        h('td', {}, !d.enabled ? h('span', { class: 'badge warn', text: 'Disabled' })
          : d.online ? h('span', { class: 'badge ok', text: 'Online' }) : h('span', { class: 'badge bad', text: 'Offline' })),
        h('td', { class: 'mono', text: d.address }),
        h('td', { class: 'hide-sm', text: ago(d.last_handshake) }),
        h('td', { class: 'hide-sm', text: d.last_handshake ? '↓ ' + bytes(d.rx_bytes) + '  ↑ ' + bytes(d.tx_bytes) : '—' }),
        showOwner ? h('td', { class: 'hide-sm', text: d.owner }) : null,
        h('td', {}, h('div', { class: 'actions' },
          h('button', { class: 'small', text: 'Rename', onclick: () => renameDevice(d, load) }),
          h('button', { class: 'small', text: d.enabled ? 'Disable' : 'Enable', onclick: async () => {
            await attempt(() => api('PATCH', '/devices/' + d.id, { enabled: !d.enabled }));
            load();
          } }),
          d.kind === 'manual' ? h('button', { class: 'small', text: 'Config', onclick: () => showConfig(d) }) : null,
          h('button', { class: 'small danger', text: 'Revoke', onclick: () => confirmDialog('Revoke ' + d.name + '?',
            'The device is disconnected at once and its resources are deleted. This cannot be undone.', async () => {
              await api('DELETE', '/devices/' + d.id);
              toast('Device revoked');
              load();
            }) })))))))));
  }
  await load();
  refreshTimer = setInterval(load, 10000);
}

function renameDevice(d, reload) {
  modal('Rename device', (body) => {
    const name = h('input', { value: d.name, required: true, maxlength: 64 });
    body.append(field('Name', name));
    return async () => { await api('PATCH', '/devices/' + d.id, { name: name.value }); reload(); return true; };
  });
}

async function showConfig(d) {
  const r = await attempt(() => api('GET', '/devices/' + d.id + '/config'));
  if (!r) return;
  modal('WireGuard config for ' + d.name, (body) => {
    body.append(h('p', { class: 'hint', text: 'The private key is only shown when the device is created. Put the device’s own key in its place.' }), codeBlock(r.config));
    return null;
  }, null);
}

function download(name, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function addDeviceDialog(reload) {
  const users = await attempt(usersForPicker) || [];
  const dlg = modal('Add device', (body, ctl) => {
    let mode = 'agent';
    const tabs = h('div', { class: 'tabs' });
    const pane = h('div');
    const name = h('input', { maxlength: 64, placeholder: 'e.g. home-router' });
    const owner = ownerSelect(users);
    const ttl = select([[15, '15 minutes'], [60, '1 hour'], [1440, '24 hours']], 60);
    const pub = h('input', { class: 'mono', placeholder: 'optional: the device’s public key' });
    const result = h('div');
    function render() {
      tabs.replaceChildren(
        h('button', { type: 'button', class: mode === 'agent' ? 'on' : null, text: 'With the agent', onclick: () => { mode = 'agent'; render(); } }),
        h('button', { type: 'button', class: mode === 'config' ? 'on' : null, text: 'WireGuard config', onclick: () => { mode = 'config'; render(); } }));
      result.replaceChildren();
      ctl.submit.hidden = false;
      if (mode === 'agent') {
        ctl.submit.textContent = 'Create token';
        pane.replaceChildren(
          h('p', { class: 'hint', text: 'Creates a one-time token. Run the shown command on the device; it keeps its private key to itself.' }),
          field('Name (optional)', name, 'Defaults to the device’s host name.'),
          owner ? field('Owner', owner) : null, field('Token valid for', ttl), result);
      } else {
        ctl.submit.textContent = 'Create config';
        pane.replaceChildren(
          h('p', { class: 'hint', text: 'For devices without the agent (phones, laptops with a WireGuard app). The configuration is static.' }),
          field('Name', name), owner ? field('Owner', owner) : null,
          field('Public key', pub, 'Leave empty to generate a key pair; the private key is shown once and never stored.'), result);
      }
    }
    body.append(tabs, pane);
    render();
    return async () => {
      const user_id = owner ? Number(owner.value) : undefined;
      if (mode === 'agent') {
        const r = await api('POST', '/devices/tokens', { name: name.value || null, user_id, ttl_minutes: Number(ttl.value) });
        result.replaceChildren(
          h('label', { text: 'On the device, run' }), codeBlock(r.command),
          h('div', { class: 'hint', text: 'The token works once and expires ' + fmtTime(r.expires_at) + '. Then start the service: on OpenWrt /etc/init.d/warren enable && /etc/init.d/warren start, with systemd systemctl enable --now warren.' }));
      } else {
        if (!name.value.trim()) throw new Error('Give the device a name.');
        const r = await api('POST', '/devices', { name: name.value, public_key: pub.value || null, user_id });
        result.replaceChildren(
          r.private_key_included ? h('div', { class: 'notice warn', text: 'This is the only time the private key is shown. Save the config now.' }) : null,
          r.qr_svg ? qrImage(r.qr_svg) : null, codeBlock(r.config),
          h('button', { type: 'button', text: 'Download .conf', onclick: () => download(r.device.name.replace(/[^\w.-]+/g, '_') + '.conf', r.config) }));
      }
      ctl.submit.hidden = true;
      reload();
      return false;
    };
  });
  return dlg;
}

// ---------- resources ----------

const ACCESS = [['public', 'Public — anyone'], ['users', 'Warren users'], ['basic', 'Basic auth'], ['pin', 'PIN code']];

function accessBadge(r) {
  const label = { public: 'Public', users: 'Users', basic: 'Basic auth', pin: 'PIN' }[r.access];
  return h('span', { class: 'badge plain', text: label });
}

async function resourcesPage(el) {
  const list = h('div', { class: 'panel' });
  el.append(h('div', { class: 'head' },
    h('div', {}, h('h1', { text: 'Resources' }), h('p', { class: 'lead', text: 'Services on your devices, published over HTTPS.' })),
    h('button', { class: 'primary', text: 'Publish service', onclick: () => resourceDialog(null, load) })), list);

  async function load() {
    const items = await attempt(() => api('GET', '/resources'));
    if (!items) return;
    if (!items.length) {
      list.replaceChildren(h('div', { class: 'empty', text: 'Nothing published yet.' }));
      return;
    }
    list.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Address' }), h('th', { text: 'Target' }), h('th', { text: 'Access' }),
        can('resources.all') ? h('th', { class: 'hide-sm', text: 'Owner' }) : null, h('th'))),
      h('tbody', {}, items.map((r) => h('tr', {},
        h('td', {}, h('a', { href: r.url, target: '_blank', rel: 'noopener', text: r.host }),
          r.enabled ? null : h('div', { class: 'sub', text: 'disabled' })),
        h('td', {}, h('div', {}, (r.device_name || '?') + ' : ' + r.target_port),
          h('div', { class: 'sub' }, r.target_scheme.toUpperCase() + ' · ', r.device_online ? 'device online' : 'device offline')),
        h('td', {}, accessBadge(r)),
        can('resources.all') ? h('td', { class: 'hide-sm', text: r.owner }) : null,
        h('td', {}, h('div', { class: 'actions' },
          h('button', { class: 'small', text: 'Edit', onclick: () => resourceDialog(r, load) }),
          h('button', { class: 'small', text: r.enabled ? 'Disable' : 'Enable', onclick: async () => {
            await attempt(() => api('PATCH', '/resources/' + r.id, { enabled: !r.enabled }));
            load();
          } }),
          h('button', { class: 'small danger', text: 'Delete', onclick: () => confirmDialog('Delete ' + r.host + '?',
            'The address stops working immediately.', async () => { await api('DELETE', '/resources/' + r.id); load(); }) })))))))));
  }
  await load();
  refreshTimer = setInterval(load, 15000);
}

async function resourceDialog(res, reload) {
  const devices = await attempt(() => api('GET', '/devices'));
  if (!devices) return;
  if (!devices.length) { toast('Add a device first.'); return; }
  const roles = await attempt(() => api('GET', '/roles')) || [];
  const users = await attempt(usersForPicker) || [];
  modal(res ? 'Edit ' + res.host : 'Publish a service', (body) => {
    const domain = server ? server.domain : '';
    const host = h('input', { required: true, value: res ? res.host : '', placeholder: 'app' });
    const device = select(devices.map((d) => [d.id, d.name + ' (' + d.address + ')' + (can('devices.all') && d.owner !== me.user.username ? ' — ' + d.owner : '')]), res ? res.device_id : devices[0].id);
    const port = h('input', { type: 'number', min: 1, max: 65535, required: true, value: res ? res.target_port : '' });
    const scheme = select([['http', 'HTTP'], ['https', 'HTTPS (certificate not checked)']], res ? res.target_scheme : 'http');
    const access = select(ACCESS, res ? res.access : 'public');
    const basicUser = h('input', { value: res ? res.basic_user : '', autocomplete: 'off' });
    const secret = h('input', { type: 'password', autocomplete: 'new-password' });
    const enabled = h('input', { type: 'checkbox', checked: res ? res.enabled : true });
    const grants = new Set(res ? res.grants : []);
    const grantBox = (subject, label) => h('label', { class: 'check' },
      h('input', { type: 'checkbox', checked: grants.has(subject), onchange: (e) => (e.target.checked ? grants.add(subject) : grants.delete(subject)) }), label);
    const modePane = h('div');
    function renderMode() {
      const m = access.value;
      const keep = res && res.access === m ? 'Leave empty to keep the current one.' : null;
      if (m === 'basic') modePane.replaceChildren(field('User name', basicUser), field('Password', secret, keep || 'At least 8 characters.'));
      else if (m === 'pin') modePane.replaceChildren(field('PIN', secret, keep || '4 to 64 characters.'));
      else if (m === 'users') {
        modePane.replaceChildren(h('label', { text: 'Who may open it' }),
          h('div', { class: 'hint', text: 'The owner and administrators always can.' }),
          grantBox('all', 'Every signed-in user'),
          ...roles.map((r) => grantBox('role:' + r.id, 'Role: ' + r.name)),
          ...users.filter((u) => u.id !== me.user.id).map((u) => grantBox('user:' + u.id, 'User: ' + u.username)));
      } else modePane.replaceChildren(h('div', { class: 'hint', text: 'Anyone with the address can open it.' }));
    }
    access.addEventListener('change', renderMode);
    renderMode();
    body.append(
      field('Address', host, 'A name like “app” becomes app.' + domain + '; a full domain must point to this server.'),
      field('Device', device), h('div', { class: 'row' }, field('Port', port), field('Protocol on the device', scheme)),
      field('Access', access), modePane, h('label', { class: 'check' }, enabled, 'Enabled'));
    return async () => {
      const payload = {
        host: host.value, device_id: Number(device.value), port: Number(port.value), scheme: scheme.value,
        access: access.value, basic_user: basicUser.value, grants: [...grants], enabled: enabled.checked,
      };
      if (secret.value) payload.secret = secret.value;
      if (res) await api('PATCH', '/resources/' + res.id, payload);
      else await api('POST', '/resources', payload);
      toast(res ? 'Saved' : 'Published');
      reload();
      return true;
    };
  });
}

// ---------- users ----------

async function usersPage(el) {
  const list = h('div', { class: 'panel' });
  const invites = h('div', { class: 'panel' });
  el.append(h('div', { class: 'head' },
    h('div', {}, h('h1', { text: 'Users' }), h('p', { class: 'lead', text: 'Accounts and their roles.' })),
    h('button', { class: 'primary', text: 'Add user', onclick: () => createUser() })), list,
  h('div', { class: 'head' }, h('h2', { text: 'Invites' }), h('button', { text: 'Create invite', onclick: () => createInvite() })), invites);
  let roles = [];

  async function load() {
    roles = await attempt(() => api('GET', '/roles')) || [];
    const users = await attempt(() => api('GET', '/users'));
    if (!users) return;
    list.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'User' }), h('th', { text: 'Role' }), h('th', { text: 'Status' }), h('th', { class: 'hide-sm', text: 'Created' }), h('th'))),
      h('tbody', {}, users.map((u) => h('tr', {},
        h('td', { text: u.username + (u.id === me.user.id ? ' (you)' : '') }),
        h('td', { text: (roles.find((r) => r.id === u.role) || { name: u.role }).name }),
        h('td', {}, u.disabled ? h('span', { class: 'badge bad', text: 'Blocked' }) : h('span', { class: 'badge ok', text: 'Active' }),
          u.totp_enabled ? h('span', { class: 'badge plain', text: '2FA' }) : null),
        h('td', { class: 'hide-sm', text: fmtTime(u.created_at) }),
        h('td', {}, u.id === me.user.id ? null : h('div', { class: 'actions' },
          h('button', { class: 'small', text: 'Role', onclick: () => changeRole(u) }),
          h('button', { class: 'small', text: u.disabled ? 'Unblock' : 'Block', onclick: async () => {
            await attempt(() => api('PATCH', '/users/' + u.id, { disabled: !u.disabled }));
            load();
          } }),
          h('button', { class: 'small', text: 'Reset password', onclick: () => resetPassword(u) }),
          h('button', { class: 'small danger', text: 'Delete', onclick: () => confirmDialog('Delete ' + u.username + '?',
            'Their devices and resources are deleted too.', async () => { await api('DELETE', '/users/' + u.id); load(); }) })))))))));
    const inv = await attempt(() => api('GET', '/invites')) || [];
    invites.replaceChildren(inv.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Role' }), h('th', { text: 'Expires' }), h('th', { text: 'Status' }), h('th'))),
      h('tbody', {}, inv.map((i) => h('tr', {},
        h('td', { text: i.role }), h('td', { text: fmtTime(i.expires_at) }),
        h('td', { text: i.used_by ? 'used' : i.expires_at < Date.now() / 1000 ? 'expired' : 'open' }),
        h('td', {}, h('div', { class: 'actions' }, h('button', { class: 'small danger', text: 'Delete', onclick: async () => {
          await attempt(() => api('DELETE', '/invites/' + i.id));
          load();
        } })))))))) : h('div', { class: 'empty', text: 'No invites. Invites work when registration is set to “invite” in Settings.' }));
  }

  function roleSelect(value) {
    return select(roles.map((r) => [r.id, r.name]), value);
  }

  function createUser() {
    modal('Add user', (body) => {
      const name = h('input', { required: true, maxlength: 32 });
      const role = roleSelect('user');
      const pass = h('input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
      const result = h('div');
      body.append(field('User name', name), field('Role', role), field('Password', pass, 'Leave empty to generate one.'), result);
      return async () => {
        const r = await api('POST', '/users', { username: name.value, role: role.value, password: pass.value || null });
        load();
        if (r.password) {
          result.replaceChildren(h('label', { text: 'Generated password (shown once)' }), codeBlock(r.password));
          return false;
        }
        return true;
      };
    });
  }

  function changeRole(u) {
    modal('Role of ' + u.username, (body) => {
      const role = roleSelect(u.role);
      body.append(field('Role', role));
      return async () => { await api('PATCH', '/users/' + u.id, { role: role.value }); load(); return true; };
    });
  }

  function resetPassword(u) {
    modal('Reset password of ' + u.username, (body) => {
      const pass = h('input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
      const twofa = h('input', { type: 'checkbox' });
      const result = h('div');
      body.append(field('New password', pass, 'Leave empty to generate one. All their sessions end.'),
        h('label', { class: 'check' }, twofa, 'Also remove two-factor authentication'), result);
      return async () => {
        const r = await api('POST', '/users/' + u.id + '/password', { password: pass.value || null, reset_2fa: twofa.checked });
        load();
        if (r.password) {
          result.replaceChildren(h('label', { text: 'New password (shown once)' }), codeBlock(r.password));
          return false;
        }
        toast('Password changed');
        return true;
      };
    });
  }

  function createInvite() {
    modal('Create invite', (body) => {
      const role = roleSelect('user');
      const ttl = select([[24, '1 day'], [72, '3 days'], [168, '7 days']], 72);
      const result = h('div');
      body.append(field('Role', role), field('Valid for', ttl), result);
      return async () => {
        const r = await api('POST', '/invites', { role: role.value, ttl_hours: Number(ttl.value) });
        result.replaceChildren(h('label', { text: 'Invite link (shown once)' }), codeBlock(r.url));
        load();
        return false;
      };
    }, 'Create');
  }

  await load();
}

// ---------- settings ----------

async function settingsPage(el) {
  const s = await attempt(() => api('GET', '/settings'));
  if (!s) return;
  const registration = select([['closed', 'Closed — administrators create accounts'], ['invite', 'By invite link']], s.registration);
  const require2fa = h('input', { type: 'checkbox', checked: s.require_2fa });
  const sessionTtl = h('input', { type: 'number', min: 1, max: 2160, value: s.session_ttl_hours });
  const tokenTtl = h('input', { type: 'number', min: 5, max: 1440, value: s.token_ttl_minutes });
  const form = h('form', { class: 'panel pad' },
    field('Registration', registration),
    h('label', { class: 'check' }, require2fa, 'Require two-factor authentication for everyone'),
    h('div', { class: 'row' }, field('Session lifetime (hours)', sessionTtl), field('Device token lifetime (minutes)', tokenTtl)),
    h('div', { class: 'buttons' }, h('button', { class: 'primary', type: 'submit', text: 'Save settings' })));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const saved = await attempt(() => api('PUT', '/settings', {
      registration: registration.value, require_2fa: require2fa.checked,
      session_ttl_hours: Number(sessionTtl.value), token_ttl_minutes: Number(tokenTtl.value),
    }));
    if (saved) { toast('Settings saved'); await loadMe(); }
  });

  const acl = h('div', { class: 'panel' });
  const info = server ? h('div', { class: 'panel pad' }, h('dl', { class: 'kv' },
    [['Version', server.version + (server.update ? ' (' + server.update.version + ' is available)' : '')], ['Admin URL', server.admin_url], ['Resource domain', '*.' + server.domain],
      ['WireGuard endpoint', server.wg_endpoint], ['Tunnel network', server.network + ' (server ' + server.server_ip + ')'],
      ['Server public key', server.public_key], ['Tunnel backend', server.backend], ['TLS', server.tls_mode]]
      .map(([k, v]) => [h('dt', { text: k }), h('dd', { class: k.includes('key') ? 'mono' : null, text: v })]))) : null;

  el.append(h('h1', { text: 'Settings' }), h('p', { class: 'lead', text: 'Server-wide policies.' }), form,
    h('div', { class: 'head' }, h('h2', { text: 'Device access rules' }), h('button', { text: 'Add rule', onclick: () => addRule() })),
    h('p', { class: 'hint', text: 'Devices of the same user always reach each other. These rules let other devices open connections; replies are allowed automatically.' }),
    acl, h('h2', { text: 'Server' }), info);

  let devices = [];
  let users = [];
  const subjectName = (s) => {
    if (s === 'any') return 'any device';
    const [kind, id] = s.split(':');
    if (kind === 'user') return 'devices of ' + ((users.find((u) => String(u.id) === id) || {}).username || 'user #' + id);
    return (devices.find((d) => String(d.id) === id) || {}).name || 'device #' + id;
  };

  async function load() {
    devices = await attempt(() => api('GET', '/devices')) || [];
    users = await attempt(() => api('GET', '/users')) || [];
    const rules = await attempt(() => api('GET', '/acl')) || [];
    acl.replaceChildren(rules.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'From' }), h('th', { text: 'To' }), h('th', { text: 'Ports' }), h('th', { class: 'hide-sm', text: 'Note' }), h('th'))),
      h('tbody', {}, rules.map((r) => h('tr', {},
        h('td', { text: subjectName(r.src) }), h('td', { text: subjectName(r.dst) }),
        h('td', { class: 'mono', text: r.ports || 'all traffic' }), h('td', { class: 'hide-sm', text: r.description }),
        h('td', {}, h('div', { class: 'actions' }, h('button', { class: 'small danger', text: 'Delete', onclick: async () => {
          await attempt(() => api('DELETE', '/acl/' + r.id));
          load();
        } })))))))) : h('div', { class: 'empty', text: 'No extra rules.' }));
  }

  function subjects() {
    return [['any', 'Any device'], ...users.map((u) => ['user:' + u.id, 'Devices of ' + u.username]),
      ...devices.map((d) => ['device:' + d.id, 'Device ' + d.name + ' (' + d.address + ')'])];
  }

  function addRule() {
    modal('Add access rule', (body) => {
      const src = select(subjects(), 'any');
      const dst = select(subjects(), 'any');
      const ports = h('input', { class: 'mono', placeholder: 'tcp:22, udp:53, any:8000-8100' });
      const note = h('input', { maxlength: 200 });
      body.append(field('From', src), field('To', dst), field('Ports', ports, 'Leave empty to allow all traffic.'), field('Note', note));
      return async () => {
        await api('POST', '/acl', { src: src.value, dst: dst.value, ports: ports.value, description: note.value });
        load();
        return true;
      };
    }, 'Add');
  }

  await load();
}

// ---------- profile ----------

async function profilePage(el) {
  const twofa = h('div', { class: 'panel pad' });
  const sessions = h('div', { class: 'panel' });
  const tokens = h('div', { class: 'panel' });

  const current = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const pwError = h('div', { class: 'error' });
  const pwForm = h('form', { class: 'panel pad' }, h('div', { class: 'row' }, field('Current password', current), field('New password', next, 'At least 10 characters.')),
    pwError, h('div', { class: 'buttons' }, h('button', { class: 'primary', type: 'submit', text: 'Change password' })));
  pwForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    pwError.textContent = '';
    const r = await attempt(() => api('POST', '/me/password', { current: current.value, new: next.value }), pwError);
    if (r) { toast('Password changed; sign in again'); me = null; go('/login'); }
  });

  el.append(h('h1', { text: 'Profile' }), h('p', { class: 'lead', text: 'Signed in as ' + me.user.username + ' (' + me.user.role + ').' }),
    h('h2', { text: 'Two-factor authentication' }), twofa,
    h('h2', { text: 'Password' }), pwForm,
    h('div', { class: 'head' }, h('h2', { text: 'Sessions' }), h('button', { text: 'Sign out everywhere', onclick: () => confirmDialog('Sign out everywhere?', 'Every session ends, this one included.', async () => {
      await api('POST', '/auth/logout-all'); me = null; go('/login');
    }) })), sessions,
    h('div', { class: 'head' }, h('h2', { text: 'API tokens' }), h('button', { text: 'Create token', onclick: () => createToken() })),
    h('p', { class: 'hint', text: 'Use with “Authorization: Bearer <token>” to call /api/v1 from scripts. Tokens act as you.' }), tokens);

  function render2fa() {
    if (me.user.totp_enabled) {
      twofa.replaceChildren(h('p', {}, h('span', { class: 'badge ok', text: 'On' }), ' Sign-in asks for a code from your authenticator app.'),
        me.require_2fa ? h('div', { class: 'hint', text: 'Required by the administrator.' })
          : h('button', { text: 'Turn off', onclick: () => modal('Turn off two-factor authentication', (body) => {
            const pass = h('input', { type: 'password', autocomplete: 'current-password', required: true });
            body.append(field('Password', pass));
            return async () => { await api('POST', '/me/totp/disable', { password: pass.value }); await loadMe(); render2fa(); return true; };
          }, 'Turn off') }));
      return;
    }
    twofa.replaceChildren(h('p', {}, h('span', { class: 'badge warn', text: 'Off' }), ' Protect your account with an authenticator app.'),
      h('button', { class: 'primary', text: 'Set up', onclick: async () => {
        const s = await attempt(() => api('POST', '/me/totp/setup'));
        if (!s) return;
        const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', required: true, placeholder: '123 456' });
        const error = h('div', { class: 'error' });
        const form = h('form', {}, qrImage(s.qr_svg), h('div', { class: 'hint', text: 'Scan with an authenticator app, or enter this key:' }),
          h('div', { class: 'code', text: s.secret }), field('Code from the app', code), error,
          h('div', { class: 'buttons' }, h('button', { class: 'primary', type: 'submit', text: 'Turn on' })));
        form.addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const ok = await attempt(() => api('POST', '/me/totp/enable', { code: code.value }), error);
          if (ok) { toast('Two-factor authentication is on'); await loadMe(); route(); }
        });
        twofa.replaceChildren(form);
        code.focus();
      } }));
  }

  async function loadSessions() {
    const list = await attempt(() => api('GET', '/me/sessions')) || [];
    sessions.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Device' }), h('th', { class: 'hide-sm', text: 'Address' }), h('th', { text: 'Started' }), h('th'))),
      h('tbody', {}, list.map((s) => h('tr', {},
        h('td', {}, h('div', { text: s.user_agent || 'unknown' }), s.current ? h('div', { class: 'sub', text: 'this session' }) : null),
        h('td', { class: 'hide-sm mono', text: s.ip }), h('td', { text: fmtTime(s.created_at) }),
        h('td', {}, s.current ? null : h('div', { class: 'actions' }, h('button', { class: 'small danger', text: 'End', onclick: async () => {
          await attempt(() => api('DELETE', '/me/sessions/' + s.id));
          loadSessions();
        } })))))))));
  }

  async function loadTokens() {
    const list = await attempt(() => api('GET', '/me/tokens')) || [];
    tokens.replaceChildren(list.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Name' }), h('th', { text: 'Created' }), h('th', { class: 'hide-sm', text: 'Last used' }), h('th'))),
      h('tbody', {}, list.map((t) => h('tr', {},
        h('td', { text: t.name }), h('td', { text: fmtTime(t.created_at) }), h('td', { class: 'hide-sm', text: ago(t.last_used_at) }),
        h('td', {}, h('div', { class: 'actions' }, h('button', { class: 'small danger', text: 'Delete', onclick: async () => {
          await attempt(() => api('DELETE', '/me/tokens/' + t.id));
          loadTokens();
        } })))))))) : h('div', { class: 'empty', text: 'No API tokens.' }));
  }

  function createToken() {
    modal('Create API token', (body) => {
      const name = h('input', { required: true, maxlength: 64, placeholder: 'e.g. backup script' });
      const result = h('div');
      body.append(field('Name', name), result);
      return async () => {
        const r = await api('POST', '/me/tokens', { name: name.value });
        result.replaceChildren(h('label', { text: 'Token (shown once)' }), codeBlock(r.secret));
        loadTokens();
        return false;
      };
    }, 'Create');
  }

  render2fa();
  if (!me.must_setup_2fa) {
    await Promise.all([loadSessions(), loadTokens()]);
  }
}

// ---------- audit ----------

async function auditPage(el) {
  const body = h('tbody');
  const more = h('button', { text: 'Load more' });
  el.append(h('h1', { text: 'Audit log' }),
    h('p', { class: 'lead', text: can('audit.all') ? 'Everything that happened on this server.' : 'Your own actions.' }),
    h('div', { class: 'panel' }, h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', { text: 'Time' }), h('th', { text: 'Who' }), h('th', { text: 'Action' }), h('th', { text: 'Object' }), h('th', { class: 'hide-sm', text: 'Details' }), h('th', { class: 'hide-sm', text: 'IP' }))),
      body))), h('div', { class: 'buttons' }, more));
  let before = null;
  async function load() {
    const q = '/audit?limit=100' + (before ? '&before=' + before : '');
    const entries = await attempt(() => api('GET', q)) || [];
    body.append(...entries.map((e) => h('tr', {},
      h('td', { text: fmtTime(e.ts) }), h('td', { text: e.actor }), h('td', { class: 'mono', text: e.action }),
      h('td', { text: e.target }), h('td', { class: 'hide-sm', text: e.details }), h('td', { class: 'hide-sm mono', text: e.ip }))));
    if (entries.length) before = entries[entries.length - 1].id;
    more.hidden = entries.length < 100;
  }
  more.addEventListener('click', load);
  await load();
}

window.addEventListener('hashchange', route);
route();
