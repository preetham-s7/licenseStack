let session = localStorage.getItem('license_platform_session') || '';
const out = document.getElementById('out');
const value = (id) => document.getElementById(id).value.trim();
const text = (id, content) => { document.getElementById(id).textContent = content; };

async function api(path, options = {}) {
  options.headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
  if (session) options.headers.Authorization = `Bearer ${session}`;
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message || 'Request failed');
  return data;
}

function show(valueToShow) { out.textContent = JSON.stringify(valueToShow, null, 2); }

async function register() {
  try {
    const data = await api('/v1/auth/register', { method: 'POST', body: JSON.stringify({ name: value('name'), email: value('email'), password: document.getElementById('password').value }) });
    session = data.session_token;
    localStorage.setItem('license_platform_session', session);
    await openWorkspace();
  } catch (error) { show({ error: error.message }); }
}

async function login() {
  try {
    const data = await api('/v1/auth/login', { method: 'POST', body: JSON.stringify({ email: value('email'), password: document.getElementById('password').value }) });
    session = data.session_token;
    localStorage.setItem('license_platform_session', session);
    await openWorkspace();
  } catch (error) { show({ error: error.message }); }
}

async function openWorkspace() {
  document.getElementById('auth').hidden = true;
  document.getElementById('workspace').hidden = false;
  const me = await api('/v1/me');
  text('who', me.developer.email);
  await loadApps();
  await loadLicenses();
}

async function logout() {
  try { await api('/v1/auth/logout', { method: 'POST', body: '{}' }); }
  finally { session = ''; localStorage.removeItem('license_platform_session'); location.reload(); }
}

async function loadApps() {
  try { show(await api('/v1/developer/apps')); }
  catch (error) { show({ error: error.message }); }
}

async function registerApp() {
  try { show(await api('/v1/developer/apps', { method: 'POST', body: JSON.stringify({ app_id: value('appId'), name: value('appName') }) })); await loadApps(); }
  catch (error) { show({ error: error.message }); }
}

async function createLicense() {
  try {
    const body = { app_id: value('licenseAppId') };
    const expires = value('expiry');
    if (expires) body.expires_at = expires;
    show(await api('/v1/developer/licenses', { method: 'POST', body: JSON.stringify(body) }));
    await loadLicenses();
  } catch (error) { show({ error: error.message }); }
}

async function loadLicenses() {
  try {
    const appId = value('licenseAppId');
    const query = appId ? `?app_id=${encodeURIComponent(appId)}` : '';
    text('licensesOut', JSON.stringify(await api(`/v1/developer/licenses${query}`), null, 2));
  } catch (error) { text('licensesOut', JSON.stringify({ error: error.message }, null, 2)); }
}

async function rotateKey() {
  try { show(await api(`/v1/developer/apps/${encodeURIComponent(value('controlAppId'))}/rotate-key`, { method: 'POST', body: '{}' })); }
  catch (error) { show({ error: error.message }); }
}

async function revokeApp() {
  if (!confirm('Revoke this application and its API key?')) return;
  try { show(await api(`/v1/developer/apps/${encodeURIComponent(value('controlAppId'))}/revoke`, { method: 'POST', body: '{}' })); await loadApps(); }
  catch (error) { show({ error: error.message }); }
}

if (session) openWorkspace().catch(() => { session = ''; localStorage.removeItem('license_platform_session'); });
