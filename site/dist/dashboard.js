'use strict';
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {session: localStorage.getItem('license_platform_session') || '', user: null, apps: [], app: '', customers: [], licenses: [], usage: null, page: 'overview', detail: null, mode: 'login', search: '', status: '', revision: 0};
let dialogSubmit = null;
let toastTimer;
const date = (v) => v ? new Date(v).toLocaleDateString(undefined, {day:'numeric',month:'short',year:'numeric'}) : 'No expiry';
const stamp = (v) => v ? new Date(v).toLocaleString() : 'Not yet';
const initials = (name) => esc(String(name).split(/\s+/).map(s=>s[0]).slice(0,2).join('').toUpperCase());
const currentApp = () => state.apps.find(a => a.app_id === state.app);
const activeApp = () => currentApp()?.status === 'active';
const status = (l) => l.status === 'revoked' ? 'revoked' : l.expires_at && new Date(l.expires_at) <= new Date() ? 'expired' : l.status;
const badge = (s) => `<span class="badge ${esc(s)}">${esc(s === 'unused' ? 'Ready to activate' : s.charAt(0).toUpperCase()+s.slice(1))}</span>`;
const action = (name, text, cls='secondary', extra='') => `<button type="button" class="${cls}" data-action="${name}" ${extra}>${text}</button>`;
const heading = (title, description, buttons='') => `<div class="page-heading"><div><div class="eyebrow">${esc(currentApp()?.name || 'DEVELOPER WORKSPACE')}</div><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="actions">${buttons}</div></div>`;
const post = (path, body) => api(path, {method:'POST',body:JSON.stringify(body)});

async function api(path, options={}) {
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), 15000);
  try {
    const response = await fetch(path, {...options, signal:controller.signal, headers:{'Content-Type':'application/json', ...(state.session ? {Authorization:`Bearer ${state.session}`} : {})}});
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401 && state.user) { clearSession(); showAuth('login'); }
      throw new Error(data.error?.message || 'Request failed. Please try again.');
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The server took too long. Please try again.');
    if (error instanceof TypeError) throw new Error('Cannot reach the local server. Check that it is running.');
    throw error;
  } finally { clearTimeout(timer); }
}
function notify(message) { $('notification').textContent=message; $('notification').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('notification').hidden=true,4500); }
function clearSession() { state.session='';state.user=null;localStorage.removeItem('license_platform_session'); }
function setAccountMenu(open) { $('accountButton').setAttribute('aria-expanded',String(open)); $('accountMenu').hidden=!open; }
function showAuth(mode, message='') {
  state.mode=mode;
  setAccountMenu(false);
  $('accountWrap').hidden=true;
  $('loadingView').hidden=true; $('appView').hidden=true; $('authView').hidden=false;
  $('mobileLogout').hidden=true;
  $('loginTab').setAttribute('aria-selected',String(mode==='login')); $('signupTab').setAttribute('aria-selected',String(mode==='signup'));
  $('nameField').hidden=mode!=='signup'; $('name').required=mode==='signup'; $('password').minLength=mode==='signup'?10:1;
  $('password').autocomplete=mode==='signup'?'new-password':'current-password'; $('passwordHint').hidden=mode!=='signup';
  $('authTitle').textContent=mode==='signup'?'Create your workspace.':'Welcome back.';
  $('authDescription').textContent=mode==='signup'?'Start managing your applications and customer access.':'Sign in to manage your applications and customers.';
  $('authSubmit').textContent=mode==='signup'?'Create account →':'Sign in →';
  $('authSwitch').innerHTML=mode==='signup'?'Already have an account? <button type="button" data-mode="login">Sign in</button>':'New to LicenseStack? <button type="button" data-mode="signup">Create an account</button>';
  $('authError').textContent=message; $('authError').hidden=!message;
  document.title=(mode==='signup'?'Create account':'Sign in')+' — LicenseStack';
  history.replaceState({},'',mode==='signup'?'/signup':'/login');
}
document.addEventListener('click',event=>{
  const mode=event.target.closest('[data-mode]');if(mode)showAuth(mode.dataset.mode);
});
$('authForm').addEventListener('submit', async event=>{
  event.preventDefault();const button=$('authSubmit');button.disabled=true;button.textContent='Please wait…';$('authError').hidden=true;
  try {
    const data=await post('/v1/auth/'+(state.mode==='signup'?'register':'login'),{name:$('name').value.trim(),email:$('email').value.trim(),password:$('password').value});
    state.session=data.session_token;localStorage.setItem('license_platform_session',state.session);$('password').value='';
    history.replaceState({},'','/dashboard#overview');await openWorkspace();
  } catch(error){$('authError').textContent=error.message;$('authError').hidden=false;}
  finally {button.disabled=false;button.textContent=state.mode==='signup'?'Create account →':'Sign in →';}
});
async function openWorkspace() {
  state.user=(await api('/v1/me')).developer;
  $('accountName').textContent=state.user.name;$('accountEmail').textContent=state.user.email;$('accountAvatar').textContent=state.user.name.slice(0,1).toUpperCase();
  $('accountMenuName').textContent=state.user.name;$('accountMenuEmail').textContent=state.user.email;
  state.apps=(await api('/v1/developer/apps')).applications;
  const saved=localStorage.getItem('licensestack-app');state.app=state.apps.find(a=>a.app_id===saved&&a.status==='active')?.app_id || state.apps.find(a=>a.status==='active')?.app_id || '';
  populateApps();
  $('authView').hidden=true;$('loadingView').hidden=true;$('appView').hidden=false;
  $('accountWrap').hidden=false;
  $('mobileLogout').hidden=false;
  if(location.pathname!=='/dashboard')history.replaceState({},'','/dashboard#overview');
  await refreshData();await route();
}
function populateApps() {
  $('appSelect').innerHTML='<option value="">Choose an application</option>'+state.apps.map(a=>`<option value="${esc(a.app_id)}" ${a.app_id===state.app?'selected':''} ${a.status==='revoked'?'disabled':''}>${esc(a.name)}${a.status==='revoked'?' (disabled)':''}</option>`).join('');
  localStorage.setItem('licensestack-app',state.app);
}
async function refreshData() {
  const revision=++state.revision;
  if(!state.app||!activeApp()){state.customers=[];state.licenses=[];state.usage=null;return;}
  const [c,l,u]=await Promise.all([api(`/v1/developer/customers?app_id=${encodeURIComponent(state.app)}`),api(`/v1/developer/licenses?app_id=${encodeURIComponent(state.app)}`),api(`/v1/developer/usage?app_id=${encodeURIComponent(state.app)}`)]);
  if(revision===state.revision){state.customers=c.customers;state.licenses=l.licenses;state.usage=u;}
}
function go(page) { if(location.hash==='#'+page)route();else location.hash=page; }
async function route() {
  if(!state.user)return;
  const parts=location.hash.slice(1).split('/');state.page=['overview','customers','licenses','keys','applications','activity'].includes(parts[0])?parts[0]:'overview';
  state.search='';state.status='';
  document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===state.page));
  $('breadcrumb').textContent=`Workspace / ${state.page==='keys'?'API & integration':state.page.charAt(0).toUpperCase()+state.page.slice(1)}`;
  document.title=$('breadcrumb').textContent.replace('Workspace / ','')+' — LicenseStack';
  if(state.page==='customers'&&parts[1]&&state.app){
    $('pageContent').innerHTML='<div class="loading-state"><span class="spinner"></span>Loading customer…</div>';
    const selectedApp=state.app;
    try{const detail=await api(`/v1/developer/customers/${encodeURIComponent(parts[1])}?app_id=${encodeURIComponent(selectedApp)}`);if(state.app===selectedApp&&location.hash==='#'+parts.join('/')){state.detail=detail;renderCustomer();}}
    catch(e){$('pageContent').innerHTML=heading('Customer unavailable',e.message,action('customers','Back to customers'));}
  } else {state.detail=null;render();}
}
function render() {
  const page=$('pageContent');
  if(state.page==='applications'){renderApplications();return;}
  if(!state.app){page.innerHTML=heading('Your workspace starts here.','Register your application to get an API key and start managing customer access.')+`<section class="panel empty-state"><div class="empty-icon">◈</div><h2>Let’s register your first application.</h2><p>Give your product a name. We’ll create its workspace and an API key so your server can manage customers and licenses.</p>${action('new-app','Register application →','primary')}<p class="field-help" style="margin-top:20px">Then add your first customer and issue their license.</p></section>`;return;}
  if(state.page==='overview')renderOverview();
  if(state.page==='customers')renderCustomers();
  if(state.page==='licenses')renderLicenses();
  if(state.page==='keys')renderKeys();
  if(state.page==='activity')renderActivity();
}
function customerTable(customers) {
  if(!customers.length)return '<div class="empty-state"><div class="empty-icon">♙</div><h2>No customers found.</h2><p>Add your first customer or adjust your search.</p>'+action('new-customer','Add customer','primary')+'</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Customer</th><th>Access</th><th>Licenses</th><th>Last seen</th><th></th></tr></thead><tbody>${customers.map(c=>`<tr><td><button class="customer-link" data-action="customer" data-id="${esc(c.id)}"><span class="person"><span class="person-avatar">${initials(c.name)}</span><span><strong>${esc(c.name)}</strong><small>${esc(c.email)}</small></span></span></button></td><td>${badge(c.access_count?'active':c.license_count?'revoked':'no licenses')}</td><td>${c.license_count}</td><td>${c.last_seen_at?esc(date(c.last_seen_at)):'Not activated'}</td><td>${action('customer','View →','quiet',`data-id="${esc(c.id)}"`)}</td></tr>`).join('')}</tbody></table></div>`;
}
function renderOverview() {
  const live=state.licenses.filter(l=>['active','unused'].includes(status(l))).length;
  $('pageContent').innerHTML=heading(`Hello, ${state.user.name.split(' ')[0]}.`,'Your customer access, all in one place.',action('new-customer','＋ Add customer','primary'))+`<div class="metrics"><div class="metric"><span>Customers</span><strong>${state.customers.length}</strong><small>In this application</small></div><div class="metric"><span>Enabled licenses</span><strong>${live}</strong><small>Ready or active</small></div><div class="metric"><span>Activated devices</span><strong>${state.licenses.filter(l=>status(l)==='active').length}</strong><small>One device per license</small></div><div class="metric"><span>Revoked / expired</span><strong>${state.licenses.length-live}</strong><small>Access unavailable</small></div></div><section class="panel"><div class="panel-heading"><h2>Set up your application</h2><span class="badge">${esc(state.app)}</span></div><div class="onboarding"><div class="step-card"><b>01 · APPLICATION REGISTERED ✓</b><h3>Connect your product</h3><p>Your API key is for your server. Your customers receive separate license keys.</p>${action('keys','Open API & integration →','quiet')}</div><div class="step-card"><b>02 · CUSTOMER PROFILES</b><h3>Add your customers</h3><p>Keep each customer’s identity, licenses, and device activity together.</p>${action('new-customer','Add customer →','quiet')}</div><div class="step-card"><b>03 · CUSTOMER ACCESS</b><h3>Issue the first license</h3><p>Choose a customer, set their plan and expiry, and give them the generated key.</p>${action('new-license','Create license →','quiet')}</div></div></section><section class="panel"><div class="panel-heading"><h2>Customers</h2>${action('customers','View all →','quiet')}</div>${customerTable(state.customers.slice(0,5))}</section>`;
}
function renderActivity() {
  const usage=state.usage||{totals:{},last_30_days:{},recent:[]};
  const total=(name)=>usage.totals[name]||0;
  const recent=usage.recent||[];
  $('pageContent').innerHTML=heading('Activity','Real activation, validation, and access events for this application.')+`<div class="metrics"><div class="metric"><span>Validations</span><strong>${total('validated')}</strong><small>${usage.last_30_days?.validated||0} in the last 30 days</small></div><div class="metric"><span>Activations</span><strong>${total('activated')}</strong><small>${usage.last_30_days?.activated||0} in the last 30 days</small></div><div class="metric"><span>Repeat checks</span><strong>${total('activation_repeated')}</strong><small>Existing devices</small></div><div class="metric"><span>Access changes</span><strong>${total('revoked')+total('reset')+total('restore')}</strong><small>Revokes, resets, and restores</small></div></div><section class="panel"><div class="panel-heading"><h2>Recent activity</h2><span class="count">Last 30 days</span></div>${recent.length?`<div class="table-wrap"><table><thead><tr><th>Event</th><th>License</th><th>Plan</th><th>Time</th><th>IP address</th></tr></thead><tbody>${recent.map(event=>`<tr><td><strong>${esc(event.event_type.replace(/_/g,' '))}</strong></td><td class="mono-value">${esc(event.key_prefix)}••••</td><td>${esc(event.plan||'—')}</td><td>${esc(stamp(event.created_at))}</td><td class="mono-value">${esc(event.ip_address||'—')}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty-state"><div class="empty-icon">◌</div><h2>No activity yet.</h2><p>Activation and validation events will appear here once your customer software connects.</p></div>'}</section>`;
}
function renderCustomers() {
  $('pageContent').innerHTML=heading('Customers','Click a customer to view their licenses, devices, and access history.',action('new-customer','＋ Add customer','primary'))+`<section class="panel"><div class="toolbar"><label class="sr-only" for="customerSearch">Search customers</label><input id="customerSearch" type="search" placeholder="Search by name or email…"><span class="count">${state.customers.length} customers</span></div><div id="customerTable">${customerTable(state.customers)}</div></section>`;
  $('customerSearch').addEventListener('input',event=>{$('customerTable').innerHTML=customerTable(state.customers.filter(c=>(c.name+' '+c.email).toLowerCase().includes(event.target.value.toLowerCase())));});
}
function licenseTable(licenses) {
  if(!licenses.length)return '<div class="empty-state"><div class="empty-icon">◇</div><h2>No licenses found.</h2><p>Create a customer license to grant access to this application.</p>'+action('new-license','Create license','primary')+'</div>';
  return `<div class="table-wrap"><table><thead><tr><th>License</th><th>Customer</th><th>Plan</th><th>Status</th><th>Expiry</th><th></th></tr></thead><tbody>${licenses.map(l=>{const c=state.customers.find(c=>c.id===l.customer_id);return `<tr><td class="mono-value">${esc(l.key_prefix)}••••</td><td>${c?`<button class="customer-link" data-action="customer" data-id="${esc(c.id)}"><strong>${esc(c.name)}</strong></button>`:'Unassigned'}</td><td>${esc(l.plan)}</td><td>${badge(status(l))}</td><td>${l.expires_at?esc(date(l.expires_at)):'No expiry'}</td><td>${action('edit-license','Manage','quiet',`data-id="${esc(l.id)}"`)}</td></tr>`;}).join('')}</tbody></table></div>`;
}
function renderLicenses() {
  $('pageContent').innerHTML=heading('Licenses','Every customer key, its plan, and its current access.',action('new-license','＋ Create license','primary'))+`<section class="panel"><div class="toolbar"><label class="sr-only" for="licenseSearch">Search licenses</label><input id="licenseSearch" type="search" placeholder="Search customer, key, or plan…"><label class="sr-only" for="licenseStatus">Filter status</label><select id="licenseStatus"><option value="">All statuses</option><option value="active">Active</option><option value="unused">Ready to activate</option><option value="revoked">Revoked</option><option value="expired">Expired</option></select><span class="count">${state.licenses.length} licenses</span></div><div id="licenseTable">${licenseTable(state.licenses)}</div></section>`;
  const filter=()=>{const q=$('licenseSearch').value.toLowerCase(),s=$('licenseStatus').value;$('licenseTable').innerHTML=licenseTable(state.licenses.filter(l=>{const c=state.customers.find(c=>c.id===l.customer_id);return (!s||status(l)===s)&&`${l.key_prefix} ${l.plan} ${c?.name||''} ${c?.email||''}`.toLowerCase().includes(q);}));};
  $('licenseSearch').addEventListener('input',filter);$('licenseStatus').addEventListener('change',filter);
}
function renderCustomer() {
  const {customer:c,licenses,events}=state.detail;
  $('pageContent').innerHTML=`<button type="button" class="back-button" data-action="customers">← All customers</button>`+heading(c.name,c.email,action('edit-customer','Edit customer')+action('new-license','＋ Issue license','primary',`data-customer="${esc(c.id)}"`))+`<div class="detail-grid"><aside class="panel"><span class="person-avatar">${initials(c.name)}</span><h2 class="profile-name">${esc(c.name)}</h2><div class="profile-email">${esc(c.email)}</div><div class="profile-field"><small>Customer since</small>${esc(date(c.created_at))}</div><div class="profile-field"><small>Application</small>${esc(currentApp()?.name)}</div><div class="profile-field"><small>Notes</small><p>${esc(c.notes||'No notes yet.')}</p></div><div class="profile-field"><small>Customer ID</small><span class="mono-value">${esc(c.id)}</span></div></aside><div><section class="panel"><div class="panel-heading"><h2>Licenses & access</h2><span class="badge">${licenses.length} licenses</span></div>${licenses.length?licenses.map(l=>`<article class="license-item"><div class="license-title"><h3>${esc(l.key_prefix)}••••</h3>${badge(status(l))}</div><div class="license-meta"><div><small>Plan</small><span>${esc(l.plan)}</span></div><div><small>Expiry</small><span>${esc(date(l.expires_at))}</span></div><div><small>Device</small><span>${esc(l.device_label||'Not activated')}</span></div><div><small>Last seen</small><span>${l.last_seen_at?esc(stamp(l.last_seen_at)):'Not yet'}</span></div><div><small>First activation</small><span>${l.activated_at?esc(date(l.activated_at)):'Not yet'}</span></div></div><div class="actions">${action('edit-license','Change plan / expiry','secondary',`data-id="${esc(l.id)}"`)}${l.status==='revoked'?action('restore-license','Restore access','secondary',`data-id="${esc(l.id)}"`):action('revoke-license','Revoke access','danger',`data-id="${esc(l.id)}"`)}${action('reset-license','Reset device','quiet',`data-id="${esc(l.id)}"`)}</div></article>`).join(''):'<div class="empty-state"><h2>No access issued yet.</h2><p>Create a license for this customer to get started.</p>'+action('new-license','Issue license','primary',`data-customer="${esc(c.id)}"`)+'</div>'}</section><section class="panel"><h2>Access history</h2><div class="timeline">${events.length?events.map(e=>`<div><strong>${esc(e.event_type.replace(/_/g,' '))} · ${esc(e.key_prefix)}••••</strong><small>${esc(stamp(e.created_at))}</small></div>`).join(''):'<p>License creation and activation events will appear here.</p>'}</div></section></div></div>`;
}
function renderKeys() {
  $('pageContent').innerHTML=heading('API & integration','Connect your server to this application’s customers and licenses.')+`<section class="panel"><div class="panel-heading"><h2>Application API key</h2>${badge(currentApp().status)}</div><p>Use this key on your server to manage only this application. The full key is shown when you create or regenerate it.</p><div class="key-box"><code>${esc(currentApp().api_key_prefix)}••••••••••••••••••••••••</code><small class="field-help">Full keys are not stored. Regenerate if you no longer have your key.</small></div><div class="actions">${action('rotate-key','Regenerate API key','primary')}${action('revoke-app','Disable application','danger')}</div></section><section class="panel"><div class="panel-heading"><h2>Connection details</h2><a class="quiet" href="/docs">Full documentation ↗</a></div><div class="license-meta"><div><small>Base URL</small><span class="mono-value">${esc(location.origin)}</span></div><div><small>Application ID</small><span class="mono-value">${esc(state.app)}</span></div><div><small>Authentication header</small><span class="mono-value">X-API-Key: YOUR_API_KEY</span></div></div><p>List your customers from your server:</p><div class="key-box"><pre id="integrationSample"></pre>${action('copy-sample','Copy example')}</div><p>Customer software activates with a customer license key and device ID. Keep your application API key on your server.</p><a class="quiet" href="/docs#quickstart">Activation quickstart →</a></section>`;
  $('integrationSample').textContent=`curl "${location.origin}/v1/customers?app_id=${state.app}" -H "X-API-Key: YOUR_API_KEY"`;
}
function renderApplications() {
  $('pageContent').innerHTML=heading('Applications','Each application has its own API key, customers, and licenses.',action('new-app','＋ Register application','primary'))+`<div class="app-grid">${state.apps.map(a=>`<article class="app-card"><div class="panel-heading"><span class="person-avatar">◈</span>${badge(a.status)}</div><h2>${esc(a.name)}</h2><p class="mono-value">${esc(a.app_id)}</p><p>Created ${esc(date(a.created_at))}</p><div class="actions">${a.status==='active'?action('select-app',a.app_id===state.app?'Current application →':'Open application →','secondary',`data-id="${esc(a.app_id)}"`):'<span class="field-help">Application disabled</span>'}</div></article>`).join('')||'<section class="panel empty-state"><h2>No applications yet.</h2><p>Register your first product to get started.</p>'+action('new-app','Register application','primary')+'</section>'}</div>`;
}
function openDialog(title, body, onSubmit=null, kicker='WORKSPACE') {
  $('dialogTitle').textContent=title;$('dialogKicker').textContent=kicker;
  $('dialogBody').innerHTML=body;dialogSubmit=onSubmit;
  if(!$('editorDialog').open)$('editorDialog').showModal();
  const form=$('dialogBody').querySelector('form');if(form)form.addEventListener('submit',submitDialog);
}
const dialogError = '<div id="dialogError" class="notice error" role="alert" hidden></div>';
const dialogActions = (label) => `<div class="dialog-actions">${action('close','Cancel')}<button class="primary" type="submit">${label}</button></div>`;
async function submitDialog(event) {
  event.preventDefault();const form=event.target;const button=form.querySelector('[type=submit]');button.disabled=true;
  const error=$('dialogError');if(error)error.hidden=true;
  try{await dialogSubmit(new FormData(form));}catch(e){if(error){error.textContent=e.message;error.hidden=false;}else notify(e.message);}
  finally{button.disabled=false;}
}
function closeDialog(){$('editorDialog').close();}
function profileDialog() {
  const user=state.user||{};
  openDialog('Developer profile',`<div class="profile-summary"><span class="person-avatar">${initials(user.name||'Developer')}</span><div><h3>${esc(user.name||'Developer')}</h3><p>${esc(user.email||'')}</p></div></div><div class="profile-details"><div><small>Account type</small><strong>Developer account</strong></div><div><small>Workspace access</small><strong>Applications, customers & licenses</strong></div></div><p class="field-help">Your account controls the applications and customer access records in this workspace.</p>`,null,'ACCOUNT PROFILE');
}
async function sync(){await refreshData();await route();}
function secretDialog(title, secret, description, next='keys') {
  openDialog(title,`<p>${esc(description)}</p><div class="key-box"><code id="issuedSecret"></code>${action('copy-secret','Copy key','primary')}</div><p class="field-help">Save this now. Only a masked prefix is available after closing.</p><div class="dialog-actions">${action('secret-done','Saved — continue →','secondary',`data-next="${next}"`)}</div>`,null,'SAVE YOUR KEY');
  $('issuedSecret').textContent=secret;
}
function newApp() {
  openDialog('Register your application',`<p>Create a workspace and API key for your product.</p><form><label>Application name<input name="name" id="applicationName" placeholder="e.g. Design Studio" maxlength="160" required></label><label>Application ID<input name="app_id" id="applicationSlug" placeholder="design-studio" pattern="[a-z0-9][a-z0-9._-]{0,119}" maxlength="120" required></label><p class="field-help">A unique identifier using lowercase letters, numbers, dots, underscores, or hyphens.</p>${dialogError}${dialogActions('Register & generate key →')}</form>`,async fd=>{
    const data=await post('/v1/developer/apps',Object.fromEntries(fd));state.apps=(await api('/v1/developer/apps')).applications;state.app=data.app_id;populateApps();await refreshData();go('keys');
    secretDialog('Your application is ready.',data.api_key,`API key for ${data.name}. Use it on your server to access this application's customer and license data.`);
  },'NEW APPLICATION');
  let touched=false;$('applicationSlug').addEventListener('input',()=>touched=true);$('applicationName').addEventListener('input',event=>{if(!touched)$('applicationSlug').value=event.target.value.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,120);});
}
function customerForm(edit=false) {
  const c=edit?state.detail.customer:{};
  openDialog(edit?'Edit customer':'Add a customer',`<p>${edit?'Update the customer profile.':'Create a customer record, then issue their first license.'}</p><form><label>Customer name<input name="name" value="${esc(c.name||'')}" placeholder="e.g. Alex Morgan" required maxlength="120"></label><label>Email address<input name="email" value="${esc(c.email||'')}" type="email" placeholder="alex@company.com" required maxlength="254"></label><label>Notes <span class="field-help">(optional)</span><textarea name="notes" maxlength="4000" placeholder="Company, account notes, or support context">${esc(c.notes||'')}</textarea></label>${dialogError}${dialogActions(edit?'Save changes':'Add customer →')}</form>`,async fd=>{
    const data=await post(edit?`/v1/developer/customers/${c.id}/update`:'/v1/developer/customers',{...Object.fromEntries(fd),app_id:state.app});closeDialog();await refreshData();go('customers/'+(edit?c.id:data.id));if(edit)await route();notify(edit?'Customer updated.':'Customer added. You can now issue their license.');
  },edit?'CUSTOMER PROFILE':'NEW CUSTOMER');
}
function newLicense(customerId) {
  if(!state.customers.length){customerForm();return;}
  openDialog('Issue a customer license',`<p>This key grants access to one device. Choose a customer and set their plan.</p><form><label>Customer<select name="customer_id" required>${state.customers.map(c=>`<option value="${esc(c.id)}" ${c.id===customerId?'selected':''}>${esc(c.name)} · ${esc(c.email)}</option>`).join('')}</select></label><label>Plan<input name="plan" value="Standard" required maxlength="80" placeholder="e.g. Pro"></label><label>Expires on <span class="field-help">(optional)</span><input name="expiry" type="date" min="${new Date().toISOString().slice(0,10)}"></label><p class="field-help">Leave empty for access without an expiry date.</p>${dialogError}${dialogActions('Generate license →')}</form>`,async fd=>{
    const body={app_id:state.app,customer_id:fd.get('customer_id'),plan:fd.get('plan'),expires_at:fd.get('expiry')?new Date(fd.get('expiry')+'T23:59:59').toISOString():null};
    const data=await post('/v1/developer/licenses',body);await sync();secretDialog('Customer license created.',data.license_key,'Send this license key to your customer. They enter it in your app to activate their device.','customers/'+body.customer_id);
  },'CUSTOMER ACCESS');
}
function editLicense(id) {
  const l=state.licenses.find(l=>l.id===id);if(!l)return;
  openDialog('Manage customer access',`<p>${esc(l.key_prefix)}•••• · ${esc(l.plan)} · ${esc(status(l))}</p><form><label>Plan<input name="plan" required maxlength="80" value="${esc(l.plan)}"></label><label>Expires on <span class="field-help">(optional)</span><input name="expiry" type="date" value="${esc(l.expires_at?.slice(0,10)||'')}" min="${new Date().toISOString().slice(0,10)}"></label><p class="field-help">Saving changes requires the customer's app to reactivate and refresh its token.</p>${dialogError}${dialogActions('Save access changes')}</form><div class="actions" style="margin-top:24px">${l.status==='revoked'?action('restore-license','Restore access','secondary',`data-id="${esc(id)}"`):action('revoke-license','Revoke access','danger',`data-id="${esc(id)}"`)}${action('reset-license','Reset device','secondary',`data-id="${esc(id)}"`)}</div>`,async fd=>{await post(`/v1/developer/license-records/${id}/update`,{app_id:state.app,plan:fd.get('plan'),expires_at:fd.get('expiry')?new Date(fd.get('expiry')+'T23:59:59').toISOString():null});closeDialog();await sync();notify('Access updated. The customer can reactivate to refresh their token.');},'LICENSE SETTINGS');
}
function confirmAction(title, message, label, callback) {
  openDialog(title,`<p>${esc(message)}</p><form>${dialogError}${dialogActions(label)}</form>`,async()=>{await callback();closeDialog();await sync();notify('Changes saved.');},'CONFIRM ACCESS CHANGE');
}
async function copy(text) {try{await navigator.clipboard.writeText(text);notify('Copied to clipboard.');}catch{notify('Clipboard is unavailable. Select and copy the displayed key.');}}
document.addEventListener('click', async event=>{
  const page=event.target.closest('[data-page]');if(page){go(page.dataset.page);return;}
  const b=event.target.closest('[data-action]');if(!b)return;
  const a=b.dataset.action,id=b.dataset.id;
  try{
    if(['overview','customers','licenses','keys','applications','activity'].includes(a)){go(a);return;}
    if(a==='close'){closeDialog();return;}
    if(a==='new-app'){newApp();return;}
    if(a==='select-app'){state.app=id;populateApps();await refreshData();go('overview');return;}
    if(a==='new-customer'){customerForm();return;}
    if(a==='customer'){go('customers/'+id);return;}
    if(a==='edit-customer'){customerForm(true);return;}
    if(a==='new-license'){newLicense(b.dataset.customer);return;}
    if(a==='edit-license'){editLicense(id);return;}
    if(a==='copy-secret'){await copy($('issuedSecret').textContent);return;}
    if(a==='copy-sample'){await copy($('integrationSample').textContent);return;}
    if(a==='secret-done'){closeDialog();go(b.dataset.next);return;}
    if(a==='rotate-key'){confirmAction('Regenerate API key?','The current API key will stop working. Update your server with the new key. Customer license keys remain the same.','Regenerate key',async()=>{const data=await post(`/v1/developer/apps/${encodeURIComponent(state.app)}/rotate-key`,{});state.apps=(await api('/v1/developer/apps')).applications;setTimeout(()=>secretDialog('Save your new API key.',data.api_key,'Update your server with this key. The previous API key is no longer valid.'),0);});return;}
    if(a==='revoke-app'){confirmAction('Disable this application?','This disables its API key and prevents its customers from activating or validating licenses. Customer records are retained.','Disable application',async()=>{await post(`/v1/developer/apps/${encodeURIComponent(state.app)}/revoke`,{});state.apps=(await api('/v1/developer/apps')).applications;state.app=state.apps.find(a=>a.status==='active')?.app_id||'';populateApps();go('applications');});return;}
    if(['revoke-license','restore-license','reset-license'].includes(a)){
      const op=a.split('-')[0], label={revoke:'Revoke access',restore:'Restore access',reset:'Reset device'}[op];
      const description={revoke:'The customer will lose access on their next online validation. You can restore this license later.',restore:'Allow this customer to activate again. Their previous device token remains invalid.',reset:'Remove the current device binding. The customer can activate this license on a new device; previous tokens will stop working.'}[op];
      confirmAction(label+'?',description,label,()=>post(`/v1/developer/license-records/${id}/${op}`,{app_id:state.app}));
    }
  } catch(error){notify(error.message);}
});
$('newAppSidebar').addEventListener('click',newApp);$('closeDialog').addEventListener('click',closeDialog);
$('appSelect').addEventListener('change',async event=>{state.app=event.target.value;populateApps();$('pageContent').innerHTML='<div class="loading-state">Loading application…</div>';try{await refreshData();go('overview');}catch(error){notify(error.message);}});
$('accountButton').addEventListener('click',()=>setAccountMenu($('accountMenu').hidden));
$('profileButton').addEventListener('click',()=>{setAccountMenu(false);profileDialog();});
document.addEventListener('click',event=>{if(!event.target.closest('.account-wrap'))setAccountMenu(false);});
async function logout(){try{await post('/v1/auth/logout',{});}catch{}clearSession();showAuth('login');}
$('logoutButton').addEventListener('click',logout);$('mobileLogout').addEventListener('click',logout);
window.addEventListener('hashchange',()=>route().catch(e=>notify(e.message)));
async function init(){
  if(state.session){try{await openWorkspace();return;}catch(error){clearSession();showAuth('login',error.message);return;}}
  showAuth(location.pathname==='/signup'?'signup':'login');
}
init();
