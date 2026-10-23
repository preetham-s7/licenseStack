const $ = id => document.getElementById(id);
const frame = $('cameraFrame');
const video = $('camera');
const statusBox = $('scanStatus');
let stream = null;
let detector = null;
let scanning = false;
let handling = false;
const apiOrigin = window.LICENSE_PLATFORM_URL || window.location.origin;

function mobileDeviceId() {
  const key = 'licensestack-mobile-device';
  let value = localStorage.getItem(key);
  if (!value) { value = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`; localStorage.setItem(key, value); }
  return value;
}

function status(title, detail, kind='') {
  statusBox.className = `scan-status ${kind}`;
  statusBox.innerHTML = `<strong>${title}</strong><span>${detail}</span>`;
}

function extractCode(value) {
  const raw = String(value || '').trim();
  try {
    const url = new URL(raw, location.origin);
    const code = url.searchParams.get('code');
    if (code) return code;
  } catch {}
  try {
    const object = JSON.parse(raw);
    if (object.pairing_code) return object.pairing_code;
  } catch {}
  return raw;
}

async function submitCode(value) {
  if (handling) return;
  const pairingCode = extractCode(value);
  if (!pairingCode) { status('No QR value found', 'Scan the QR shown in the customer software.', 'error'); return; }
  handling = true;
  status('Checking activation…', 'LicenseStack is securely processing this pairing.', '');
  try {
    const response = await fetch(`${apiOrigin}/v1/pairing/scan`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pairing_code: pairingCode, mobile_device_id: mobileDeviceId()})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'This QR code could not be accepted.');
    if (data.status === 'already_activated') status('Already activated', 'This software is already paired. Scanning again will not create another activation.', 'success');
    else status('Activation complete', 'This device is now paired with the customer software.', 'success');
    stopCamera();
  } catch (error) {
    handling = false;
    status('Scan not accepted', error.message, 'error');
  }
}

async function scanFrame() {
  if (!scanning || !detector || handling) return;
  try {
    const results = await detector.detect(video);
    if (results.length && results[0].rawValue) { await submitCode(results[0].rawValue); return; }
  } catch {}
  if (scanning) requestAnimationFrame(scanFrame);
}

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) { status('Camera unavailable', 'Use HTTPS or localhost, or paste the QR value below.', 'error'); return; }
  if (!('BarcodeDetector' in window)) { status('QR scanning is unavailable in this browser', 'Use a current Chrome or Edge browser, or paste the QR value below.', 'error'); return; }
  try {
    detector = new BarcodeDetector({formats:['qr_code']});
    stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280},height:{ideal:1280}},audio:false});
    video.srcObject = stream; await video.play(); scanning = true; frame.classList.add('is-live'); $('startCamera').hidden = true; $('stopCamera').hidden = false; status('Ready to scan', 'Point your camera at the QR code in the desktop software.'); requestAnimationFrame(scanFrame);
  } catch (error) { status('Camera permission was not granted', error.message || 'Allow camera access and try again.', 'error'); }
}

function stopCamera() { scanning = false; if (stream) stream.getTracks().forEach(track => track.stop()); stream = null; video.srcObject = null; frame.classList.remove('is-live'); $('startCamera').hidden = false; $('stopCamera').hidden = true; }

$('startCamera').addEventListener('click', startCamera);
$('stopCamera').addEventListener('click', stopCamera);
$('submitCode').addEventListener('click', () => submitCode($('pairingCode').value));
const queryCode = new URLSearchParams(location.search).get('code');
if (queryCode) { $('pairingCode').value = queryCode; status('QR value loaded', 'Start the camera or submit the loaded value.'); }
window.addEventListener('pagehide', stopCamera);
