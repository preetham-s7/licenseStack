const menuToggle = document.querySelector('.menu-toggle');
const siteNav = document.querySelector('.site-nav');
const toast = document.querySelector('.toast');
const platformOrigin = window.LICENSE_PLATFORM_URL || window.location.origin;

document.querySelectorAll('[data-platform-route]').forEach((element) => {
  const route = element.dataset.platformRoute;
  if (!route) return;
  const destination = `${platformOrigin}${route}`;
  if (element.tagName === 'A') element.href = destination;
  element.addEventListener('click', () => {
    window.location.href = destination;
  });
});

document.querySelectorAll('.mock-button').forEach((button) => {
  if (button.tagName === 'BUTTON') {
    button.addEventListener('click', () => { window.location.href = `${platformOrigin}/dashboard`; });
  }
});

function setMenuOpen(isOpen) {
  if (!siteNav || !menuToggle) return;
  siteNav.classList.toggle('open', isOpen);
  siteNav.setAttribute('aria-hidden', String(!isOpen));
  menuToggle.setAttribute('aria-expanded', String(isOpen));
  menuToggle.textContent = isOpen ? 'Close' : 'Menu';
}

menuToggle?.addEventListener('click', (event) => {
  event.preventDefault();
  event.stopPropagation();
  setMenuOpen(!siteNav?.classList.contains('open'));
});

document.querySelectorAll('.site-nav a').forEach((link) => {
  link.addEventListener('click', () => {
    setMenuOpen(false);
  });
});

document.addEventListener('click', (event) => {
  if (siteNav?.classList.contains('open') && !siteNav.contains(event.target) && event.target !== menuToggle) {
    setMenuOpen(false);
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') setMenuOpen(false);
});

window.addEventListener('resize', () => {
  if (window.innerWidth > 680) setMenuOpen(false);
});

document.querySelectorAll('[data-copy-target]').forEach((button) => {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copyTarget)?.innerText || '';
    try {
      await navigator.clipboard.writeText(code);
      button.textContent = 'Copied';
      showToast('Code copied to clipboard');
      setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    } catch {
      showToast('Select the code to copy it');
    }
  });
});

document.querySelectorAll('a[href^="#"]').forEach((link) => {
  link.addEventListener('click', (event) => {
    const target = document.querySelector(link.getAttribute('href'));
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

function showToast(message) {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 2200);
}

// The homepage scanner is intentionally public: customers do not need a
// LicenseStack account. It only submits the short-lived pairing value from
// the QR code and an anonymous browser/device identifier.
const scannerDialog = document.getElementById('customer-scan');
const homeCamera = document.getElementById('home-camera');
const homeCameraPlaceholder = document.getElementById('home-camera-placeholder');
const homeStartCamera = document.getElementById('home-start-camera');
const homeStopCamera = document.getElementById('home-stop-camera');
const homeScanStatus = document.getElementById('home-scan-status');
const homeManualForm = document.getElementById('home-manual-form');
const homeManualCode = document.getElementById('home-manual-code');
let homeCameraStream = null;
let homeScanFrame = null;
let homeScanBusy = false;
let homeBarcodeDetector = null;

function getMobileDeviceId() {
  const key = 'licensestack-mobile-device';
  try {
    let deviceId = window.localStorage.getItem(key);
    if (!deviceId) {
      deviceId = `mobile_${crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}_${Math.random().toString(16).slice(2)}`}`;
      window.localStorage.setItem(key, deviceId);
    }
    return deviceId;
  } catch {
    return `mobile_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  }
}

function setScannerStatus(message, state = '') {
  if (!homeScanStatus) return;
  homeScanStatus.textContent = message;
  homeScanStatus.dataset.state = state;
}

function extractPairingCode(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw, window.location.origin);
    const queryCode = url.searchParams.get('code');
    if (queryCode) return queryCode;
  } catch {
    // The QR can also contain the raw opaque pairing value.
  }
  try {
    const payload = JSON.parse(raw);
    if (payload && typeof payload.pairing_code === 'string') return payload.pairing_code;
    if (payload && typeof payload.code === 'string') return payload.code;
  } catch {
    // Not JSON; use the raw value below.
  }
  return raw;
}

function stopHomeCamera() {
  if (homeScanFrame) window.cancelAnimationFrame(homeScanFrame);
  homeScanFrame = null;
  if (homeCameraStream) {
    homeCameraStream.getTracks().forEach((track) => track.stop());
    homeCameraStream = null;
  }
  if (homeCamera) {
    homeCamera.pause();
    homeCamera.srcObject = null;
    homeCamera.hidden = true;
  }
  if (homeCameraPlaceholder) homeCameraPlaceholder.hidden = false;
  if (homeStartCamera) homeStartCamera.hidden = false;
  if (homeStopCamera) homeStopCamera.hidden = true;
}

function openScanner(event) {
  event?.preventDefault();
  if (!scannerDialog) return;
  if (typeof scannerDialog.showModal === 'function' && !scannerDialog.open) scannerDialog.showModal();
  else scannerDialog.setAttribute('open', '');
  setScannerStatus('Ready to scan. Your phone will be identified only for this activation.');
  homeManualCode?.focus({ preventScroll: true });
}

function closeScanner() {
  stopHomeCamera();
  if (scannerDialog?.open && typeof scannerDialog.close === 'function') scannerDialog.close();
  else scannerDialog?.removeAttribute('open');
}

async function submitHomePairingCode(value) {
  const pairingCode = extractPairingCode(value);
  if (!pairingCode) {
    setScannerStatus('Paste or scan a valid activation QR value.', 'error');
    return;
  }
  homeScanBusy = true;
  setScannerStatus('Checking activation…');
  try {
    const response = await fetch(`${platformOrigin}/v1/pairing/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pairing_code: pairingCode, mobile_device_id: getMobileDeviceId() }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || 'This activation QR could not be accepted.');
    stopHomeCamera();
    if (payload.status === 'already_activated') {
      setScannerStatus('Already activated. This device pairing is already complete.', 'success');
      showToast('This activation is already complete');
    } else {
      setScannerStatus('Activation complete. You can return to the software.', 'success');
      showToast('Activation complete');
    }
  } catch (error) {
    setScannerStatus(error.message || 'Activation failed. Try again.', 'error');
  } finally {
    homeScanBusy = false;
  }
}

async function scanHomeCameraFrame() {
  if (!homeCameraStream || !homeCamera || homeScanBusy) return;
  try {
    const codes = await homeBarcodeDetector.detect(homeCamera);
    if (codes.length && codes[0].rawValue) {
      await submitHomePairingCode(codes[0].rawValue);
      return;
    }
  } catch {
    // Keep scanning; camera frames can occasionally fail while autofocus runs.
  }
  homeScanFrame = window.requestAnimationFrame(scanHomeCameraFrame);
}

async function startHomeCamera() {
  if (!homeCamera || !navigator.mediaDevices?.getUserMedia) {
    setScannerStatus('Camera access is unavailable in this browser. Paste the QR value below.', 'error');
    return;
  }
  if (!('BarcodeDetector' in window)) {
    setScannerStatus('QR scanning is not supported in this browser. Paste the QR value below.', 'error');
    return;
  }
  try {
    homeBarcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
    homeCameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
    homeCamera.srcObject = homeCameraStream;
    homeCamera.hidden = false;
    if (homeCameraPlaceholder) homeCameraPlaceholder.hidden = true;
    if (homeStartCamera) homeStartCamera.hidden = true;
    if (homeStopCamera) homeStopCamera.hidden = false;
    setScannerStatus('Point your camera at the QR code shown in the software.');
    await homeCamera.play();
    scanHomeCameraFrame();
  } catch (error) {
    stopHomeCamera();
    const message = error.name === 'NotAllowedError'
      ? 'Camera permission was denied. Allow camera access or paste the QR value below.'
      : 'Could not start the camera. Paste the QR value below instead.';
    setScannerStatus(message, 'error');
  }
}

document.querySelectorAll('[data-open-scanner]').forEach((trigger) => trigger.addEventListener('click', openScanner));
document.querySelectorAll('[data-close-scanner]').forEach((trigger) => trigger.addEventListener('click', closeScanner));
homeStartCamera?.addEventListener('click', startHomeCamera);
homeStopCamera?.addEventListener('click', () => {
  stopHomeCamera();
  setScannerStatus('Camera stopped. You can start it again or paste the QR value.');
});
homeManualForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  submitHomePairingCode(homeManualCode?.value);
});
scannerDialog?.addEventListener('cancel', stopHomeCamera);
scannerDialog?.addEventListener('close', stopHomeCamera);
scannerDialog?.addEventListener('click', (event) => {
  if (event.target === scannerDialog) closeScanner();
});
window.addEventListener('pagehide', stopHomeCamera);

const initialPairingCode = new URLSearchParams(window.location.search).get('code');
if (initialPairingCode && scannerDialog) {
  openScanner();
  if (homeManualCode) homeManualCode.value = initialPairingCode;
}
