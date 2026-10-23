const menuToggle = document.querySelector('.menu-toggle');
const siteNav = document.querySelector('.site-nav');
const toast = document.querySelector('.toast');
const platformOrigin = window.LICENSE_PLATFORM_URL || (window.location.port === '8080' ? window.location.origin : 'http://127.0.0.1:8080');

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

menuToggle?.addEventListener('click', () => {
  const isOpen = siteNav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', String(isOpen));
  menuToggle.textContent = isOpen ? 'Close' : 'Menu';
});

document.querySelectorAll('.site-nav a').forEach((link) => {
  link.addEventListener('click', () => {
    siteNav.classList.remove('open');
    menuToggle?.setAttribute('aria-expanded', 'false');
    if (menuToggle) menuToggle.textContent = 'Menu';
  });
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
