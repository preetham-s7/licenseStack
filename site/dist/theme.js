(() => {
  const key = 'licensestack-theme';
  const saved = localStorage.getItem(key);
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches;

  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(key, theme);
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      const dark = theme === 'dark';
      button.textContent = dark ? '☀' : '☾';
      button.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
      button.setAttribute('title', dark ? 'Switch to light theme' : 'Switch to dark theme');
      button.setAttribute('aria-pressed', String(dark));
    });
  }

  apply(saved || (prefersDark ? 'dark' : 'light'));
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      button.addEventListener('click', () => apply(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
    });
  });
})();
