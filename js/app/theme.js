const THEME_STORAGE_KEY = 'logAtlasTheme';

function readStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Ignore storage failures so the app shell still boots.
  }
}

function prefersDark() {
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applyTheme(themeToggle, theme, { persist = true } = {}) {
  const isDark = theme === 'dark';
  if (isDark) {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }

  const nextActionLabel = isDark ? 'Switch to light mode' : 'Switch to dark mode';
  themeToggle.textContent = isDark ? 'Light' : 'Dark';
  themeToggle.title = nextActionLabel;
  themeToggle.setAttribute('aria-label', nextActionLabel);

  if (persist) {
    writeStoredTheme(isDark ? 'dark' : 'light');
  }
}

export function initThemeToggle() {
  const themeToggle = document.getElementById('themeToggle');
  if (!themeToggle) return;

  // Both labels name the action rather than the theme in effect, so the button
  // carries no pressed state to contradict them.
  themeToggle.removeAttribute('aria-pressed');

  // theme-bootstrap.js sets data-theme before CSS applies; this just brings the toggle button label into agreement.
  const stored = readStoredTheme();
  const initial = stored === 'dark' || stored === 'light'
    ? stored
    : (prefersDark() ? 'dark' : 'light');
  applyTheme(themeToggle, initial, { persist: false });

  themeToggle.addEventListener('click', () => {
    const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(themeToggle, nextTheme);
  });

  // Track system preference until the user explicitly picks a theme.
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener('change', (e) => {
      if (readStoredTheme() != null) return;
      applyTheme(themeToggle, e.matches ? 'dark' : 'light', { persist: false });
    });
  }
}
