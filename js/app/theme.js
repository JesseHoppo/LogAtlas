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
  themeToggle.setAttribute('aria-pressed', String(isDark));

  if (persist) {
    writeStoredTheme(isDark ? 'dark' : 'light');
  }
}

export function initThemeToggle() {
  const themeToggle = document.getElementById('themeToggle');
  if (!themeToggle) return;

  const savedTheme = readStoredTheme();
  applyTheme(themeToggle, savedTheme === 'dark' ? 'dark' : 'light', { persist: false });

  themeToggle.addEventListener('click', () => {
    const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(themeToggle, nextTheme);
  });
}
