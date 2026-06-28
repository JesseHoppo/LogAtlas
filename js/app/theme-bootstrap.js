(function () {
  try {
    var stored = localStorage.getItem('logAtlasTheme');
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (stored === 'dark' || (stored == null && prefersDark)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch {}
})();
