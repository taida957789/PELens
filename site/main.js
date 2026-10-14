// Language, screenshot tabs, copy button and the latest release on the download button.
(function () {
  const select = document.getElementById('lang');
  const supported = Object.keys(window.PELENS_I18N);

  function pick() {
    const saved = localStorage.getItem('pelens-lang');
    if (saved && supported.includes(saved)) return saved;
    for (const l of navigator.languages || [navigator.language || 'en']) {
      const lower = l.toLowerCase();
      if (lower.startsWith('zh')) return /tw|hk|mo|hant/.test(lower) ? 'zh-TW' : 'zh-CN';
      const base = lower.split('-')[0];
      if (supported.includes(base)) return base;
    }
    return 'en';
  }

  function apply(lang) {
    const t = window.PELENS_I18N[lang] || {};
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      if (!el.dataset.en) el.dataset.en = el.innerHTML;
      el.innerHTML = t[key] || el.dataset.en;
    });
    if (t['meta.title']) document.title = t['meta.title'];
    select.value = lang;
  }

  select.addEventListener('change', function () {
    localStorage.setItem('pelens-lang', select.value);
    apply(select.value);
  });
  apply(pick());

  // screenshot tabs
  const shot = document.getElementById('shot');
  document.querySelectorAll('.tabs button').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('.tabs button').forEach(function (x) { x.setAttribute('aria-selected', 'false'); });
      b.setAttribute('aria-selected', 'true');
      shot.src = 'screenshots/' + b.dataset.shot + '.png';
      shot.alt = b.textContent;
    });
  });

  // copy the command examples (comments removed)
  document.querySelectorAll('.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      const text = document.getElementById(b.dataset.copy).innerText
        .split('\n').filter(function (l) { return l.trim() && !l.trim().startsWith('#'); }).join('\n');
      navigator.clipboard.writeText(text).then(function () {
        const old = b.textContent;
        b.textContent = '✓';
        setTimeout(function () { b.textContent = old; }, 1200);
      });
    });
  });

  // latest release: version and size of the zip
  fetch('https://api.github.com/repos/taida957789/PELens/releases/latest')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rel) {
      if (!rel) return;
      const zip = (rel.assets || []).find(function (a) { return /\.zip$/.test(a.name); });
      const info = document.getElementById('release-info');
      info.textContent = rel.tag_name + ' · x64 · ' + (zip ? (zip.size / 1048576).toFixed(1) + ' MB' : 'zip');
      if (zip) document.getElementById('download').href = zip.browser_download_url;
    })
    .catch(function () {});
})();
