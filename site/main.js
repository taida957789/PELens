// Language, screenshot tabs, copy button and the latest release on the download buttons.
(function () {
  // the visitor's system picks the main download button
  const OS = {
    windows: { name: 'Windows', info: 'x64 · zip', asset: /windows-x64\.zip$/ },
    macos: { name: 'macOS', info: 'Apple silicon + Intel · zip', asset: /macos-universal\.zip$/ },
    linux: { name: 'Linux', info: 'x86_64 · tar.gz', asset: /linux-x86_64\.tar\.gz$/ },
  };
  const ua = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '') + ' ' + navigator.userAgent;
  const os = /mac|iphone|ipad/i.test(ua) ? 'macos' : /linux|x11|cros/i.test(ua) && !/android/i.test(ua) ? 'linux' : 'windows';
  document.querySelectorAll('.other-os a').forEach(function (a) { a.hidden = a.dataset.os === os; });
  document.querySelector('[data-i18n="hero.download"]').dataset.en = 'Download for {os}';
  document.getElementById('release-info').textContent = OS[os].info;
  if (os !== 'windows') {
    document.getElementById('cli').hidden = true;
    document.getElementById('cli-unix').hidden = false;
    document.getElementById('shell').textContent = os === 'macos' ? 'Terminal' : 'Shell';
    document.querySelector('.copy').dataset.copy = 'cli-unix';
  }

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
      el.innerHTML = (t[key] || el.dataset.en).replace('{os}', OS[os].name);
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

  // latest release: version and size of the package of each system
  fetch('https://api.github.com/repos/taida957789/PELens/releases/latest')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rel) {
      if (!rel) return;
      const find = function (k) { return (rel.assets || []).find(function (a) { return OS[k].asset.test(a.name); }); };
      const main = find(os);
      document.getElementById('release-info').textContent =
        rel.tag_name + ' · ' + OS[os].info.split(' · ')[0] + (main ? ' · ' + (main.size / 1048576).toFixed(1) + ' MB' : '');
      if (main) document.getElementById('download').href = main.browser_download_url;
      document.querySelectorAll('.other-os a').forEach(function (a) {
        const f = find(a.dataset.os);
        if (f) a.href = f.browser_download_url;
      });
    })
    .catch(function () {});
})();
