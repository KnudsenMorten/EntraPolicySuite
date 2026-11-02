// BRAND-2.5: the chosen theme on <html> before the first paint (loaded synchronously in <head>). Auto = the OS setting.
(function () {
  var t = 'auto';
  try { t = localStorage.getItem('eps.theme') || 'auto'; } catch (e) { }
  if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
})();
