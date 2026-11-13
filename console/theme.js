/* theme.js — the console's two themes, Night and Paper, plus "as the system".
   Loaded synchronously in <head>, before the stylesheets apply, so the saved
   theme is on <html> before the first paint and a Paper reader never sees a
   flash of Night. It has to be a file: the CSP (script-src 'self') runs no
   inline script.

   The preference is stored ("night" | "paper" | "system"); <html data-theme>
   always carries the EFFECTIVE theme ("night" | "paper"), so the stylesheet
   needs one selector per theme and never a media query. */
(function (w, d) {
  "use strict";
  var KEY = "kapkan.theme";
  var PREFS = { night: 1, paper: 1, system: 1 };
  var mq = w.matchMedia ? w.matchMedia("(prefers-color-scheme: light)") : null;
  var pref = "night";
  try { var saved = w.localStorage.getItem(KEY); if (PREFS[saved]) pref = saved; } catch (e) {}

  function effective() { return pref === "system" ? (mq && mq.matches ? "paper" : "night") : pref; }
  function apply() { d.documentElement.setAttribute("data-theme", effective()); }
  apply();

  var subs = [];
  /* "as the system" follows the OS switching while the page is open */
  if (mq) {
    var onChange = function () { if (pref === "system") { apply(); subs.forEach(function (fn) { fn(); }); } };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  w.KapkanTheme = {
    pref: function () { return pref; },
    effective: effective,
    set: function (p) {
      if (!PREFS[p]) return;
      pref = p;
      try { w.localStorage.setItem(KEY, p); } catch (e) {}
      apply();
      subs.forEach(function (fn) { fn(); });
    },
    onChange: function (fn) { subs.push(fn); }
  };
})(window, document);
