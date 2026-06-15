/* i18n.js — locale engine. No external lib; formatting via built-in Intl.
   Catalogs register themselves on window.KAPKAN_LOCALES (loaded as same-origin
   static JS here; in production may equally be JSON fetched same-origin). */
(function (w) {
  "use strict";
  w.KAPKAN_LOCALES = w.KAPKAN_LOCALES || {};

  var AVAILABLE = [
    { code: "en", label: "English",  flag: "EN" },
    { code: "de", label: "Deutsch",  flag: "DE" },
    { code: "ru", label: "Русский",  flag: "RU" },
    { code: "fr", label: "Français", flag: "FR" },
    { code: "es", label: "Español",  flag: "ES" }
  ];
  var STORE_KEY = "kapkan.locale";

  var I = {
    locale: "en",
    available: AVAILABLE,
    _subs: [],

    init: function () {
      var saved = null;
      try { saved = localStorage.getItem(STORE_KEY); } catch (e) {}
      var loc = saved && w.KAPKAN_LOCALES[saved] ? saved : "en";
      this.set(loc, true);
    },

    set: function (loc, silent) {
      if (!w.KAPKAN_LOCALES[loc]) loc = "en";
      this.locale = loc;
      try { localStorage.setItem(STORE_KEY, loc); } catch (e) {}
      document.documentElement.setAttribute("lang", loc);
      // build Intl formatters bound to this locale
      this._nf0 = new Intl.NumberFormat(loc, { maximumFractionDigits: 0 });
      this._nf1 = new Intl.NumberFormat(loc, { maximumFractionDigits: 1, minimumFractionDigits: 0 });
      this._pr  = new Intl.PluralRules(loc);
      this._rtf = new Intl.RelativeTimeFormat(loc, { numeric: "auto" });
      this._tf  = new Intl.DateTimeFormat(loc, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
      this._dtf = new Intl.DateTimeFormat(loc, { dateStyle: "medium", timeStyle: "short" });
      if (!silent) this._subs.forEach(function (fn) { fn(loc); });
    },

    onChange: function (fn) { this._subs.push(fn); },

    _cat: function () { return w.KAPKAN_LOCALES[this.locale] || w.KAPKAN_LOCALES.en; },
    _en:  function () { return w.KAPKAN_LOCALES.en; },

    /* translate a UI string key; {vars} interpolated */
    t: function (key, vars) {
      var c = this._cat();
      var s = (c.strings && c.strings[key]);
      if (s == null) s = (this._en().strings && this._en().strings[key]);
      if (s == null) return key;
      if (vars) {
        s = s.replace(/\{(\w+)\}/g, function (_, k) {
          return (vars[k] != null) ? vars[k] : "{" + k + "}";
        });
      }
      return s;
    },

    /* translate an enum value (attack type, metric, action, state...) */
    label: function (cat, key) {
      var c = this._cat();
      var m = c.enums && c.enums[cat];
      var v = m && m[key];
      if (v == null) { var e = this._en().enums[cat]; v = e && e[key]; }
      return v != null ? v : key;
    },
    /* short label variant (for tight widths, e.g. ladder rungs) */
    labelShort: function (cat, key) {
      var c = this._cat();
      var m = c.enumsShort && c.enumsShort[cat];
      var v = m && m[key];
      if (v != null) return v;
      return this.label(cat, key);
    },

    /* ---- formatting (locale-aware) ---- */
    num: function (n) { return this._nf0.format(n); },

    /* abbreviated count with k/M; physical unit appended verbatim */
    abbr: function (n, unit) {
      var s, abs = Math.abs(n);
      if (abs >= 1e9) s = this._nf1.format(n / 1e9) + "G";
      else if (abs >= 1e6) s = this._nf1.format(n / 1e6) + "M";
      else if (abs >= 1e3) s = this._nf1.format(n / 1e3) + "k";
      else s = this._nf0.format(n);
      return unit ? s + " " + unit : s;
    },
    pps:  function (n) { return this.abbr(n, "pps"); },
    mbps: function (n) {
      // present Gb/s above 1000 Mb/s; units standard across locales
      if (n >= 1000) return this._nf1.format(n / 1000) + " Gb/s";
      return this._nf0.format(n) + " Mb/s";
    },
    fps:  function (n) { return this.abbr(n, "fps"); },
    pct:  function (frac) { return this._nf0.format(Math.round(frac * 100)) + "%"; },

    /* humanized duration "22h 31m" (never raw seconds) */
    duration: function (sec) {
      sec = Math.max(0, Math.floor(sec));
      var u = this._cat().units || this._en().units;
      var d = Math.floor(sec / 86400); sec -= d * 86400;
      var h = Math.floor(sec / 3600);  sec -= h * 3600;
      var m = Math.floor(sec / 60);    var s = sec - m * 60;
      var parts = [];
      if (d) parts.push(d + u.d);
      if (h) parts.push(h + u.h);
      if (!d && m) parts.push(m + u.m);
      if (!d && !h && (s || !m)) parts.push(s + u.s);
      return parts.slice(0, 2).join(" ");
    },

    /* short countdown "0:14" or "1:05" */
    countdown: function (sec) {
      sec = Math.max(0, Math.ceil(sec));
      var m = Math.floor(sec / 60), s = sec % 60;
      return m + ":" + (s < 10 ? "0" : "") + s;
    },

    time: function (d) { return this._tf.format(d); },
    datetime: function (d) { return this._dtf.format(d); },

    /* relative time, e.g. "2m ago" */
    rel: function (date) {
      var diff = (date.getTime() - Date.now()) / 1000;
      var abs = Math.abs(diff);
      if (abs < 60) return this._rtf.format(Math.round(diff), "second");
      if (abs < 3600) return this._rtf.format(Math.round(diff / 60), "minute");
      if (abs < 86400) return this._rtf.format(Math.round(diff / 3600), "hour");
      return this._rtf.format(Math.round(diff / 86400), "day");
    },

    /* pluralization: key resolves to a {one,few,many,other} object */
    plural: function (n, key) {
      var c = this._cat();
      var forms = (c.plurals && c.plurals[key]) || (this._en().plurals[key]);
      var cat = this._pr.select(n);
      var tmpl = forms[cat] || forms.other;
      return tmpl.replace("#", this._nf0.format(n));
    }
  };

  w.I18N = I;
})(window);
