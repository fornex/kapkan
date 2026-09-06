// Kapkan clearance page: solve the hashcash puzzle, then submit the form.
//
// One file, two roles. On the page it drives the status line and starts
// Workers from its own URL (the page's CSP allows only its own scripts, and
// this is one); in a Worker it searches one LANE of candidates. The page's
// main thread searches a lane too, in short slices: a visible tab's main
// thread runs on the fastest core, while the Workers keep going when the tab
// is in the background and its timers are throttled. Lanes never overlap
// (each tags its candidates), and the first to find a solution submits.
//
// SHA-256 is implemented here rather than taken from WebCrypto: a hashcash
// attempt is one or two blocks, and WebCrypto's cost per call — a promise
// and a hop to another thread — was the bottleneck, not the hashing. The
// implementation is checked against a known digest before it is trusted.
//
// Everything a client sees here is public; the nonce binds the puzzle to
// this zone, this source and its pair of minutes.
(function () {
  "use strict";

  // The server accepts a nonce for its two-minute bucket and the
  // neighbours, so a solve that ran past this is posted for nothing: a fresh
  // puzzle is asked for instead.
  var STALE_MS = 100 * 1000;
  // Main-thread work between yields, and how many lanes run in Workers.
  var SLICE_MS = 12;
  var MAX_WORKERS = 4;

  var K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf | 0, 0xe9b5dba5 | 0, 0x3956c25b, 0x59f111f1, 0x923f82a4 | 0, 0xab1c5ed5 | 0,
    0xd807aa98 | 0, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe | 0, 0x9bdc06a7 | 0, 0xc19bf174 | 0,
    0xe49b69c1 | 0, 0xefbe4786 | 0, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152 | 0, 0xa831c66d | 0, 0xb00327c8 | 0, 0xbf597fc7 | 0, 0xc6e00bf3 | 0, 0xd5a79147 | 0, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e | 0, 0x92722c85 | 0,
    0xa2bfe8a1 | 0, 0xa81a664b | 0, 0xc24b8b70 | 0, 0xc76c51a3 | 0, 0xd192e819 | 0, 0xd6990624 | 0, 0xf40e3585 | 0, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814 | 0, 0x8cc70208 | 0, 0x90befffa | 0, 0xa4506ceb | 0, 0xbef9a3f7 | 0, 0xc67178f2 | 0
  ]);
  var W = new Int32Array(64);

  // sha256First returns the first word of SHA-256 over m[0:padded], a message
  // already padded in place (padded is a multiple of 64). The difficulty is
  // at most 22 leading zero bits, so the first word decides.
  function sha256First(m, padded) {
    var h0 = 0x6a09e667, h1 = 0xbb67ae85 | 0, h2 = 0x3c6ef372, h3 = 0xa54ff53a | 0;
    var h4 = 0x510e527f, h5 = 0x9b05688c | 0, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    for (var off = 0; off < padded; off += 64) {
      var i, j;
      for (i = 0, j = off; i < 16; i++, j += 4) {
        W[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
      }
      for (i = 16; i < 64; i++) {
        var x = W[i - 15], y = W[i - 2];
        W[i] = (W[i - 16] + (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) +
          W[i - 7] + (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10))) | 0;
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (i = 0; i < 64; i++) {
        var t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
          ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
        var t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
          ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return h0;
  }

  // selfCheck: SHA-256("abc") begins with ba7816bf — and the search step
  // itself runs (typed-array fill, clz32, the padding path), so an engine
  // that would throw in the loop is found out before the fallback is hidden.
  function selfCheck() {
    try {
      var m = new Uint8Array(64);
      m[0] = 0x61; m[1] = 0x62; m[2] = 0x63; m[3] = 0x80; m[63] = 24;
      if (sha256First(m, 64) !== (0xba7816bf | 0)) { return false; }
      return lane("ab", "c", 0).step(1) !== null;
    } catch (e) {
      return false;
    }
  }

  // lane searches candidates "<tag><n>" (n in base 36) appended to the
  // nonce, the message padded in place in one buffer. step(count) hashes up
  // to count candidates and returns the winner or null.
  function lane(nonce, tag, need) {
    var L = nonce.length + tag.length;
    var m = new Uint8Array(((L + 16 + 9 + 63) >> 6) << 6);
    var i;
    for (i = 0; i < nonce.length; i++) { m[i] = nonce.charCodeAt(i); }
    for (i = 0; i < tag.length; i++) { m[nonce.length + i] = tag.charCodeAt(i); }
    var n = 0;
    return {
      attempts: function () { return n; },
      step: function (count) {
        for (var k = 0; k < count; k++) {
          var cand = (n++).toString(36), cl = cand.length, len = L + cl;
          for (var p = 0; p < cl; p++) { m[L + p] = cand.charCodeAt(p); }
          var padded = ((len + 9 + 63) >> 6) << 6;
          m[len] = 0x80;
          m.fill(0, len + 1, padded);
          var bits = len * 8;
          m[padded - 3] = (bits >>> 16) & 0xff; m[padded - 2] = (bits >>> 8) & 0xff; m[padded - 1] = bits & 0xff;
          if (Math.clz32(sha256First(m, padded)) >= need) { return tag + cand; }
        }
        return null;
      }
    };
  }

  // The Worker role: one message in (the puzzle and this lane's tag),
  // progress about once a second and the solution out.
  if (typeof document === "undefined" && typeof self !== "undefined" && typeof self.postMessage === "function") {
    self.onmessage = function (e) {
      var p = e.data || {};
      if (!selfCheck()) { self.postMessage({ error: "sha256" }); return; }
      var ln = lane(String(p.nonce), String(p.tag), p.difficulty | 0);
      var last = Date.now();
      for (;;) {
        var found = ln.step(4096);
        if (found !== null) { self.postMessage({ solution: found }); return; }
        var now = Date.now();
        if (now - last > 900) { last = now; self.postMessage({ progress: ln.attempts() }); }
      }
    };
    return;
  }

  // The page role.
  var scriptURL = document.currentScript && document.currentScript.src;
  var status = document.getElementById("kapkan-status");
  var count = document.getElementById("kapkan-count");
  var form = document.getElementById("kapkan-answer");
  var fallback = document.getElementById("kapkan-fallback");
  var block = document.getElementById("kapkan-puzzle");
  if (!status || !form || !block) { return; }

  // showFallback puts the timed ticket's Continue in front of the visitor
  // now (the stylesheet would reveal it by itself after a while) and says so
  // in the status line, which assistive technology announces. With keep, the
  // solver goes on beside it — a slow client gets the timed path without
  // losing the puzzle.
  function showFallback(keep) {
    if (fallback) { fallback.hidden = false; fallback.className = "kapkan-now"; }
    if (!keep) {
      if (count) { count.textContent = ""; }
      var said = fallback && fallback.querySelector("p");
      if (status && said) { status.textContent = said.textContent; }
    }
  }

  var puzzle;
  try { puzzle = JSON.parse(block.textContent); } catch (e) { showFallback(); return; }
  if (!puzzle || typeof puzzle.nonce !== "string" || !/^[\x21-\x7e]{1,200}$/.test(puzzle.nonce) || !selfCheck()) {
    showFallback();
    return;
  }
  var need = puzzle.difficulty | 0;
  var lang = document.documentElement.lang || "en";
  var words = {
    en: ["Working…", "Done, continuing…"], ru: ["Считаем…", "Готово, продолжаем…"],
    de: ["Wird berechnet…", "Fertig, weiter geht es…"], fr: ["Calcul en cours…", "Terminé, on continue…"],
    es: ["Calculando…", "Listo, continuamos…"]
  };
  var w = words[lang] || words.en;
  var started = Date.now();
  var over = false;
  var workers = [];
  var attempts = {}; // per lane

  if (fallback) { fallback.hidden = true; }
  // Announced once by assistive technology (role=status); the moving counter
  // is a separate element it does not read.
  status.textContent = w[0];
  // A solve that is taking long — a slow device, a high difficulty — gets the
  // timed path offered beside it: the ticket is redeemable from 4 s to 120 s
  // after issue, so from here on Continue is the sure way through.
  setTimeout(function () { if (!over) { showFallback(true); } }, 20000);

  function progress(tag, n) {
    attempts[tag] = n;
    var total = 0;
    for (var t in attempts) { total += attempts[t]; }
    if (count) { count.textContent = Math.round(total / 1000) + "k"; }
  }
  function stopWorkers() {
    for (var i = 0; i < workers.length; i++) { workers[i].terminate(); }
    workers = [];
  }
  function fresh() {
    // Start over with a fresh puzzle: the request goes back through the
    // terminator, whose decision service challenges again.
    over = true;
    stopWorkers();
    location.reload();
  }
  function finish(solution) {
    if (over) { return; }
    if (Date.now() - started > STALE_MS) { fresh(); return; }
    over = true;
    stopWorkers();
    status.textContent = w[1];
    if (count) { count.textContent = ""; }
    form.elements.solution.value = solution;
    form.submit();
  }
  document.addEventListener("visibilitychange", function () {
    // Back from a long stretch in the background: whatever the lanes did,
    // the puzzle has aged out.
    if (!document.hidden && !over && Date.now() - started > STALE_MS) { fresh(); }
  });

  // Worker lanes: one per core, a few at most. A lane that cannot run is
  // simply not there; the main thread's lane always is.
  if (window.Worker && scriptURL) {
    var want = Math.min(MAX_WORKERS, Math.max(1, (navigator.hardwareConcurrency || 2) - 1));
    for (var i = 0; i < want; i++) {
      try {
        var wk = new Worker(scriptURL);
        (function (tag) {
          wk.onmessage = function (e) {
            var m = e.data || {};
            if (typeof m.solution === "string") { finish(m.solution); } else if (m.progress) { progress(tag, m.progress); }
          };
          wk.onerror = function () { /* this lane is out; the others go on */ };
          wk.postMessage({ nonce: puzzle.nonce, tag: tag, difficulty: need });
        })("w" + i);
        workers.push(wk);
      } catch (e) {
        break;
      }
    }
  }

  // The main thread's lane, in slices. It yields through a MessageChannel
  // where there is one — a background tab throttles timers, not messages —
  // and through a timer otherwise.
  var main = lane(puzzle.nonce, "m", need);
  var yieldTo = (function () {
    if (window.MessageChannel) {
      var ch = new MessageChannel(), pending = null;
      ch.port1.onmessage = function () { var f = pending; pending = null; if (f) { f(); } };
      return function (f) { pending = f; ch.port2.postMessage(0); };
    }
    return function (f) { setTimeout(f, 0); };
  })();
  var lastReport = Date.now();
  function slice() {
    if (over) { return; }
    try {
      var t0 = Date.now();
      do {
        var found = main.step(256);
        if (found !== null) { finish(found); return; }
      } while (Date.now() - t0 < SLICE_MS);
      if (t0 - lastReport > 900) { lastReport = t0; progress("m", main.attempts()); }
    } catch (e) {
      // The main lane died: whatever the Workers do, the visitor gets the
      // sure way through now.
      failed();
      return;
    }
    yieldTo(slice);
  }
  slice();
})();
