// Kapkan clearance page: solve the hashcash puzzle, then submit the form.
// Runs on the main thread in short chunks (no Worker: the page's CSP allows
// only its own script, and a chunked loop keeps the page responsive).
// SHA-256 comes from WebCrypto, which needs the secure context every zone
// already is. Everything a client sees here is public; the nonce is what
// binds the puzzle to this zone, this source and this minute.
(function () {
  "use strict";
  var status = document.getElementById("kapkan-status");
  var form = document.getElementById("kapkan-answer");
  var block = document.getElementById("kapkan-puzzle");
  if (!status || !form || !block || !window.crypto || !crypto.subtle || !window.TextEncoder) {
    return; // the <noscript> path is the fallback for everything old
  }
  var puzzle;
  try { puzzle = JSON.parse(block.textContent); } catch (e) { return; }
  var lang = document.documentElement.lang || "en";
  var words = {
    en: ["Working…", "Done, continuing…"], ru: ["Считаем…", "Готово, продолжаем…"],
    de: ["Wird berechnet…", "Fertig, weiter geht es…"], fr: ["Calcul en cours…", "Terminé, on continue…"],
    es: ["Calculando…", "Listo, continuamos…"]
  };
  var w = words[lang] || words.en;
  status.textContent = w[0];

  var enc = new TextEncoder();
  var prefix = enc.encode(puzzle.nonce);
  var need = puzzle.difficulty | 0;
  var counter = 0;
  var lastTick = 0;

  function leadingZeroBits(buf) {
    var bytes = new Uint8Array(buf), n = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b === 0) { n += 8; continue; }
      while ((b & 0x80) === 0) { n++; b <<= 1; }
      return n;
    }
    return n;
  }

  function attempt(candidate) {
    var c = enc.encode(candidate);
    var data = new Uint8Array(prefix.length + c.length);
    data.set(prefix, 0);
    data.set(c, prefix.length);
    return crypto.subtle.digest("SHA-256", data).then(function (sum) {
      return leadingZeroBits(sum) >= need;
    });
  }

  function chunk() {
    // A few dozen digests per tick, then yield: smooth on a slow phone, and
    // the progress line stays live for assistive technology.
    var tries = 0;
    function next() {
      if (tries++ >= 48) {
        var now = Date.now();
        if (now - lastTick > 900) {
          lastTick = now;
          status.textContent = w[0] + " " + Math.round(counter / 1000) + "k";
        }
        setTimeout(chunk, 0);
        return;
      }
      var candidate = (counter++).toString(36);
      attempt(candidate).then(function (ok) {
        if (ok) {
          status.textContent = w[1];
          form.elements.solution.value = candidate;
          form.submit();
          return;
        }
        next();
      }, function () {
        // WebCrypto refused (an insecure context?): leave the no-JS path.
        status.textContent = "";
      });
    }
    next();
  }
  chunk();
})();
