/* icons.js — inline SVG icon set. Trusted constants (no user data).
   Presentation attributes only (no style= attrs) so it is CSP style-src safe.
   Stroke icons inherit color via currentColor. */
(function (w) {
  "use strict";
  var P = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" class="ico" aria-hidden="true">';
  var F = '<svg viewBox="0 0 24 24" fill="currentColor" class="ico" aria-hidden="true">';
  var ICONS = {
    /* The Kapkan mark: an ink tile, a stepped ramp of nine blue modules (the
       escalation ladder: watch → drop only the attack → null-route the target)
       and the duty light, a round ember dot, on the top step. Same geometry as
       the brand mark, on a 64 grid: modules 8×8, gap 2,
       the grid offset to 12; light r 4.6. Its colours are constant (never
       currentColor): the light always sits on dark. Presentation attributes
       only, so it stays CSP style-src safe like the rest of this set. */
    brandmark:    '<svg viewBox="0 0 64 64" class="ico" aria-hidden="true" focusable="false">' +
      '<rect width="64" height="64" rx="14" fill="#16181c"/>' +
      '<rect x="32" y="22" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="42" y="22" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="22" y="32" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="32" y="32" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="42" y="32" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="12" y="42" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="22" y="42" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="32" y="42" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<rect x="42" y="42" width="8" height="8" rx="1.6" fill="#4ea1ff"/>' +
      '<circle cx="46" cy="16" r="4.6" fill="#ffb454"/></svg>',
    /* The wordmark: lowercase "kapkan" in IBM Plex Sans SemiBold at −0.02em,
       outlined to one path (font units, baseline at y = 0; the viewBox starts
       at the k's ink), so it looks the same without the font. One colour:
       currentColor. Not an icon — sized by .brand__word, not .ico. */
    wordmark:     '<svg viewBox="74 -740 3186 940" class="brand__word" aria-hidden="true" focusable="false">' +
      '<path fill="currentColor" d="M74 0L74-740L202-740L202-294L207-294L276-388L393-522L538-522L358-320L557 0L405 0L271-234L202-159L202 0L74 0Z M1070 0L999 0Q957 0 932.5-24.5Q908-49 902-90L896-90Q883-39 843-13.5Q803 12 744 12Q664 12 621-30Q578-72 578-142Q578-223 636-262.5Q694-302 801-302L890-302L890-340Q890-384 867-408Q844-432 793-432Q748-432 720.5-412.5Q693-393 674-366L598-434Q627-479 675-506.5Q723-534 802-534Q908-534 963-486Q1018-438 1018-348L1018-102L1070-102L1070 0ZM787-81Q830-81 860-100Q890-119 890-156L890-225L808-225Q708-225 708-161L708-144Q708-112 728.5-96.5Q749-81 787-81Z M1154 200L1154-522L1282-522L1282-436L1286-436Q1300-481 1339-507.5Q1378-534 1430-534Q1530-534 1582.5-463.5Q1635-393 1635-262Q1635-130 1582.5-59Q1530 12 1430 12Q1378 12 1339.5-15Q1301-42 1286-87L1282-87L1282 200L1154 200ZM1389-94Q1439-94 1470-127Q1501-160 1501-216L1501-306Q1501-362 1470-395.5Q1439-429 1389-429Q1343-429 1312.5-406Q1282-383 1282-345L1282-179Q1282-138 1312.5-116Q1343-94 1389-94Z M1734 0L1734-740L1862-740L1862-294L1867-294L1936-388L2053-522L2198-522L2018-320L2217 0L2065 0L1931-234L1862-159L1862 0L1734 0Z M2730 0L2659 0Q2617 0 2592.5-24.5Q2568-49 2562-90L2556-90Q2543-39 2503-13.5Q2463 12 2404 12Q2324 12 2281-30Q2238-72 2238-142Q2238-223 2296-262.5Q2354-302 2461-302L2550-302L2550-340Q2550-384 2527-408Q2504-432 2453-432Q2408-432 2380.5-412.5Q2353-393 2334-366L2258-434Q2287-479 2335-506.5Q2383-534 2462-534Q2568-534 2623-486Q2678-438 2678-348L2678-102L2730-102L2730 0ZM2447-81Q2490-81 2520-100Q2550-119 2550-156L2550-225L2468-225Q2368-225 2368-161L2368-144Q2368-112 2388.5-96.5Q2409-81 2447-81Z M2942 0L2814 0L2814-522L2942-522L2942-435L2947-435Q2963-477 2997.5-505.5Q3032-534 3093-534Q3174-534 3217-481Q3260-428 3260-330L3260 0L3132 0L3132-317Q3132-373 3112-401Q3092-429 3046-429Q3026-429 3007.5-423.5Q2989-418 2974.5-407.5Q2960-397 2951-381.5Q2942-366 2942-345L2942 0Z"/></svg>',
    shield:       P + '<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>',
    "shield-check": P + '<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    "shield-alert": P + '<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M12 8v4"/><circle cx="12" cy="15.5" r=".6" fill="currentColor"/></svg>',
    alert:        P + '<path d="M10.3 4.3 2.8 17a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><circle cx="12" cy="16.5" r=".6" fill="currentColor"/></svg>',
    activity:     P + '<path d="M3 12h4l3 8 4-16 3 8h4"/></svg>',
    ban:          P + '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>',
    server:       P + '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><circle cx="7" cy="7.5" r=".7" fill="currentColor"/><circle cx="7" cy="16.5" r=".7" fill="currentColor"/></svg>',
    layers:       P + '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>',
    chart:        P + '<path d="M4 4v16h16"/><rect x="7" y="11" width="3" height="6"/><rect x="12" y="7" width="3" height="10"/><rect x="17" y="13" width="3" height="4"/></svg>',
    settings:     P + '<circle cx="12" cy="12" r="3"/><path d="M19.4 13a7.9 7.9 0 0 0 0-2l1.7-1.3-1.7-3-2 .8a7.6 7.6 0 0 0-1.7-1l-.3-2.2H9.6l-.3 2.2a7.6 7.6 0 0 0-1.7 1l-2-.8-1.7 3L5.6 11a7.9 7.9 0 0 0 0 2l-1.7 1.3 1.7 3 2-.8c.5.4 1.1.8 1.7 1l.3 2.2h4.1l.3-2.2c.6-.2 1.2-.6 1.7-1l2 .8 1.7-3z"/></svg>',
    check:        P + '<path d="M5 12.5l4.5 4.5L19 6.5"/></svg>',
    "check-sm":   P + '<path d="M4 12l5 5L20 6"/></svg>',
    x:            P + '<path d="M6 6l12 12M18 6L6 18"/></svg>',
    "chevron-right": P + '<path d="M9 6l6 6-6 6"/></svg>',
    "chevron-down":  P + '<path d="M6 9l6 6 6-6"/></svg>',
    "arrow-down": P + '<path d="M12 5v14M6 13l6 6 6-6"/></svg>',  /* incoming */
    "arrow-up":   P + '<path d="M12 19V5M6 11l6-6 6 6"/></svg>',  /* outgoing */
    eye:          P + '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
    edit:         P + '<path d="M4 20h4L18.5 9.5a2 2 0 0 0-2.8-2.8L5 17z"/><path d="M13.5 6.5l4 4"/></svg>',
    refresh:      P + '<path d="M20 11a8 8 0 0 0-14-5L3 9"/><path d="M3 4v5h5"/><path d="M4 13a8 8 0 0 0 14 5l3-3"/><path d="M21 20v-5h-5"/></svg>',
    bell:         P + '<path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6z"/><path d="M10 20a2 2 0 0 0 4 0"/></svg>',
    zap:          F + '<path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>',          /* flowspec */
    divert:       P + '<path d="M4 7h6l4 10h6"/><path d="M18 4l3 3-3 3"/><path d="M4 17h4"/></svg>', /* reroute */
    slash:        P + '<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/></svg>',  /* blackhole */
    /* dataplane: a NIC/silicon die with pins. Deliberately unlike zap (flowspec)
       and divert, which both mean "a router elsewhere does the work" — this one
       means the drop happens on this box, in the kernel, before the stack. */
    chip:         P + '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/></svg>',
    clock:        P + '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>',
    globe:        P + '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
    search:       P + '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>',
    play:         F + '<path d="M7 5l12 7-12 7z"/></svg>',
    stop:         F + '<rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
    info:         P + '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="8" r=".7" fill="currentColor"/></svg>',
    target:       P + '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/></svg>',
    flame:        F + '<path d="M12 2c1 4 5 5 5 9a5 5 0 0 1-10 0c0-2 1-3 2-4 .5 1 1 1.5 2 1.5C12 7 11 5 12 2z"/></svg>',
    database:     P + '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
    sliders:      P + '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h7M15 18h5"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="13" cy="18" r="2"/></svg>',
    menu:         P + '<path d="M4 7h16M4 12h16M4 17h16"/></svg>',
    "external":   P + '<path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M19 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"/></svg>',
    history:      P + '<path d="M3 4v5h5"/><path d="M3.5 9a8 8 0 1 1-1 5"/><path d="M12 8v4l3 2"/></svg>',
    lock:         P + '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    plus:         P + '<path d="M12 5v14M5 12h14"/></svg>',
    minus:        P + '<path d="M5 12h14"/></svg>',
    up:           P + '<path d="M5 15l7-7 7 7"/></svg>',
    dot:          F + '<circle cx="12" cy="12" r="4"/></svg>'
  };

  function icon(name, extraClass) {
    var span = document.createElement("span");
    span.className = "ico-wrap" + (extraClass ? " " + extraClass : "");
    span.style.display = "inline-flex";
    span.innerHTML = ICONS[name] || ICONS.dot;   // trusted constant only
    var svg = span.firstChild;
    return svg;   // return the <svg> node directly
  }

  w.ICONS = ICONS;
  w.icon = icon;
})(window);
