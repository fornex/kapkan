/* icons.js — inline SVG icon set. Trusted constants (no user data).
   Presentation attributes only (no style= attrs) so it is CSP style-src safe.
   Stroke icons inherit color via currentColor. */
(function (w) {
  "use strict";
  var P = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" class="ico" aria-hidden="true">';
  var F = '<svg viewBox="0 0 24 24" fill="currentColor" class="ico" aria-hidden="true">';
  var ICONS = {
    /* Brand tile mark — escalation-ramp motif. Intentionally multi-color
       (not currentColor); uses fill/stroke presentation attributes only, so
       it stays CSP style-src safe like the rest of this set. */
    brandmark:    '<svg viewBox="0 0 64 64" class="ico" aria-hidden="true">' +
      '<rect x="1" y="1" width="62" height="62" rx="15.4" fill="#141a21" stroke="#2a323d" stroke-width="1.5"/>' +
      '<rect x="40.32" y="15.36" width="6.82" height="6.82" rx="1.08" fill="#9cccff"/>' +
      '<rect x="32" y="23.68" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff"/>' +
      '<rect x="40.32" y="23.68" width="6.82" height="6.82" rx="1.08" fill="#9cccff"/>' +
      '<rect x="23.68" y="32" width="6.82" height="6.82" rx="1.08" fill="#3f8fe0"/>' +
      '<rect x="32" y="32" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff"/>' +
      '<rect x="40.32" y="32" width="6.82" height="6.82" rx="1.08" fill="#9cccff"/>' +
      '<rect x="15.36" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#2f6dab"/>' +
      '<rect x="23.68" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#3f8fe0"/>' +
      '<rect x="32" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff"/>' +
      '<rect x="40.32" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#9cccff"/></svg>',
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
