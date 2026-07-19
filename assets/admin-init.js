// Admin page bootstrap. Served same-origin at /assets/admin-init.js.
//
// Moved out of an inline <script> so the admin plane can ship a real CSP:
// an inline script requires script-src 'unsafe-inline', which would leave
// script execution effectively unrestricted — exactly the hole this closes.

// Defense in depth against htmx-swapped markup executing script. htmx defaults
// allowScriptTags:true and allowEval:true, and every admin fragment is swapped
// with innerHTML, so any HTML reaching a swap target could otherwise run.
// The admin UI uses only plain hx-get/post/swap/trigger/target -- no `js:`
// values, no hx-on -- so both features are dead weight here and are turned off.
// CSP is the outer wall; this is the inner one.
if (window.htmx && window.htmx.config) {
  window.htmx.config.allowScriptTags = false;
  window.htmx.config.allowEval = false;
}

window.addEventListener("DOMContentLoaded", function () {
  var nodes = document.querySelectorAll("[data-fiducia-sync]");
  if (!nodes.length || !window.FiduciaSyncAdmin) return;
  var tables = [];
  nodes.forEach(function (n) {
    (n.getAttribute("data-fiducia-sync") || "").split(",").forEach(function (t) {
      t = t.trim(); if (t && tables.indexOf(t) === -1) tables.push(t);
    });
  });
  if (!tables.length) return;
  var csrf = document.querySelector('meta[name="fiducia-admin-csrf"]');
  window.FiduciaSyncAdmin.init({
    tables: tables,
    htmx: window.htmx,
    csrfToken: csrf ? csrf.content : ""
  }).then(function (sync) {
    window.__fiduciaSync = sync; // exposed for debugging / future optimistic writes
  }).catch(function (e) { console.error("fiducia-sync init failed", e); });
});
