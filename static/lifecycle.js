(function () {
  function initializeRedirect(target) {
    var el = target && target.hasAttribute && target.hasAttribute('data-redirect-after') ? target : null;
    if (!el && target && target.querySelector) { el = target.querySelector('[data-redirect-after]'); }
    if (!el || el.hasAttribute('data-redirect-scheduled')) { return; }
    el.setAttribute('data-redirect-scheduled', 'true');
    setTimeout(function () {
      window.location.href = el.getAttribute('data-redirect-href');
    }, parseInt(el.getAttribute('data-redirect-after'), 10));
  }

  document.addEventListener('DOMContentLoaded', function () { initializeRedirect(document); });
  document.body.addEventListener('htmx:afterSwap', function (e) {
    // outerHTML leaves detail.target pointing at the detached original card.
    var root = e.target;
    if (!root || root.nodeType !== 1 || root.isConnected === false) { root = e.detail && e.detail.elt; }
    if (!root || root.nodeType !== 1 || root.isConnected === false) { root = document; }
    initializeRedirect(root);
  });
})();
