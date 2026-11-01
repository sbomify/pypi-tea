// Page tools: copy buttons (a string, or the page's Markdown twin fetched on
// click) and the More menu. No build step; loaded on pages with a Markdown twin.
(function () {
  "use strict";
  var status = document.querySelector("[data-copy-status]");

  // Copy a string, or a promise of one. ClipboardItem with a promise keeps the
  // click's user activation in Safari while the Markdown is fetched.
  function copy(text) {
    if (typeof text !== "string" && window.ClipboardItem && navigator.clipboard.write) {
      var blob = text.then(function (t) {
        return new Blob([t], { type: "text/plain" });
      });
      return navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]);
    }
    return Promise.resolve(text).then(function (t) {
      return navigator.clipboard.writeText(t);
    });
  }

  function confirm(button, ok) {
    if (status) status.textContent = ok ? button.dataset.done || "Copied" : "Could not copy";
    var label = button.querySelector("span");
    button.classList.add(ok ? "is-done" : "is-failed");
    if (label) {
      var before = label.textContent;
      label.textContent = ok ? "Copied" : "Could not copy";
      setTimeout(function () {
        label.textContent = before;
      }, 1600);
    }
    setTimeout(function () {
      button.classList.remove("is-done", "is-failed");
    }, 1600);
  }

  document.addEventListener("click", function (ev) {
    var button = ev.target.closest && ev.target.closest("[data-copy-text], [data-copy-url]");
    if (!button) return;
    var text = button.dataset.copyText
      ? button.dataset.copyText
      : fetch(button.dataset.copyUrl).then(function (r) {
          if (!r.ok) throw new Error(r.status);
          return r.text();
        });
    copy(text).then(
      function () {
        confirm(button, true);
      },
      function () {
        confirm(button, false);
      }
    );
    var menu = button.closest("details");
    if (menu) menu.removeAttribute("open");
  });

  // More menu: close on outside click and on Escape.
  var menus = document.querySelectorAll("details.more-menu");
  document.addEventListener("click", function (ev) {
    menus.forEach(function (m) {
      if (m.open && !m.contains(ev.target)) m.open = false;
    });
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    menus.forEach(function (m) {
      if (m.open) {
        m.open = false;
        var summary = m.querySelector("summary");
        if (summary) summary.focus();
      }
    });
  });
})();
