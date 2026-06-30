/* Dotmac Academy — chapter reading experience.
   Progressive enhancement for /courses/<slug>/chapters/<n>:
   in-page Table of Contents + scroll-spy, heading anchor links, figure
   lightbox, code copy-buttons, and a top scroll-progress bar.
   No dependencies; safe no-op if the expected nodes are absent. */
(function () {
  "use strict";
  var article = document.querySelector("article.prose");
  if (!article) return;

  function slugify(s) {
    return (s || "").toLowerCase().trim()
      .replace(/[^\w\s-]/g, "").replace(/\s+/g, "-").replace(/-+/g, "-").slice(0, 64) || "section";
  }

  /* --- heading ids + anchor links + ToC ------------------------------- */
  var headings = [].slice.call(article.querySelectorAll("h2, h3"));
  var used = {};
  headings.forEach(function (h) {
    if (!h.id) {
      var base = slugify(h.textContent);
      var id = base, i = 2;
      while (used[id] || document.getElementById(id)) { id = base + "-" + i++; }
      used[id] = true; h.id = id;
    }
    var a = document.createElement("a");
    a.href = "#" + h.id; a.className = "heading-anchor"; a.setAttribute("aria-hidden", "true");
    a.textContent = "#"; h.appendChild(a);
  });

  var tocNav = document.getElementById("chapter-toc");
  if (tocNav && headings.length > 2) {
    var ul = document.createElement("ul");
    headings.forEach(function (h) {
      var li = document.createElement("li");
      li.className = h.tagName === "H3" ? "toc-sub" : "toc-top";
      var link = document.createElement("a");
      link.href = "#" + h.id; link.textContent = h.textContent.replace(/#$/, "").trim();
      link.dataset.target = h.id;
      li.appendChild(link); ul.appendChild(li);
    });
    tocNav.appendChild(ul);

    /* scroll-spy: highlight the section currently in view */
    var links = {};
    [].forEach.call(tocNav.querySelectorAll("a"), function (l) { links[l.dataset.target] = l; });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          for (var k in links) links[k].classList.remove("active");
          if (links[e.target.id]) links[e.target.id].classList.add("active");
        }
      });
    }, { rootMargin: "-10% 0px -75% 0px", threshold: 0 });
    headings.forEach(function (h) { spy.observe(h); });
  } else if (tocNav) {
    tocNav.style.display = "none";
  }

  /* --- figure lightbox ------------------------------------------------- */
  var box = document.createElement("div");
  box.className = "lightbox"; box.setAttribute("aria-hidden", "true");
  box.innerHTML = '<img alt="">';
  document.body.appendChild(box);
  function closeBox() { box.classList.remove("open"); box.setAttribute("aria-hidden", "true"); }
  box.addEventListener("click", closeBox);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeBox(); });
  [].forEach.call(article.querySelectorAll("img"), function (img) {
    img.classList.add("zoomable");
    img.addEventListener("click", function () {
      box.querySelector("img").src = img.currentSrc || img.src;
      box.classList.add("open"); box.setAttribute("aria-hidden", "false");
    });
  });

  /* --- code copy buttons ---------------------------------------------- */
  [].forEach.call(article.querySelectorAll("pre"), function (pre) {
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "code-copy"; btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      var code = pre.querySelector("code") || pre;
      navigator.clipboard.writeText(code.innerText).then(function () {
        btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      }).catch(function () { btn.textContent = "Press Ctrl+C"; });
    });
    pre.style.position = "relative";
    pre.appendChild(btn);
  });

  /* --- scroll-progress bar -------------------------------------------- */
  var bar = document.getElementById("reading-progress");
  if (bar) {
    var tick = function () {
      var top = article.offsetTop;
      var h = article.offsetHeight - window.innerHeight + 120;
      var p = h > 0 ? Math.min(100, Math.max(0, ((window.scrollY - top) / h) * 100)) : 100;
      bar.style.width = p.toFixed(1) + "%";
    };
    window.addEventListener("scroll", tick, { passive: true });
    window.addEventListener("resize", tick); tick();
  }
})();
