"""C1.1 CSP Part 1: no first-party inline scripts or handlers may return.

Mirrors Starter's sensitivity-tested template guard: the production policy is
script-src 'self', so every script must be a /static file and every former
on*= handler must stay a delegated data-* listener.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_COMMENT = re.compile(r"<!--.*?-->|\{#.*?#\}", re.S)
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.I)
_HANDLER = re.compile(r"\son[a-z]+\s*=", re.I)
_STATIC_JS_REF = re.compile(r"""src=['"](/static/[^'"?]+\.js)(?:\?[^'"]*)?['"]""")


def _strip_comments(text: str) -> str:
    return _COMMENT.sub("", text)


def find_inline_scripts(html: str) -> list[str]:
    return [tag for tag in _SCRIPT_TAG.findall(_strip_comments(html)) if "src=" not in tag.lower()]


def find_inline_handlers(html: str) -> list[str]:
    return _HANDLER.findall(_strip_comments(html))


def find_inline_python_scripts(source: str) -> list[str]:
    return [tag for tag in _SCRIPT_TAG.findall(source) if "src=" not in tag.lower()]


def test_templates_have_no_inline_scripts_or_handlers() -> None:
    offenders: dict[str, list[str]] = {}
    for path in sorted((ROOT / "templates").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        found = find_inline_scripts(text) + find_inline_handlers(text)
        if found:
            offenders[str(path.relative_to(ROOT))] = found
    assert offenders == {}


def test_python_sources_have_no_inline_script_literals() -> None:
    offenders: dict[str, list[str]] = {}
    for path in sorted((ROOT / "app").rglob("*.py")):
        found = find_inline_python_scripts(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(ROOT))] = found
    assert offenders == {}


def test_every_referenced_static_script_exists() -> None:
    referenced: set[str] = set()
    for path in sorted((ROOT / "templates").rglob("*.html")):
        referenced.update(_STATIC_JS_REF.findall(path.read_text(encoding="utf-8")))
    lifecycle = (ROOT / "app" / "web" / "lifecycle.py").read_text(encoding="utf-8")
    referenced.update(_STATIC_JS_REF.findall(lifecycle))
    assert referenced  # the scan must actually see the externalized tags
    missing = sorted(ref for ref in referenced if not (ROOT / ref.lstrip("/")).is_file())
    assert missing == []


def test_guard_detectors_are_sensitive() -> None:
    assert find_inline_scripts("<script>alert(1)</script>")
    assert find_inline_scripts('<script type="text/javascript">alert(1)</script>')
    assert find_inline_handlers('<img src="x" onerror="hide()">')
    assert find_inline_handlers("<form onsubmit='return confirm(1)'>")
    assert find_inline_python_scripts('x = "<script>go()</script>"')
    # And the detectors must not flag the compliant shapes.
    assert find_inline_scripts('<script src="/static/csrf.js?v=1"></script>') == []
    assert find_inline_handlers('<img src="x" data-hide-on-error>') == []
    assert find_inline_python_scripts('x = "<script src=\'/static/csrf.js\'></script>"') == []
