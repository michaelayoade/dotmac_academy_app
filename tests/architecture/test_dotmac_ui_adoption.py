"""Ratchets for Academy's adoption of the shared presentation contract.

The package dependency alone is not adoption. These checks pin all four seams:
the released artifact is served, every full page links it, Tailwind resolves the
installed preset, and Academy's product palette supplies the shared variables.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import dotmac_ui
from dotmac_ui import static_dir
from fastapi.testclient import TestClient

from app.assembly import assembly
from app.main import app
from app.ui import UI_ASSET_DIRECTORY, UI_ASSET_MOUNT, UI_STYLESHEET_URL

REPO_ROOT = Path(__file__).resolve().parents[2]
INPUT_CSS = REPO_ROOT / "src" / "input.css"
COMPILED_CSS = REPO_ROOT / "static" / "app.css"
RAMP_STEPS = (
    "50",
    "100",
    "200",
    "300",
    "400",
    "500",
    "600",
    "700",
    "800",
    "900",
    "950",
)


def _channels() -> dict[str, tuple[int, int, int]]:
    declarations = re.findall(
        r"--dmui-([a-z0-9-]+)-rgb:\s*(\d+)\s+(\d+)\s+(\d+);",
        INPUT_CSS.read_text(encoding="utf-8"),
    )
    return {name: (int(red), int(green), int(blue)) for name, red, green, blue in declarations}


def _hex(channels: tuple[int, int, int]) -> str:
    return "#" + "".join(f"{channel:02x}" for channel in channels)


def test_dependency_is_an_exact_pin_to_the_first_adoptable_release() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declaration = pyproject["tool"]["poetry"]["dependencies"]["dotmac-ui"]

    assert declaration == {"version": "0.1.0a3", "source": "forgejo"}
    assert dotmac_ui.__version__ == "0.1.0a3"
    assert dotmac_ui.UI_CONTRACT_VERSION == 1


def test_installed_compiled_asset_is_composed_below_academys_static_layer() -> None:
    assert UI_ASSET_DIRECTORY.is_dir()
    assert (UI_ASSET_DIRECTORY / "dotmac-ui-1.css").is_file()
    assert UI_STYLESHEET_URL.startswith(f"{UI_ASSET_MOUNT}/dotmac-ui-1.css?v=")
    assert assembly.packaged_static_dirs == (static_dir(),)
    assert assembly.stylesheets == (UI_STYLESHEET_URL,)
    assert TestClient(app).get(UI_STYLESHEET_URL).status_code == 200
    assert not (REPO_ROOT / "static" / "dotmac-ui").exists(), "serve the package; do not copy it"


def test_every_full_page_consumes_the_shared_head_and_light_theme_contract() -> None:
    full_pages = []
    for path in sorted((REPO_ROOT / "templates").rglob("*.html")):
        source = path.read_text(encoding="utf-8")
        if source.lstrip().lower().startswith("<!doctype html>"):
            full_pages.append(path)
            assert '{% include "_dotmac_ui_head.html" %}' in source, path
            assert "dotmac_ui_theme_attribute" in source, path
            assert "dotmac_ui_theme" in source, path
            local_css = re.search(r'href="/static/(?:app|public)\.css', source)
            assert local_css is not None, path
            assert source.index('{% include "_dotmac_ui_head.html" %}') < local_css.start()

    assert full_pages, "the guard is vacuous: no full-page templates found"

    lifecycle = (REPO_ROOT / "app" / "web" / "lifecycle.py").read_text(encoding="utf-8")
    assert "UI_STYLESHEET_URL" in lifecycle
    assert "UI_THEME_ATTRIBUTE" in lifecycle


def test_tailwind_consumes_the_installed_preset_without_a_copied_palette() -> None:
    config = (REPO_ROOT / "tailwind.config.js").read_text(encoding="utf-8")

    assert "dotmac_ui.tailwind_preset_path()" in config
    assert "presets: [dotmacUi]" in config
    assert "oklch(" not in config


def test_academy_supplies_complete_brand_accent_and_neutral_ramps() -> None:
    channels = _channels()
    for family in ("brand", "accent"):
        for step in RAMP_STEPS:
            assert f"color-{family}-{step}" in channels
    for step in RAMP_STEPS:
        assert f"color-semantic-neutral-{step}" in channels

    assert all(0 <= channel <= 255 for colour in channels.values() for channel in colour)


def test_academy_overrides_the_roles_it_uses_instead_of_leaking_generic_values() -> None:
    source = INPUT_CSS.read_text(encoding="utf-8")
    role_values = {
        "surface-background": "color-semantic-neutral-100",
        "surface-primary": "color-semantic-neutral-50",
        "surface-secondary": "color-semantic-neutral-200",
        "text-primary": "color-semantic-neutral-900",
        "text-secondary": "color-semantic-neutral-700",
        "border-default": "color-semantic-neutral-300",
        "border-strong": "color-semantic-neutral-600",
        "action-primary-default": "color-brand-700",
        "action-primary-hover": "color-brand-800",
        "action-primary-pressed": "color-brand-900",
        "action-accent-default": "color-accent-700",
        "action-accent-hover": "color-accent-800",
        "action-accent-pressed": "color-accent-900",
    }
    for role, value in role_values.items():
        assert f"--dmui-{role}: var(--dmui-{value});" in source
        assert f"--dmui-{role}-rgb: var(--dmui-{value}-rgb);" in source


def test_product_roles_keep_the_accessibility_pairs_they_claim() -> None:
    channels = _channels()
    neutral_50 = _hex(channels["color-semantic-neutral-50"])
    neutral_100 = _hex(channels["color-semantic-neutral-100"])

    text_pairs = (
        ("color-semantic-neutral-900", neutral_50),
        ("color-semantic-neutral-700", neutral_50),
        ("color-brand-700", neutral_50),
        ("color-brand-800", neutral_50),
        ("color-brand-900", neutral_50),
        ("color-accent-700", neutral_50),
        ("color-accent-800", neutral_50),
        ("color-accent-900", neutral_50),
    )
    for foreground, background in text_pairs:
        ratio = dotmac_ui.contrast_ratio(_hex(channels[foreground]), background)
        assert ratio >= dotmac_ui.TEXT_CONTRAST_MINIMUM, (foreground, ratio)

    non_text_pairs = (
        ("color-brand-600", neutral_100),  # focus ring on the page canvas
        ("color-semantic-neutral-600", neutral_50),  # strong control boundary
    )
    for foreground, background in non_text_pairs:
        ratio = dotmac_ui.contrast_ratio(_hex(channels[foreground]), background)
        assert ratio >= dotmac_ui.NON_TEXT_CONTRAST_MINIMUM, (foreground, ratio)


def test_compiled_css_uses_channel_variables_and_covers_the_completed_aliases() -> None:
    css = COMPILED_CSS.read_text(encoding="utf-8")

    assert "rgb(var(--dmui-color-brand-900-rgb)/.35)" in css
    assert ".bg-clay-50{" in css
    assert ".bg-clay-100{" in css
    assert ".text-clay-700{" in css
