from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.web.context import nav_context

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
templates = Jinja2Templates(
    directory=str(_TEMPLATES_DIR), context_processors=[nav_context]
)
