"""Config-driven navigation: role areas + contextual sidebars.

`AREAS` is the ordered source of truth for the app shell's top-level area tabs
(Learn / Teaching / Admin) and each area's sidebar. Helpers map roles → visible
areas, a request path → its area, and an area → its sidebar items.
"""

from __future__ import annotations

# Ordered top-level areas. `required` gates visibility:
#   None        → always visible (Learn)
#   "instructor"→ instructor OR admin
#   "admin"     → admin only
AREAS: list[dict] = [
    {
        "key": "learn",
        "label": "Learn",
        "home": "/",
        "required": None,
        "sidebar": [
            {"label": "Home", "path": "/"},
            {"label": "Progress", "path": "/progress"},
        ],
    },
    {
        "key": "teaching",
        "label": "Teaching",
        "home": "/instructor",
        "required": "instructor",
        "sidebar": [
            {"label": "Home", "path": "/instructor"},
            {"label": "Cohorts", "path": "/instructor/cohorts"},
            {"label": "Reports", "path": "/instructor/reports"},
            {"label": "Lab monitor", "path": "/instructor/labs"},
        ],
    },
    {
        "key": "admin",
        "label": "Admin",
        "home": "/admin",
        "required": "admin",
        "sidebar": [
            {"label": "Console", "path": "/admin"},
            {"label": "Users", "path": "/admin/users"},
            {"label": "Settings", "path": "/admin/settings"},
        ],
    },
]

_BY_KEY: dict[str, dict] = {a["key"]: a for a in AREAS}


def areas_for_roles(is_instructor: bool, is_admin: bool) -> list[dict]:
    """Return the areas visible to a person with the given role flags."""
    visible: list[dict] = []
    for area in AREAS:
        required = area["required"]
        if required is None:
            visible.append(area)
        elif required == "instructor" and (is_instructor or is_admin):
            visible.append(area)
        elif required == "admin" and is_admin:
            visible.append(area)
    return visible


def area_for_path(path: str) -> str:
    """Map a request path to its area key via prefix rules."""
    if path.startswith("/instructor") or path.startswith("/reports"):
        return "teaching"
    if path.startswith("/admin"):
        return "admin"
    return "learn"


def sidebar_for(area_key: str) -> list[dict]:
    """Return the sidebar items for an area, or an empty list if unknown."""
    area = _BY_KEY.get(area_key)
    return list(area["sidebar"]) if area else []
