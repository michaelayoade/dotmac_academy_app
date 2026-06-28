# LMS Gaps (feat/lms-gaps) — SDD progress ledger

Spec: docs/superpowers/specs/2026-06-28-lms-gaps-design.md (commit c9aa505)
Base: feat/lms-buildout @ ad5ec4e | Test DB: academy_gaps :5437

Build order (per-feature implementer + review):
- [x] F1 catalog + landing — complete (1d39fac, review clean; 34 tests, ruff+mypy clean)
- [x] F2 calendar/agenda — complete (58086bb, review clean; 21 tests, ruff+mypy clean)
- [x] F3 search — complete (00b78aa, review clean; 13 tests, ruff+mypy clean; minor: search input bg-white off-palette → final pass)
- [x] F4 audit viewer — complete (2803cbd, review clean; 13 tests, ruff+mypy clean)
- [ ] F5 notifications center
- [ ] F6 announcements
- [ ] F7 rich embeds
- [ ] F8 question types
- [ ] F9 weighted gradebook
- [ ] integration (suite + ruff/mypy + nav cross-check)
