#!/usr/bin/env bash
# Production dependency install for dotmac_academy_app.
#
# Run as the `dotmac` user, from the checkout root
# (/home/dotmac/projects/dotmac_academy_app — see the WorkingDirectory of
# every unit in this directory), before restarting academy-web and the
# systemd services/timers declared alongside this script.
#
# Why the executable is verified by VERSION, not addressed by PATH:
#
#   `poetry.lock` is only readable by the Poetry major that wrote it (2.x).
#   Two checked-in sources have described where that Poetry 2.4.1 lives on
#   the production host, and they disagree: the CI workflow's install-step
#   comment says a system-wide pipx install at /usr/local/bin
#   (PIPX_HOME=/opt/pipx); durable fleet records describe a per-user pipx
#   install for `dotmac` at /home/dotmac/.local/bin/poetry. Rather than pick
#   one and bake a host layout detail into this repository — which is what
#   produced the disagreement in the first place — this script trusts
#   whatever `poetry` the operator's PATH resolves and instead checks the
#   one thing that actually matters: that it reports exactly 2.4.1. A wrong
#   Poetry on PATH (e.g. the OS package, apt's 1.8.2) is exactly what
#   produced the 2026-08-10 production 502 — it cannot read this repo's
#   2.x lockfile and fails as "pyproject.toml changed significantly since
#   poetry.lock was last generated", which blames the repository for what
#   is really a toolchain mismatch. Refuse loudly here instead.
#
# Why `poetry sync --only main`, not `poetry install` or `--without dev`:
#
#   `--only main` names the complete, closed production dependency set.
#   `poetry install` (bare) and `poetry install --without dev` both instead
#   modify a *default* group selection — so a future non-optional Poetry
#   group would silently enter production under either of them without this
#   script changing at all. `--only main` has no such gap: a group is in
#   production because this line names it, not because it wasn't excluded.
#
#   `sync` rather than `install` because sync also removes any package that
#   is installed but no longer declared for the selected groups — so a host
#   venv that still carries dev-group packages from an earlier bare
#   `poetry install` converges to the production set instead of keeping
#   them around indefinitely.
#
# Do not "simplify" this to a bare `poetry install`: that reintroduces both
# gaps above (dev tooling in production, and silent adoption of a future
# non-optional group) and was not what production was found to be running.

set -euo pipefail

# Poetry resolves its target project by walking up from the current working
# directory, not from this script's location — so running this recipe from
# any cwd other than the checkout root (see the instruction at the top of
# this file) silently resolves a *different* project's pyproject.toml/.venv
# and `sync`s against it. Make the recipe independent of cwd by deriving the
# checkout root from the script's own path and moving there before doing
# anything else. Resolve symlinks so invoking through a symlinked path (e.g.
# a systemd unit that references a stable symlink to a release directory)
# still lands on the real checkout root.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "${SOURCE}" ]; do
  DIR="$(cd -P "$(dirname "${SOURCE}")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "${SOURCE}")"
  [[ ${SOURCE} != /* ]] && SOURCE="${DIR}/${SOURCE}"
done
SCRIPT_DIR="$(cd -P "$(dirname "${SOURCE}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$(cd -P "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${ROOT_DIR}"

REQUIRED_POETRY_VERSION="Poetry (version 2.4.1)"

if ! command -v poetry >/dev/null 2>&1; then
  echo "install.sh: no 'poetry' found on PATH. This script deliberately does" >&2
  echo "not hardcode a Poetry location (see comment above) — install Poetry" >&2
  echo "Poetry 2.4.1 and ensure it resolves on PATH for this user." >&2
  exit 1
fi

actual_poetry_version="$(poetry --version --no-ansi 2>/dev/null || true)"

if [ "${actual_poetry_version}" != "${REQUIRED_POETRY_VERSION}" ]; then
  echo "install.sh: PATH resolves ${actual_poetry_version:-an unknown Poetry version}, but this" >&2
  echo "repository's poetry.lock was written by Poetry 2.4.1 and is" >&2
  echo "only readable by that major/minor. A mismatched Poetry (e.g. the OS package)" >&2
  echo "reports the mismatch as 'pyproject.toml changed significantly since" >&2
  echo "poetry.lock was last generated' and blames the repository for a toolchain" >&2
  echo "problem — this is the exact failure mode behind the 2026-08-10 production" >&2
  echo "502. Refusing rather than proceeding. Install Poetry 2.4.1 and" >&2
  echo "put it first on this user's PATH." >&2
  exit 1
fi

# Every checked-in systemd unit executes this checkout's `.venv`. Do not let
# an operator's active environment or host-global Poetry configuration select
# a different target while this script appears to succeed. IN_PROJECT alone
# only says *where* the venv goes; it does nothing if host-global Poetry
# config (e.g. `~/.config/pypoetry/config.toml` setting
# `virtualenvs.create = false`, a common container/CI idiom that migrates
# onto hosts) has disabled venv creation entirely — in that case Poetry
# resolves the ambient interpreter instead, and because this is `sync` (not
# `install`) it uninstalls every package in that environment absent from
# this repository's `main` lock. CREATE=true forces venv creation regardless
# of host-global config, so IN_PROJECT's target is the one actually used.
unset VIRTUAL_ENV
export POETRY_VIRTUALENVS_CREATE=true
export POETRY_VIRTUALENVS_IN_PROJECT=true

poetry sync --only main --no-root --no-interaction --no-ansi
