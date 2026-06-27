"""Check engine: dispatch checks to primitives and aggregate a weighted score."""

from __future__ import annotations

from .primitives import eval_command, eval_config_grep, eval_probe

_EVAL = {
    "command": eval_command,
    "probe": eval_probe,
    "config_grep": eval_config_grep,
}


def eval_check(check, engine, handle, seed):
    """Evaluate one check -> ``{id, weight, pass, actual, expected}``."""
    out = _EVAL[check["type"]](check, engine, handle, seed)
    return {"id": check["id"], "weight": check.get("weight", 1), **out}


def run_checks(checks, engine, handle, seed):
    """Evaluate all checks -> ``{score, max_score, per_check}`` (weighted).

    ``score`` = sum of weights of passing checks; ``max_score`` = sum of all
    weights; ``per_check`` = list of :func:`eval_check` results in order.
    """
    per = [eval_check(c, engine, handle, seed) for c in checks]
    max_score = sum(c.get("weight", 1) for c in checks)
    score = sum(r["weight"] for r in per if r["pass"])
    return {"score": score, "max_score": max_score, "per_check": per}
