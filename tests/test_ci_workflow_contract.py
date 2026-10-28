"""Contracts for the hosted CI service; guard execution uses fake Docker only."""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
IMAGE_EXPRESSION = "${{ vars.ACADEMY_RETAINED_PG_IMAGE }}"
IMAGE_PATTERN = r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$"
DIGEST_IMAGE = "docker.io/library/postgres@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


@pytest.fixture
def ci_job():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["test"]


@pytest.fixture
def run_image_guard(ci_job, tmp_path):
    guard = ci_job["steps"][0]
    assert guard["name"] == "Verify immutable PostgreSQL service image"
    assert guard["shell"] == "bash"
    assert guard["env"] == {
        "IMAGE": IMAGE_EXPRESSION,
        "SERVICE_CONTAINER_ID": "${{ job.services.db.id }}",
    }
    invocation_log = tmp_path / "invocations"
    fake_docker = tmp_path / "docker"
    fake_docker.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
if [ "$1" = "$FAKE_DOCKER_FAIL_COMMAND" ]; then
    exit 23
fi
case "$*" in
    "inspect service-container --format {{.Image}}")
        printf '%s\\n' "$FAKE_SERVICE_IMAGE_ID" ;;
    "image inspect $IMAGE --format {{.Id}}")
        printf '%s\\n' "$FAKE_DECLARED_IMAGE_ID" ;;
    *) exit 24 ;;
esac
"""
    )
    fake_docker.chmod(0o700)

    def run(image, *, service_id=IMAGE_ID, declared_id=IMAGE_ID, fail_command=""):
        # PATH contains only our fake. No real Docker executable can be resolved.
        result = subprocess.run(  # noqa: S603 -- source-controlled guard with isolated fake-only PATH
            ["/bin/bash", "-c", guard["run"]],
            env={
                "PATH": str(tmp_path),
                "IMAGE": image,
                "SERVICE_CONTAINER_ID": "service-container",
                "FAKE_DOCKER_LOG": str(invocation_log),
                "FAKE_SERVICE_IMAGE_ID": service_id,
                "FAKE_DECLARED_IMAGE_ID": declared_id,
                "FAKE_DOCKER_FAIL_COMMAND": fail_command,
            },
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        calls = invocation_log.read_text().splitlines() if invocation_log.exists() else []
        return result, calls

    return run


def test_service_and_bindings_use_the_same_immutable_image_declaration(ci_job):
    assert ci_job["services"]["db"]["image"] == IMAGE_EXPRESSION
    assert ci_job["env"]["ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE"] == IMAGE_EXPRESSION
    for service in ci_job["services"].values():
        image = service["image"]
        assert image == IMAGE_EXPRESSION or re.fullmatch(IMAGE_PATTERN, image)


@pytest.mark.parametrize(
    "image",
    ["", "postgres:16", "postgres@sha256:", "postgres@sha256:" + "A" * 64, "postgres:16@sha256:" + "a" * 64],
)
def test_image_guard_refuses_invalid_declarations_before_inspection(run_image_guard, image):
    result, calls = run_image_guard(image)
    assert result.returncode != 0
    assert calls == []


def test_image_guard_accepts_matching_image_ids_without_printing_them(run_image_guard):
    result, calls = run_image_guard(DIGEST_IMAGE)
    assert result.returncode == 0, result.stderr
    # The fake refuses any request beyond these two narrowly formatted fields.
    assert len(calls) == 2
    assert result.stdout == result.stderr == ""


@pytest.mark.parametrize(
    ("service_id", "declared_id"),
    [(IMAGE_ID, "sha256:" + "c" * 64), ("", IMAGE_ID), (IMAGE_ID, ""), ("", "")],
)
def test_image_guard_refuses_mismatching_or_empty_ids(run_image_guard, service_id, declared_id):
    result, calls = run_image_guard(DIGEST_IMAGE, service_id=service_id, declared_id=declared_id)
    assert result.returncode != 0
    assert len(calls) == 2
    assert IMAGE_ID not in result.stdout + result.stderr


@pytest.mark.parametrize(("fail_command", "expected_calls"), [("inspect", 1), ("image", 2)])
def test_image_guard_refuses_failed_inspections(run_image_guard, fail_command, expected_calls):
    result, calls = run_image_guard(DIGEST_IMAGE, fail_command=fail_command)
    assert result.returncode != 0
    assert len(calls) == expected_calls


def test_bootstrap_declaration_and_lint_gates_run_unless_cancelled(ci_job):
    steps = {step.get("name"): step for step in ci_job["steps"]}
    for name in (
        "Bootstrap DB roles",
        "Bootstrap outbox dispatcher roles",
        "Bootstrap isolated Kernel entry rehearsal database",
        "Declare hosted environment expectations before profile observation",
        "Lint (ruff)",
    ):
        assert steps[name]["if"] == "!cancelled()", name
