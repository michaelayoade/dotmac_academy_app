"""README policy checks run with stdlib unittest, without platform packages."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.check_readme_update import validate_update


class ReadmePolicyTests(unittest.TestCase):
    def test_cli_checks_actual_git_changes(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/check_readme_update.py"
        with TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()  # noqa: S603,S607

            git("init", "-q")
            git("config", "user.name", "README policy fixture")
            git("config", "user.email", "readme-policy@example.test")
            (root / "README.md").write_text("Academy\n")
            git("add", ".")
            git("commit", "-qm", "Fixture baseline")
            base = git("rev-parse", "HEAD")
            (root / "app").mkdir()
            (root / "app/feature.py").write_text("# New feature\n")
            git("add", ".")
            git("commit", "-qm", "Fixture feature")

            def check() -> subprocess.CompletedProcess[str]:
                return subprocess.run(  # noqa: S603 - fixed Python/script, disposable Git fixture
                    [sys.executable, str(script), "--base", base, "--head", git("rev-parse", "HEAD")],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual(check().returncode, 1)
            (root / "README.md").write_text("Academy now includes the feature.\n")
            git("add", ".")
            git("commit", "-qm", "Fixture documentation")
            self.assertEqual(check().returncode, 0)
            git("rm", "README.md")
            git("commit", "-qm", "Fixture README deletion")
            self.assertEqual(check().returncode, 1)

    def test_feature_without_readme_fails(self) -> None:
        self.assertFalse(validate_update(paths=("app/web/example.py",), before="Old", after="Old"))

    def test_feature_with_meaningful_readme_passes(self) -> None:
        self.assertTrue(validate_update(paths=("templates/page.html", "README.md"), before="Old", after="New feature"))

    def test_whitespace_and_empty_readme_fail(self) -> None:
        for after in (" Old \n", ""):
            with self.subTest(after=after):
                self.assertFalse(validate_update(paths=("static/main.js", "README.md"), before="Old", after=after))

    def test_docs_tests_and_workflow_only_changes_pass(self) -> None:
        self.assertTrue(
            validate_update(paths=("docs/a.md", "tests/a.py", ".github/workflows/ci.yml"), before="", after="")
        )

    def test_all_runtime_surfaces_are_covered(self) -> None:
        for path in ("content/course.md", "alembic/a.py", "deploy/app.service", "scripts/run.py", "poetry.lock"):
            with self.subTest(path=path):
                self.assertFalse(validate_update(paths=(path,), before="Old", after="Old"))


if __name__ == "__main__":
    unittest.main()
