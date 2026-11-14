"""Run private synthetic contracts without publishing source, names or tracebacks."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import resource
import types
import unittest
from pathlib import Path


class Discard:
    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        pass


class SafeResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.safe_diagnostics = []

    def record(self, err):
        categories = {"test_reader_composition.py": 1, "reader_server.py": 2,
                      "consume-handoff.py": 3, "idp-create-operator.py": 4}
        frames = []
        trace = err[2]
        while trace is not None and len(frames) < 32:
            category = categories.get(Path(trace.tb_frame.f_code.co_filename).name)
            if category is not None:
                frames.append([category, trace.tb_lineno])
            trace = trace.tb_next
        allowed = {"AssertionError", "ValueError", "RuntimeError", "NameError", "AttributeError",
                   "TypeError", "FileNotFoundError", "KeyError"}
        kind = err[0].__name__
        self.safe_diagnostics.append({"case": self.testsRun, "kind": kind if kind in allowed else "Other",
                                      "frames": frames})

    def addError(self, test, err):
        self.record(err)
        self.errors.append((None, None))

    def addFailure(self, test, err):
        self.record(err)
        self.failures.append((None, None))

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.record(err)
            self.failures.append((None, None))


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    directory = parser.parse_args().directory
    if not (os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true"):
        return 1
    module = types.ModuleType("private_reader_synthetic_contracts")
    module.__file__ = str(directory / "test_reader_composition.py")
    result = SafeResult()
    with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
        source = Path(module.__file__).read_bytes()
        exec(compile(source, module.__file__, "exec"), module.__dict__)  # noqa: S102 - pinned private synthetic tests
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        suite.run(result)
    evidence = {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                "skipped": len(result.skipped), "private_contents_rendered": False,
                "diagnostics": result.safe_diagnostics}
    print(json.dumps(evidence, sort_keys=True))
    passed = (result.testsRun == 18 and result.wasSuccessful() and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        status = main()
    except BaseException:
        print("Private composition qualification failed; contents withheld.")
        status = 1
    raise SystemExit(status)
