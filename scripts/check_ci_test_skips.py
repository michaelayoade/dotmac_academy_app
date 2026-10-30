"""Refuse missing execution evidence and unreviewed skips in a CI JUnit report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


def verify(report: Path, allowlist: Path) -> None:
    allowed = [line.strip() for line in allowlist.read_text().splitlines() if line.strip() and not line.startswith("#")]
    if len(allowed) != len(set(allowed)) or any("::" not in name or "*" in name for name in allowed):
        raise ValueError("CI skip allowlist requires distinct exact testcase identities")
    try:
        root = ET.parse(report).getroot()
    except DefusedXmlException:
        raise ValueError("CI JUnit report contains forbidden XML declarations") from None
    cases = list(root.iter("testcase"))
    if not cases:
        raise ValueError("CI JUnit report contains no executed testcases")
    skipped = {
        case.attrib.get("classname", "") + "::" + case.attrib.get("name", "")
        for case in cases if case.find("skipped") is not None
    }
    if skipped != set(allowed):
        # Raw reasons and parametrized names can carry test input material.
        raise ValueError(
            f"CI skip declarations mismatch: unreviewed={len(skipped - set(allowed))}, "
            f"unused={len(set(allowed) - skipped)}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("allowlist", type=Path)
    args = parser.parse_args(argv)
    try:
        verify(args.report, args.allowlist)
    except (OSError, ValueError, ParseError):
        print("CI test skip evidence refused; review the retained JUnit report", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
