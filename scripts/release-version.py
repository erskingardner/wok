#!/usr/bin/env python3
"""Validate a SemVer release version and print its prerelease classification."""
import re
import sys

CORE = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = r"[0-9A-Za-z-]+"
VERSION = re.compile(
    rf"{CORE}\.{CORE}\.{CORE}"
    rf"(?:-(?P<prerelease>{IDENTIFIER}(?:\.{IDENTIFIER})*))?"
    rf"(?:\+(?P<build>{IDENTIFIER}(?:\.{IDENTIFIER})*))?\Z"
)


def is_prerelease(version):
    match = VERSION.fullmatch(version)
    if match is None:
        raise ValueError(f"version must be SemVer MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD], got: {version!r}")
    prerelease = match.group("prerelease")
    if prerelease and any(part.isdigit() and len(part) > 1 and part.startswith("0")
                          for part in prerelease.split(".")):
        raise ValueError("numeric prerelease identifiers must not have leading zeroes")
    return prerelease is not None


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: release-version.py VERSION")
        print(str(is_prerelease(sys.argv[1])).lower())
    except ValueError as error:
        raise SystemExit(str(error))
