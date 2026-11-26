#!/usr/bin/env python3
"""Compare the cells of a sequoia-probe run with the expected cells.

Usage: check-cells.py <expected-cells.txt> <probe output>

A cell is "group | operation | status". The detail column of the probe's
output is not compared: it holds fingerprints, sizes and timings that
differ from run to run. Lines starting with "#" are comments in both
files. The exit status is 0 only if both files have the same cells in
the same order; otherwise the differences are printed as a unified diff
(lines with "-" are expected and missing, lines with "+" are new).
"""
import difflib
import sys


def cells(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(" | ", 3)
            if len(parts) < 3:
                raise SystemExit("%s: not a cell: %r" % (path, line))
            out.append(" | ".join(parts[:3]))
    return out


expected, got = cells(sys.argv[1]), cells(sys.argv[2])
if not expected:
    raise SystemExit("%s: no cells" % sys.argv[1])
diff = list(difflib.unified_diff(expected, got, "expected", "this run", lineterm="", n=0))
if diff:
    print("\n".join(diff))
    print("check-cells: %d expected cells, %d cells in this run: DIFFERENT" % (len(expected), len(got)))
    sys.exit(1)
print("check-cells: %d cells, all as expected" % len(got))
