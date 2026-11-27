#!/usr/bin/env python3
"""Self-test of compare-logs.py.

Usage: test-compare-logs.py

Writes small structured logs in the format of `mach test --log-raw`, runs
compare-logs.py on them, and checks outcomes and exit statuses.  The cases
are the ones a real run of the Thunderbird job does not produce as long as
all is well: the comparison must fail for them.  Needs only the Python
standard library.  The exit status is 0 only if every case behaves as
stated here.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
X = "comm/mail/extensions/openpgp/test/unit/rnp/"
B = "comm/mail/test/browser/openpgp/"


def start(test):
    return {"action": "test_start", "test": test}


def check(test, subtest, status="PASS", **more):
    return dict({"action": "test_status", "test": test, "subtest": subtest,
                 "status": status}, **more)


def end(test, status="PASS", **more):
    return dict({"action": "test_end", "test": test, "status": status}, **more)


def suite(name, *entries):
    return [{"action": "suite_start", "name": name, "tests": {}}] + list(entries) \
        + [{"action": "suite_end"}]


def good():
    """A run in which one test passes, one fails and one is skipped."""
    return suite("mochitest-browser",
                 start(B + "browser_a.js"), check(B + "browser_a.js", "one"),
                 end(B + "browser_a.js", "OK"),
                 start(B + "browser_b.js"),
                 check(B + "browser_b.js", "two", "FAIL", expected="PASS", message="no"),
                 end(B + "browser_b.js", "OK")) \
        + suite("xpcshell",
                start(X + "test_a.js"), end(X + "test_a.js", "PASS"),
                start(X + "test_skip.js"), end(X + "test_skip.js", "SKIP"))


GOOD_TABLE = [
    X + "test_a.js\tpass\tpass",
    X + "test_skip.js\tskip\tskip",
    B + "browser_a.js\tpass\tpass",
    B + "browser_b.js\tfail\tfail",
]

failures = []


def run(name, control, octopus, table, want_status, want_lines=()):
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for label, entries in (("control", control), ("octopus", octopus)):
            paths[label] = os.path.join(tmp, label + ".log")
            with open(paths[label], "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(entry if isinstance(entry, str) else json.dumps(entry))
                    f.write("\n")
        command = [sys.executable, os.path.join(HERE, "compare-logs.py"),
                   "--control", paths["control"], "--octopus", paths["octopus"],
                   "--results", os.path.join(tmp, "results.tsv")]
        if table is not None:
            expected = os.path.join(tmp, "expected.tsv")
            with open(expected, "w", encoding="utf-8") as f:
                f.write("# a comment\n" + "\n".join(sorted(table)) + "\n")
            command += ["--expected", expected]
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              encoding="utf-8", check=False)
    problems = []
    if done.returncode != want_status:
        problems.append("exit status %d, wanted %d" % (done.returncode, want_status))
    for line in want_lines:
        if line not in done.stdout.splitlines():
            problems.append("missing line %r" % line)
    print("%s: %s" % (name, "ok" if not problems else "; ".join(problems)))
    if problems:
        print(done.stdout)
        failures.append(name)


run("a run that reproduces the table", good(), good(), GOOD_TABLE, 0,
    ["compare-logs: 4 tests, all as expected"])

run("a table that differs in one line", good(), good(),
    [l.replace("browser_b.js\tfail\tfail", "browser_b.js\tpass\tfail") for l in GOOD_TABLE], 1,
    ["+" + B + "browser_b.js\tfail\tfail"])

run("no table: outcomes are printed, nothing is judged", good(), good(), None, 0,
    [B + "browser_b.js\tfail\tfail"])

run("a crash that belongs to no test, outcomes as in the table",
    good(), good() + [{"action": "crash", "signature": "@ shutdown"}], GOOD_TABLE, 1,
    ["compare-logs: octopus: 1 crashes reported"])

run("a crash that belongs to no test, in the control",
    good() + [{"action": "crash", "signature": "@ shutdown"}], good(), GOOD_TABLE, 1,
    ["compare-logs: control: 1 crashes reported"])

run("a crash in a test",
    good(), good()[:2] + [{"action": "crash", "test": B + "browser_a.js", "signature": "@ x"}]
    + good()[2:], GOOD_TABLE, 1,
    [B + "browser_a.js\tpass\tfail", "compare-logs: octopus: 1 crashes reported"])

run("an error of the harness, outcomes as in the table",
    good(), good() + [{"action": "log", "level": "ERROR", "message": "application timed out"}],
    GOOD_TABLE, 1, ["compare-logs: octopus: 1 errors logged by the harness"])

run("a suite that does not end", good(), good()[:-1], GOOD_TABLE, 1,
    ["compare-logs: octopus: 2 suites started, 1 ended"])

run("a test that starts and never ends",
    good(), [e for e in good() if e != end(B + "browser_a.js", "OK")], GOOD_TABLE, 1,
    [B + "browser_a.js\tpass\tno-result"])

run("a test that is missing in one run",
    good(), [e for e in good() if e.get("test") != X + "test_a.js"], GOOD_TABLE, 1,
    [X + "test_a.js\tpass\tabsent"])

run("a suite that is missing in one run",
    good(), good()[:7], GOOD_TABLE, 1, [X + "test_a.js\tpass\tabsent"])

run("an empty log", good(), [], None, 1,
    ["compare-logs: a log without tests: control 4, octopus 0 test files"])

run("a test that ends with an unexpected status",
    good(), [end(X + "test_a.js", "FAIL", expected="PASS")
             if e == end(X + "test_a.js", "PASS") else e for e in good()], GOOD_TABLE, 1,
    [X + "test_a.js\tpass\tfail"])

run("a failed test that passes when the harness runs it again counts as passed",
    good(), good() + suite("xpcshell",
                           start(X + "test_a.js"),
                           end(X + "test_a.js", "FAIL", expected="PASS"),
                           start(X + "test_a.js"), end(X + "test_a.js", "PASS")),
    GOOD_TABLE, 0, [X + "test_a.js\tpass\tpass"])

run("an unexpected status that the test lists as a known intermittent is not a failure",
    good(), [check(B + "browser_a.js", "one", "FAIL", expected="PASS",
                   known_intermittent=["FAIL"])
             if e == check(B + "browser_a.js", "one") else e for e in good()],
    GOOD_TABLE, 0, [B + "browser_a.js\tpass\tpass"])

run("lines that are not JSON are counted and ignored",
    good(), good() + ["not json"], GOOD_TABLE, 0, ["compare-logs: 4 tests, all as expected"])

if failures:
    print("test-compare-logs: %d cases FAILED: %s" % (len(failures), ", ".join(failures)))
    sys.exit(1)
print("test-compare-logs: all cases behave as stated")
