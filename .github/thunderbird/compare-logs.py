#!/usr/bin/env python3
"""Compare two runs of Thunderbird's OpenPGP tests: Mozilla's librnp
(control) against the Octopus.

Usage: compare-logs.py --control <raw log> --octopus <raw log>
           [--results <results.tsv>] [--markdown <summary.md>]
           [--expected <expected-results.tsv>]

The inputs are the structured logs that `mach test --log-raw` writes (one
JSON object per line, mozlog format).  For every test file the script
derives one outcome per run:

  pass       the test ended and no result differed from what the test
             itself expects
  fail       the test ended, and its status or at least one of its checks
             was unexpected (this includes timeouts and crashes that the
             harness attributes to the test)
  skip       the harness skipped the test (a condition in its manifest)
  no-result  the test started and never ended
  absent     the test does not occur in this log

A test that the harness ran again (xpcshell retries a failed test once) is
judged by its last run; the number of runs is reported.

--results writes one line per test: path, control outcome, Octopus
outcome, separated by tabs, sorted by path.  --expected compares exactly
these lines with a recorded file (lines starting with "#" are comments) and
makes the exit status 1 if they differ; the differences are printed as a
unified diff ("-" expected and missing, "+" new).  No test is ever
excluded: a test that is expected to fail stays in the run and in the
table.  --markdown writes a summary with the checks that failed.

Independently of the table, the exit status is 1 if one of the logs

  * contains no test at all,
  * reports a crash, whether the harness attributes it to a test or not
    (a crash at startup or shutdown belongs to no test),
  * has a message of the harness at level ERROR or CRITICAL, or
  * has a suite that started and did not end.

The table records outcomes of test files only, so these would otherwise go
unnoticed: `mach test` exits with status 1 in every run in which a test
fails, which is why its exit status cannot be the criterion.
"""
import argparse
import collections
import difflib
import json
import sys

MAX_DETAILS = 15
MAX_MESSAGE = 300


class Test:
    def __init__(self):
        self.runs = 0
        self.reset()

    def reset(self):
        self.status = None
        self.unexpected_end = None
        self.checks = 0
        self.unexpected = []


def normalize(test):
    test = str(test)
    for marker in ("comm/mail/", "comm/mailnews/"):
        at = test.find(marker)
        if at > 0:
            return test[at:]
    return test


def is_unexpected(entry):
    if "expected" not in entry:
        return False
    return entry.get("status") not in entry.get("known_intermittent", [])


def first_line(text):
    text = str(text or "").strip().splitlines()
    text = text[0] if text else ""
    return text if len(text) <= MAX_MESSAGE else text[:MAX_MESSAGE] + "..."


def read(path):
    tests = collections.OrderedDict()
    info = {"suites": [], "suites_ended": 0, "crashes": [], "errors": [],
            "lines": 0, "bad_lines": 0}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            info["lines"] += 1
            try:
                entry = json.loads(line)
            except ValueError:
                info["bad_lines"] += 1
                continue
            if not isinstance(entry, dict):
                info["bad_lines"] += 1
                continue
            action = entry.get("action")
            if action == "suite_start":
                info["suites"].append(entry.get("name") or entry.get("source") or "?")
            elif action == "suite_end":
                info["suites_ended"] += 1
            elif action == "crash":
                info["crashes"].append("%s: %s" % (entry.get("test") or "no test",
                                                   first_line(entry.get("signature"))))
                if entry.get("test"):
                    t = tests.setdefault(normalize(entry["test"]), Test())
                    t.unexpected.append(("crash", "CRASH", first_line(entry.get("signature"))))
            elif action == "log":
                if entry.get("level") in ("ERROR", "CRITICAL"):
                    info["errors"].append(first_line(entry.get("message")))
            elif action == "test_start":
                t = tests.setdefault(normalize(entry["test"]), Test())
                t.reset()
                t.runs += 1
            elif action == "test_status":
                t = tests.setdefault(normalize(entry["test"]), Test())
                t.checks += 1
                if is_unexpected(entry):
                    t.unexpected.append((first_line(entry.get("subtest")),
                                         entry.get("status"),
                                         first_line(entry.get("message"))))
            elif action == "test_end":
                t = tests.setdefault(normalize(entry["test"]), Test())
                t.status = entry.get("status")
                if is_unexpected(entry):
                    t.unexpected_end = (entry.get("status"), entry.get("expected"),
                                        first_line(entry.get("message")))
    return tests, info


def outcome(t):
    if t is None:
        return "absent"
    if t.status is None:
        return "no-result"
    if t.status == "SKIP":
        return "skip"
    if t.unexpected_end or t.unexpected:
        return "fail"
    return "pass"


def detail(t):
    """Describe a run of a test in a few words."""
    if t is None:
        return ""
    parts = []
    if t.unexpected_end:
        parts.append("ended %s, expected %s" % t.unexpected_end[:2])
    if t.unexpected:
        parts.append("%d of %d checks unexpected" % (len(t.unexpected), t.checks))
    elif t.status not in (None, "SKIP"):
        parts.append("%d checks" % t.checks)
    if t.runs > 1:
        parts.append("%d runs" % t.runs)
    return ", ".join(parts)


def escape(text):
    return str(text).replace("|", "\\|").replace("`", "'")


def markdown(control, octopus, cinfo, oinfo, names):
    out = ["## Thunderbird OpenPGP tests: Mozilla's librnp against the Octopus", ""]
    out += ["| Outcome | Mozilla's librnp (control) | Octopus |", "|---|---|---|"]
    for kind in ("pass", "fail", "skip", "no-result", "absent"):
        c = sum(1 for n in names if outcome(control.get(n)) == kind)
        o = sum(1 for n in names if outcome(octopus.get(n)) == kind)
        out.append("| %s | %d | %d |" % (kind, c, o))
    out.append("| test files | %d | %d |" % (len(control), len(octopus)))
    out.append("| crashes reported | %d | %d |"
               % (len(cinfo["crashes"]), len(oinfo["crashes"])))
    out.append("| suites started and ended | %d and %d | %d and %d |"
               % (len(cinfo["suites"]), cinfo["suites_ended"],
                  len(oinfo["suites"]), oinfo["suites_ended"]))
    out.append("| errors logged by the harness | %d | %d |"
               % (len(cinfo["errors"]), len(oinfo["errors"])))
    out.append("")

    different = [n for n in names
                 if any(outcome(run.get(n)) != "pass" or run[n].runs > 1
                        for run in (control, octopus))]
    if different:
        out += ["### Tests that did not pass in both runs at the first attempt", "",
                "| Test | Control | Octopus |", "|---|---|---|"]
        for n in different:
            cells = []
            for run in (control, octopus):
                t = run.get(n)
                d = detail(t)
                cells.append(outcome(t) + (" (" + d + ")" if d else ""))
            out.append("| `%s` | %s | %s |" % (n, cells[0], cells[1]))
        out.append("")
    else:
        out += ["Every test passed in both runs at the first attempt.", ""]

    for title, run, info in (("control", control, cinfo), ("Octopus", octopus, oinfo)):
        failing = [n for n in names if run.get(n) is not None
                   and (run[n].unexpected or run[n].unexpected_end)]
        if failing:
            out += ["### Unexpected results, %s" % title, ""]
        for n in failing:
            t = run[n]
            out.append("`%s`" % n)
            out.append("")
            if t.unexpected_end:
                out.append("- test ended %s, expected %s: %s"
                           % (t.unexpected_end[0], t.unexpected_end[1],
                              escape(t.unexpected_end[2])))
            for subtest, status, message in t.unexpected[:MAX_DETAILS]:
                out.append("- %s: %s%s" % (status, escape(subtest),
                                           " (" + escape(message) + ")" if message else ""))
            if len(t.unexpected) > MAX_DETAILS:
                out.append("- ... and %d more" % (len(t.unexpected) - MAX_DETAILS))
            out.append("")
        if info["crashes"]:
            out += ["### Crashes, %s" % title, ""]
            for crash in info["crashes"][:MAX_DETAILS]:
                out.append("- %s" % escape(crash))
            out.append("")
        if info["errors"]:
            out += ["### Errors logged by the harness, %s" % title, ""]
            for message in info["errors"][:MAX_DETAILS]:
                out.append("- %s" % escape(message))
            if len(info["errors"]) > MAX_DETAILS:
                out.append("- ... and %d more" % (len(info["errors"]) - MAX_DETAILS))
            out.append("")
    return "\n".join(out) + "\n"


def lines_of(path):
    with open(path, encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--control", required=True)
    p.add_argument("--octopus", required=True)
    p.add_argument("--results")
    p.add_argument("--markdown")
    p.add_argument("--expected")
    args = p.parse_args()

    control, cinfo = read(args.control)
    octopus, oinfo = read(args.octopus)
    names = sorted(set(control) | set(octopus))
    results = ["%s\t%s\t%s" % (n, outcome(control.get(n)), outcome(octopus.get(n)))
               for n in names]

    for title, run, info in (("control", control, cinfo), ("octopus", octopus, oinfo)):
        print("%s: %d log lines (%d not JSON), suites %s, %d test files, %d checks"
              % (title, info["lines"], info["bad_lines"], info["suites"], len(run),
                 sum(t.checks for t in run.values())))

    text = markdown(control, octopus, cinfo, oinfo, names)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)

    if args.results:
        with open(args.results, "w", encoding="utf-8") as f:
            f.write("# test\tcontrol (Mozilla's librnp)\tOctopus\n")
            f.write("\n".join(results) + "\n")
    print("--- results")
    print("\n".join(results))
    print("--- end of results")

    status = 0
    if not control or not octopus:
        print("compare-logs: a log without tests: control %d, octopus %d test files"
              % (len(control), len(octopus)))
        status = 1
    for title, info in (("control", cinfo), ("octopus", oinfo)):
        if info["crashes"]:
            print("compare-logs: %s: %d crashes reported" % (title, len(info["crashes"])))
            status = 1
        if info["errors"]:
            print("compare-logs: %s: %d errors logged by the harness"
                  % (title, len(info["errors"])))
            status = 1
        if len(info["suites"]) != info["suites_ended"]:
            print("compare-logs: %s: %d suites started, %d ended"
                  % (title, len(info["suites"]), info["suites_ended"]))
            status = 1
    if args.expected:
        expected = lines_of(args.expected)
        diff = list(difflib.unified_diff(expected, results, "expected", "this run",
                                         lineterm="", n=0))
        if diff:
            print("\n".join(diff))
            print("compare-logs: %d expected lines, %d in this run: DIFFERENT"
                  % (len(expected), len(results)))
            status = 1
        else:
            print("compare-logs: %d tests, all as expected" % len(results))
    sys.exit(status)


if __name__ == "__main__":
    main()
