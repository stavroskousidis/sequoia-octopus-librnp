#!/usr/bin/env python3
"""Find and check the Taskcluster build that an artifact build of the pinned
Thunderbird downloads.

Usage: find-artifact-task.py --comm-rev <git commit of comm> \
           --comm-tag <release tag> --gecko-rev <GECKO_HEAD_REV> \
           --version <application version> [--task <task id>] \
           [--output <file>]

An artifact build of Thunderbird (`ac_add_options --enable-artifact-builds`)
compiles nothing: it downloads Mozilla's own Linux build and the matching
test archive and installs them into the object directory.  From a git clone
`mach` cannot always find that build by itself, so the workflow names the
task with MOZ_ARTIFACT_TASK.  This script

  * with --task: checks that the task is the shippable linux64 build of the
    pinned source, and fails otherwise;
  * without --task: looks the task up in the Taskcluster index, by the git
    commit and by the Mercurial revision of the release tag, prints what it
    finds, and applies the same checks.

The checks: the task has the two artifacts an artifact build needs
(`public/build/target.tar.xz`, `public/build/target.common.tests.tar.zst`);
its `target.json` reports the expected application version; and, where the
task definition names them, its Firefox revision is the GECKO_HEAD_REV of
the pinned tag's `.gecko_rev.yml` and its comm revision is the pinned
commit or the Mercurial revision of the release tag.

Read-only access to public services of Mozilla.  Only the Python standard
library is used.  With --output, the task id is written to that file.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

ROOT = "https://firefox-ci-tc.services.mozilla.com"
HG = "https://hg.mozilla.org/releases/comm-release"
NEEDED = ("public/build/target.tar.xz", "public/build/target.common.tests.tar.zst")


def get(url):
    """Return (status, parsed JSON or None)."""
    req = urllib.request.Request(url, headers={"User-Agent": "pqc-octopus-ci"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print("  %s: %s" % (url, e))
        return 0, None


def index_task(rev):
    for tree in ("comm-release.shippable", "comm-release"):
        ns = "comm.v2.%s.revision.%s.thunderbird.linux64-opt" % (tree, rev)
        status, body = get("%s/api/index/v1/task/%s" % (ROOT, ns))
        print("  index %s: HTTP %s" % (ns, status))
        if status == 200 and body and "taskId" in body:
            return body["taskId"]
    return None


def hints(args):
    """Nothing was found: print what could help a person to find the task."""
    print("For information, the newest shippable linux64 build of comm-release:")
    ns = "comm.v2.comm-release.shippable.latest.thunderbird.linux64-opt"
    status, body = get("%s/api/index/v1/task/%s" % (ROOT, ns))
    print("  index %s: HTTP %s" % (ns, status))
    if status == 200 and body and "taskId" in body:
        print("  task %s" % body["taskId"])
        for problem in check(body["taskId"], args, None):
            print("  differs from the pin: %s" % problem)
    for url in ("https://archive.mozilla.org/pub/thunderbird/candidates/%s-candidates/" % args.version,
                "https://archive.mozilla.org/pub/thunderbird/releases/%s/linux-x86_64/en-US/" % args.version):
        req = urllib.request.Request(url, headers={"User-Agent": "pqc-octopus-ci"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                print("  %s: HTTP %s" % (url, resp.status))
        except (urllib.error.URLError, TimeoutError) as e:
            print("  %s: %s" % (url, e))


def hg_revision(tag):
    status, body = get("%s/json-rev/%s" % (HG, tag))
    print("  %s/json-rev/%s: HTTP %s" % (HG, tag, status))
    if status == 200 and body:
        return body.get("node")
    return None


def artifacts(task):
    names, token = [], None
    while True:
        url = "%s/api/queue/v1/task/%s/artifacts" % (ROOT, task)
        if token:
            url += "?continuationToken=" + token
        status, body = get(url)
        if status != 200 or body is None:
            raise SystemExit("task %s: listing artifacts gave HTTP %s" % (task, status))
        names += [a["name"] for a in body.get("artifacts", [])]
        token = body.get("continuationToken")
        if not token:
            return names


def check(task, args, hg_rev):
    """Print what the task is; return a list of reasons why it is wrong."""
    problems = []
    status, definition = get("%s/api/queue/v1/task/%s" % (ROOT, task))
    if status != 200 or definition is None:
        return ["task %s: HTTP %s" % (task, status)]
    meta = definition.get("metadata", {})
    env = definition.get("payload", {}).get("env", {})
    print("  name:     %s" % meta.get("name"))
    print("  created:  %s" % definition.get("created"))
    print("  expires:  %s" % definition.get("expires"))
    for key in sorted(env):
        if key.startswith(("COMM_", "GECKO_")) or key in ("MH_BRANCH", "MOZ_BUILD_DATE"):
            print("  env %s=%s" % (key, env[key]))

    if "linux64-shippable/opt" not in str(meta.get("name")):
        problems.append("task name %r is not the shippable linux64 build" % meta.get("name"))

    gecko = env.get("GECKO_HEAD_REV")
    if gecko is not None and gecko != args.gecko_rev:
        problems.append("GECKO_HEAD_REV is %s, .gecko_rev.yml says %s" % (gecko, args.gecko_rev))
    comm = env.get("COMM_HEAD_REV")
    accepted = [r for r in (args.comm_rev, hg_rev) if r]
    if comm is not None and comm not in accepted:
        problems.append("COMM_HEAD_REV is %s, expected one of %s" % (comm, accepted))
    if gecko is None or comm is None:
        print("  note: the task definition does not name both revisions; "
              "only version and build id identify the build")

    names = artifacts(task)
    for name in NEEDED:
        present = name in names
        print("  artifact %s: %s" % (name, "present" if present else "MISSING"))
        if not present:
            problems.append("artifact %s is missing" % name)

    status, target = get("%s/api/queue/v1/task/%s/artifacts/public/build/target.json" % (ROOT, task))
    if status == 200 and target:
        for key in ("moz_app_version", "buildid", "moz_source_repo", "moz_source_stamp"):
            print("  target.json %s: %s" % (key, target.get(key)))
        if target.get("moz_app_version") != args.version:
            problems.append("target.json has version %s, expected %s"
                            % (target.get("moz_app_version"), args.version))
    else:
        problems.append("target.json: HTTP %s" % status)
    return problems


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--comm-rev", required=True)
    p.add_argument("--comm-tag", required=True)
    p.add_argument("--gecko-rev", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--task", default="")
    p.add_argument("--output")
    args = p.parse_args()

    print("Mercurial revision of %s:" % args.comm_tag)
    hg_rev = hg_revision(args.comm_tag)
    print("  %s" % hg_rev)

    task = args.task
    if task:
        print("Task given: %s" % task)
    else:
        print("Looking the task up in the index:")
        for rev in (args.comm_rev, hg_rev):
            if rev:
                task = index_task(rev)
                if task:
                    break
        if not task:
            hints(args)
            raise SystemExit("no task found for %s (%s)" % (args.comm_tag, args.comm_rev))
        print("Task found: %s" % task)

    print("Task %s:" % task)
    problems = check(task, args, hg_rev)
    if problems:
        for problem in problems:
            print("WRONG: %s" % problem)
        sys.exit(1)
    print("Task %s is the build of %s." % (task, args.comm_tag))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(task + "\n")


if __name__ == "__main__":
    main()
