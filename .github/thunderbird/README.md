# Thunderbird's OpenPGP tests with the Octopus

Fork-only directory of `stavroskousidis/sequoia-octopus-librnp`, used by `.github/workflows/thunderbird.yml`. It is not part of the upstream series. The master copy is `fork-files/sequoia-octopus-librnp/.github/thunderbird/` in `stavroskousidis/pqc-octopus`.

The workflow runs Thunderbird's own OpenPGP tests twice with the same Thunderbird, in one job in a Fedora 45 container: with the `librnp.so` that Mozilla ships (the control), and with the Octopus copied over it. It then compares the two runs test file by test file with `expected-results.tsv`. This is what upstream's CI does in `.gitlab-ci.yml` (template `.thunderbird-tests`), with three differences: the Thunderbird is the pinned release instead of a prebuilt image of beta or ESR, there is a control run, and the result is a table instead of pass or fail.

## Files

| File | Purpose |
|---|---|
| `find-artifact-task.py` | Finds the Taskcluster task of Mozilla's linux64 build for a Thunderbird commit, or checks a given task: name, Firefox and comm revisions, version, and the two archives an artifact build needs |
| `run-tests.sh` | Runs `mach test --headless` on `comm/mail/extensions/openpgp/test` and `comm/mail/test/browser/openpgp` with whatever is installed as `dist/bin/librnp.so`, and records which library that was |
| `compare-logs.py` | Reads the two structured logs, derives one outcome per test file and run (`pass`, `fail`, `skip`, `no-result`, `absent`), prints a summary with the checks that failed, and compares the outcomes with `expected-results.tsv` |
| `expected-results.tsv` | The recorded outcomes. The job is green only if a run reproduces every line |

## How the job gets a Thunderbird without compiling one

An artifact build (`ac_add_options --enable-artifact-builds`): `mach build` downloads Mozilla's own build of the same source from Taskcluster, together with its test archive, and installs both into the object directory. Thunderbird's JavaScript, XHTML and Fluent files are taken from the checkout, so a patched checkout is tested with its patches as long as it changes no compiled code. The source is a shallow clone of `mozilla-firefox/firefox` at the tag that `.gecko_rev.yml` of the Thunderbird commit names, with Thunderbird as its subdirectory `comm`.

The workflow passes the task to `mach` in `MOZ_ARTIFACT_TASK`. For the pinned tag the task id is written in the workflow; `find-artifact-task.py` checks on every run that it still is the build of the pinned source.

## Rules

- No test is excluded, skipped or marked as expected to fail in Thunderbird's manifests. A test that fails stays in the run; its line in `expected-results.tsv` says so, and the header of that file says what is known about it.
- A failure counts against the Octopus only if the control passes. A test that fails in the control is recorded as `fail` in both columns.
- A line of `expected-results.tsv` changes in the same commit as the change that causes it.
- Only the test keys and messages of Thunderbird's own test suite are used. The job runs in a fresh container with an empty home directory.

## Moving the pin

Change `PIN_TB_REF` and `PIN_TB_COMMIT` in the workflow, set `PIN_FX_COMMIT` to the commit of the Firefox tag that the new `.gecko_rev.yml` names, and empty `PIN_ARTIFACT_TASK`. The next run prints the task it finds; write that id into the workflow, and record the new outcomes from the section "results" of the step "Compare the two runs with the recorded results".

## Starting a run by hand

`workflow_dispatch` with the inputs `thunderbird_repository`, `thunderbird_ref`, `artifact_task` and `tests`. With another Thunderbird or other test paths the job compares the two runs and prints the table, and does not judge them against `expected-results.tsv`.
