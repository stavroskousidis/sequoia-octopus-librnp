#!/usr/bin/env bash
# Run Thunderbird's OpenPGP tests once, with whatever library is installed
# as dist/bin/librnp.so of the object directory.
#
# Usage: run-tests.sh <label> <source directory> <object directory> <log directory>
#
# <label> names the run in the file names of the logs ("control",
# "octopus").  The script records which file is in place before and after
# the run (SHA-256 and the version string the library reports) and fails if
# the file changed during the run.  The exit status of `mach test` is
# printed, not returned: tests are expected to fail in some runs, and the
# comparison of the structured logs (compare-logs.py) decides.
#
# The test selection is the one of upstream's CI (.gitlab-ci.yml, template
# .thunderbird-tests), with the second path written out in full.
set -euo pipefail

label=$1
src=$2
obj=$3
logs=$4
lib="$obj/dist/bin/librnp.so"

# A browser started by root refuses a home directory that belongs to
# another user, which is what GitHub Actions sets in a container job.
export HOME=/root
export MOZ_NOSPAM=1
export MACH_NO_TERMINAL_FOOTER=1

mkdir -p "$logs"

identify() {
  sha256sum "$lib"
  ls -l "$lib"
  "${PYTHON:-python3}" - "$lib" <<'PY' || echo "version: could not be read outside of Thunderbird"
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
lib.rnp_version_string_full.restype = ctypes.c_char_p
print("version: rnp_version_string_full() = %s" % lib.rnp_version_string_full().decode())
PY
}

echo "=== $label: library before the run"
identify
before=$(sha256sum "$lib" | cut -d' ' -f1)

cd "$src"
status=0
start=$(date +%s)
dbus-run-session -- "${PYTHON:-python3}" mach test \
  --log-raw "$logs/$label.raw.log" \
  --log-errorsummary "$logs/$label.errorsummary.log" \
  --headless \
  comm/mail/extensions/openpgp/test \
  comm/mail/test/browser/openpgp \
  > "$logs/$label.out.log" 2>&1 || status=$?
end=$(date +%s)

echo "=== $label: last lines of the output"
tail -n 150 "$logs/$label.out.log"
echo "=== $label: mach test exit status $status, $((end - start)) seconds"

echo "=== $label: library after the run"
identify
after=$(sha256sum "$lib" | cut -d' ' -f1)
if [ "$before" != "$after" ]; then
  echo "$lib changed during the run" >&2
  exit 1
fi
if [ ! -s "$logs/$label.raw.log" ]; then
  echo "$logs/$label.raw.log is missing or empty" >&2
  exit 1
fi
