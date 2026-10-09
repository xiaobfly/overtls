#!/usr/bin/env bash
# Run every demo scenario and print a summary.
#
#   cargo build --release      # once, then
#   sh demo/run_all.sh         # or: bash demo/run_all.sh
#
# The scenarios drive the real binary, print the expectation and the observation for every step, and
# keep their artifacts in demo/.run/<scenario>/. This runner shows each scenario's output live while
# copying it into demo/.run/logs/run-<scenario>.log, and requires both the scenario's exit code and
# the trailing "scenario result: PASS" line of that log - the exit code is the honest signal and the
# summary line proves the scenario actually finished. Every scenario runs under a deadline. The
# runner's exit code is non-zero when any scenario failed or timed out.
set -u

HERE=$(cd "$(dirname "$0")" && pwd | tr '\\' '/')
PYTHON_DIR="$HERE/python"
LOGS="$HERE/.run/logs"
mkdir -p "$LOGS"

SCENARIO_TIMEOUT_SECS=${SCENARIO_TIMEOUT_SECS:-900}

if [ -n "${RUN_SH:-}" ]; then
    RUNNER=$RUN_SH
else
    # The probe must prove that the candidate sees the same filesystem: a WSL bash on PATH would not
    # find demo/lib.sh and would run different python/cargo binaries against a different filesystem.
    RUNNER=sh
    for candidate in bash sh; do
        if "$candidate" -c "test -f \"$HERE/lib.sh\"" >/dev/null 2>&1; then
            RUNNER=$candidate
            break
        fi
    done
fi

# A liveness probe, not just `command -v`: on Windows `python3` on PATH is often the Microsoft Store
# execution alias, which cannot run a script.
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'pass' >/dev/null 2>&1; then
        PY=$candidate
        break
    fi
done
[ -n "$PY" ] || printf 'note: python3/python not found - the scenario timeouts are disabled\n' >&2

# The deadline, the live output and the log copy all live in demo/python/run_with_timeout.py, shared
# with demo/lib.sh (this runner deliberately does not source lib.sh - the scenarios do that).
run_with_timeout() {
    if [ "$1" = "--log" ]; then
        log_file=$2
        shift 2
    else
        log_file=""
    fi
    seconds=$1
    shift
    if [ -z "$PY" ]; then
        # Without python there is no deadline and no live pump; the scenarios need python anyway and
        # fail loudly, but the log is still written so the judge below can read it.
        if [ -n "$log_file" ]; then
            "$@" >"$log_file" 2>&1
        else
            "$@"
        fi
        return $?
    fi
    if [ -n "$log_file" ]; then
        "$PY" "$PYTHON_DIR/run_with_timeout.py" --log "$log_file" "$seconds" "$@"
    else
        "$PY" "$PYTHON_DIR/run_with_timeout.py" "$seconds" "$@"
    fi
}

trap 'exit 130' INT TERM

printf 'demo runner shell: %s\n' "$RUNNER"
printf 'logs: %s\n' "$LOGS"

summary=""
failed=0
total=0

for script in "$HERE"/scenarios/[0-9][0-9]_*.sh; do
    [ -f "$script" ] || continue
    name=$(basename "$script" .sh)
    log="$LOGS/run-$name.log"
    total=$((total + 1))
    printf '\n\n=================== %s ===================\n' "$name"
    rc=0
    run_with_timeout --log "$log" "$SCENARIO_TIMEOUT_SECS" "$RUNNER" "$script" || rc=$?
    # Anchored at the start of the line and limited to the tail: a scenario may print the words
    # "scenario result: PASS" while explaining itself, only the final summary line counts.
    if [ "$rc" -eq 0 ] && tail -n 20 "$log" 2>/dev/null | grep -q '^    scenario result: PASS'; then
        summary="$summary
  PASS  $name"
    else
        if [ "$rc" -eq 124 ]; then
            reason=" (timed out after ${SCENARIO_TIMEOUT_SECS}s)"
        elif [ "$rc" -ne 0 ]; then
            reason=" (exit code $rc)"
        else
            reason=" (no trailing PASS line)"
        fi
        summary="$summary
  FAIL  $name$reason   (log: $log)"
        failed=$((failed + 1))
    fi
done

printf '\n\n========================= demo summary =========================\n'
printf '%s\n' "$summary"
printf '================================================================\n'
printf '%s/%s scenarios passed\n' "$((total - failed))" "$total"
[ "$failed" -eq 0 ] || exit 1
