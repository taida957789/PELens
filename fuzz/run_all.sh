#!/bin/sh
# Run fuzz targets in parallel: ./run_all.sh <seconds per target> [target ...]
# On Windows the MSVC AddressSanitizer runtime must be on PATH (clang_rt.asan_dynamic-x86_64.dll).
# Inputs are capped at 256 KB: instrumented analysis of larger files is slow (≈ 100x a release
# build) and would be reported as timeouts without finding more code.
cd "$(dirname "$0")" || exit 1
T=${1:-1800}
shift
TARGETS=${*:-parse_pe certificate dotnet resources analyze}
mkdir -p logs
for t in $TARGETS; do
  cargo +nightly fuzz run "$t" -- -max_total_time="$T" -max_len=262144 -timeout=30 -rss_limit_mb=4096 > "logs/$t.log" 2>&1 &
done
wait
for t in $TARGETS; do
  printf '%s: ' "$t"; grep -aE "^Done|SUMMARY|panicked|deadly" "logs/$t.log" | head -3 | tr '\n' ' '; echo
done
