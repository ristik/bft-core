#!/usr/bin/env bash
# Samples disk, memory and the largest resident processes every INTERVAL seconds into a TSV until it receives TERM/INT (CI evidence of peak resource use).
#   scripts/ci/sample-resources.sh OUT.tsv [INTERVAL=5] [DIR=.]   DIR: the filesystem whose free space is also sampled
# Columns: utc, monotonic seconds since start, root fs used KiB, DIR fs used KiB, DIR fs free KiB, mem used MiB, mem available MiB, swap used MiB, top process (RSS MiB name).
set -uo pipefail
out=${1:?usage: sample-resources.sh OUT.tsv [INTERVAL] [DIR]}; interval=${2:-5}; dir=${3:-.}
start=$SECONDS
printf 'utc\tt_s\troot_used_kib\tdir_used_kib\tdir_free_kib\tmem_used_mib\tmem_avail_mib\tswap_used_mib\ttop_rss\n' >"$out"
trap 'exit 0' TERM INT
while :; do
  root=$(df -Pk / | awk 'NR==2{print $3}'); d=$(df -Pk "$dir" | awk 'NR==2{print $3"\t"$4}')
  mem=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}/SwapTotal/{st=$2}/SwapFree/{sf=$2}END{printf "%d\t%d\t%d", (t-a)/1024, a/1024, (st-sf)/1024}' /proc/meminfo)
  top=$(ps -eo rss=,comm= --sort=-rss 2>/dev/null | head -1 | awk '{printf "%d %s", $1/1024, $2}')
  printf '%s\t%d\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" $((SECONDS - start)) "$root" "$d" "$mem" "$top" >>"$out"
  sleep "$interval" & wait $!
done
