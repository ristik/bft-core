#!/usr/bin/env bash
# Peaks of a sample-resources.sh series: the largest disk use (growth from the first sample), the lowest free disk, the largest memory use and the longest span.
#   scripts/ci/summarize-resources.sh SERIES.tsv
set -uo pipefail
awk -F'\t' 'NR==1{next} NR==2{r0=$3; d0=$4} {if($3-r0>rg)rg=$3-r0; if($4-d0>dg)dg=$4-d0; if(minf==""||$5<minf)minf=$5; if($6>mu)mu=$6; if(mina==""||$7<mina)mina=$7; if($8>su)su=$8; t=$2; n++}
  END{printf "samples %d over %d s\nroot fs growth peak %.2f GiB\nDIR fs growth peak %.2f GiB\nDIR fs lowest free %.2f GiB\nmemory used peak %.2f GiB (lowest available %.2f GiB)\nswap used peak %d MiB\n", n, t, rg/1048576, dg/1048576, minf/1048576, mu/1024, mina/1024, su}' "${1:?usage: summarize-resources.sh SERIES.tsv}"
