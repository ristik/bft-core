#!/usr/bin/env bash
# X4 PoS step check (reward-interval): read-only; exit 0 iff the effect of the step is present on the chain.
set -euo pipefail
cd "$(dirname "$0")/../../.."
source scripts/x4pos/lib.sh
x4p_reward_interval_check
