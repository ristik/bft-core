#!/usr/bin/env bash
# X4 PoS step (reward-exhaust-refill): see scripts/x4pos/lib.sh x4p_reward_exhaust_refill. Run by scripts/x4pos/driver.py from the repository root.
set -euo pipefail
cd "$(dirname "$0")/../../.."
source scripts/x4pos/lib.sh
x4p_reward_exhaust_refill
