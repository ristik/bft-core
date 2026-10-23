# X4 B6c: the reward steps of the PoS campaign on the RECOVERY lane's chain (election, custody, offences, exit on the same accumulated state), not on the shadow chain they were
# proven on (X4_REWARDS, scripts/x4-shadow-steps.sh). Definitions only: sourcing this file starts nothing. Lane steps (p85_step): x4r_intervals, x4r_exhaust_refill.
# The pool is a small genesis alloc (P85_REWARD_FUNDING, run-lane sets it for run-inputs "rewards": true), so it runs dry; x4e_run (scripts/p85-recovery-steps.sh) runs the same
# scripts/x4pos/steps/reward-*.sh the driver runs. NOT yet proven on this chain: whether the settle/replay agree with the K -> J -> K acknowledged history and the slashed lots.

X4R_PROGRESS=${X4R_PROGRESS:-3600}   # the registry's progress (seconds of certified time) waited for before the first settle, as in the shadow rewards lane
# live (x4-rew-1): at progress 3600 this chain had closed 2 intervals (the shadow chain 3), settle and replay agreeing (5 payees, 3 segments); the minimum is what was observed
X4R_MIN_INTERVALS=${X4R_MIN_INTERVALS:-2}
X4R_EXHAUST_WAIT=${X4R_EXHAUST_WAIT:-3000}

x4r_intervals() {
  local p i reg; reg=$(jq -r .registry "$P85_DEPLOY")
  for i in $(seq 1 7200); do
    p=$(p85_call "$reg" 'progress()(uint64)' | awk 'NR==1{print $1}'); [ "${p:-0}" -ge "$X4R_PROGRESS" ] && break; sleep 1
  done
  [ "${p:-0}" -ge "$X4R_PROGRESS" ] || { echo "x4r: the registry's progress did not reach $X4R_PROGRESS in 7200 s (at ${p:-none})" >&2; return 1; }
  x4e_run ri1 reward-interval.sh "{\"minIntervals\":$X4R_MIN_INTERVALS}" && x4e_run ri1 reward-interval.check.sh "{\"minIntervals\":$X4R_MIN_INTERVALS}"
}

x4r_exhaust_refill() {
  x4e_run xr reward-exhaust-refill.sh "{\"refillWei\":\"1500000000000000000\",\"waitSeconds\":$X4R_EXHAUST_WAIT}" && x4e_run xr reward-exhaust-refill.check.sh '{}'
}
