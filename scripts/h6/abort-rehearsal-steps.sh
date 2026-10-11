# Sourced by reth-paired-devnet.sh (H6_ABORT_LANE=1) after the first paid certified block: the H6 Abort rehearsal (see scripts/lib/h6-abort-lib.sh).
source scripts/lib/m2-handoff-lib.sh
source scripts/lib/h6-abort-lib.sh
echo "H6 Abort rehearsal: Abort before H (epoch 2), then Abort after H (epoch 3), same members, Q3 flow"
read -r m2_epoch_slot m2_cursor_slot m2_shard_epoch_slot < <(go run ./scripts/m2slots)
h6_preamble || return 1
h6_abort_before_h 2 || return 1
h6_abort_after_h 3 || return 1
