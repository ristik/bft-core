# Sourced by reth-paired-devnet.sh (P85_LANE=1, Q3_B1=1, M2_PROFILE2=1, SIGNING=authority) after the first paid certified block, in place of
# m2-profile2-handoffs.sh. Design: briefs/p85-recovery-lane.md.
#
# The genesis is proof of stake: scripts/lib/p85-lib.sh deployed the P85 contracts into the EVM genesis (custody, election, evidence; four
# bonded identities), pinned the records hook and the election in the B1 profile, and started the roots with --pos-deployment,
# --pos-evm-rpc and --pos-genesis-identities.
#
# Steps (NOT IMPLEMENTED YET; the lane refuses to run rather than pass without them):
#   1. baseline: the hook applies root records; custody's recordCursor follows the registry
#   2. the joiner (a fifth entity) registers, bonds and delegates through the live contracts (relayer EVM transactions)
#   3. the election becomes due; the hook-driven elect reserves a primary J = K + joiner
#   4. members sign possession proofs (ubft pos-relayer sign-pop); the relayer assembles them, submits submitAssignmentPoPs and finalizeCandidate
#   5. `ubft pos-relayer proposal` reads the published result from the EVM and builds the handoff proposal (identities with rawWeight, the
#      recovery authorization K, the possession proofs); the operator plans it: Prepare, endorsement, the v4 Freeze (negative controls: no
#      proof, a witness of another result), H commits
#   6. the joiner and one retained member go down: J (3 of 5) cannot make progress, K (3 of 4) can
#   7. the derived recovery candidate is proposed and admitted (VerifyLifecycle), RecoveryAck resolves the result, K resumes
#   8. all roots and one validator restart across the recovery; the old-origin head is admitted
#
# Missing pieces, in dependency order: (a) `pos-relayer proposal` (EVM -> evmassign.Proposal), (b) the relayer's EVM transactions, (c) the
# joiner's pair and onboarding, (d) these steps.
fail "the P85 recovery lane's steps are not implemented yet (scripts/p85-recovery-steps.sh); see briefs/p85-recovery-lane.md"
exit 1
