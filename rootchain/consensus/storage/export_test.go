package storage

// VerifyFreezeAssignmentForTest drives the EVM-state-dependent half of freeze admission from the external test package.
var VerifyFreezeAssignmentForTest = verifyFreezeAssignment

// VerifyPrimaryProofForTest drives the primary candidate's EVM-proof admission from the external test package.
var VerifyPrimaryProofForTest = verifyPrimaryProof

// FreezeV4VersionForTest is the version byte of the proof-bearing Freeze companion.
const FreezeV4VersionForTest = freezeV4Version
