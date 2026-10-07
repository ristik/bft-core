// Package b1ref is the inactive A′ reference oracle for UC, shared-seal and
// RSMT builtins. Certificate requests carry claims only. Full root authority
// is an explicit simulation of admitted registry state; this oracle does not
// authenticate injected fixtures or activate a production execution path.
// Malformed requests are exceptional halts, shaped wrong relations are false,
// and unavailable/impossible registry state is ErrInfrastructure.
// All prices are candidate formulas pending the two-CPU acceptance benchmarks.
package b1ref
