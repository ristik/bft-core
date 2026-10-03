// Package b1gen is the independent vector generator for the B1 builtins. It
// builds every byte itself from explicit seeds: its own CBOR writer, its own
// hash folds, its own UC and RSMT trees, and real low-s RFC 6979 secp256k1
// signatures from dcrd. It imports neither b1ref nor the bft-go-base types, so
// a vector the oracle accepts is two independent constructions agreeing.
//
// Output is a JSON manifest (Manifest); a generator run is a pure function of
// the seed.
package b1gen
