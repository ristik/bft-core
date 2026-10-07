// Package b1paired names the inactive per-pair B1 admission API. The shared
// rootinput derivation owns the gate, so direct callers cannot bypass it.
package b1paired

import "github.com/unicitynetwork/bft-core/rootinput"

type Config = rootinput.B1Config
type Result = rootinput.B1Result

var ErrAdmission = rootinput.ErrB1Admission
