package recordwiring

import "github.com/unicitynetwork/bft-core/certifiedstore"

// OpenStore opens the certified-record store at path, retaining retain non-genesis records, with the parent
// directory synced before it is returned (certifiedstore.Open).
func OpenStore(path string, retain int) (*certifiedstore.Store, error) {
	return certifiedstore.Open(path, certifiedstore.Settings{Retain: retain})
}
