package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func loadRestorePin(ucPath, trPath string) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	read := func(path string) ([]byte, error) {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > 1<<20 {
			return nil, fmt.Errorf("pin file %s must be a nonempty regular file of at most 1 MiB", path)
		}
		return os.ReadFile(path)
	}
	ucRaw, err := read(ucPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading restore UC: %w", err)
	}
	trRaw, err := read(trPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading restore TR: %w", err)
	}
	var uc types.UnicityCertificate
	var tr certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(ucRaw, &uc); err != nil {
		return nil, nil, fmt.Errorf("decoding restore UC: %w", err)
	}
	if err := types.Cbor.Unmarshal(trRaw, &tr); err != nil {
		return nil, nil, fmt.Errorf("decoding restore TR: %w", err)
	}
	ucAgain, err := types.Cbor.Marshal(&uc)
	if err != nil || !bytes.Equal(ucRaw, ucAgain) {
		return nil, nil, fmt.Errorf("restore UC is not canonical CBOR: %v", err)
	}
	trAgain, err := types.Cbor.Marshal(&tr)
	if err != nil || !bytes.Equal(trRaw, trAgain) {
		return nil, nil, fmt.Errorf("restore TR is not canonical CBOR: %v", err)
	}
	return &uc, &tr, nil
}
