package configuredprogress

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestM2IdentityPinnedOnRestore(t *testing.T) {
	f := newFixture(t, 0)
	f.ctx.ExecutionConfigV2 = sha256.Sum256([]byte("checked profile and collector"))
	s, path := f.open(3)
	_, _, err := s.Initialize(context.Background(), f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err = s.Load(context.Background(), f.ctx); err != nil {
		t.Fatal(err)
	}
	changed := f.ctx
	changed.ExecutionConfigV2 = sha256.Sum256([]byte("changed fee profile"))
	if _, _, err = s.Load(context.Background(), changed); !errors.Is(err, ErrContext) {
		t.Fatalf("changed identity: %v", err)
	}
	legacyContext := f.ctx
	legacyContext.ExecutionConfigV2 = [32]byte{}
	if _, _, err = s.Load(context.Background(), legacyContext); !errors.Is(err, ErrVersion) {
		t.Fatalf("legacy context: %v", err)
	}
}
func TestM2IdentityRefusesLegacyDescriptor(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(3)
	defer s.Close()
	if _, _, err := s.Initialize(context.Background(), f.ctx); err != nil {
		t.Fatal(err)
	}
	m2 := f.ctx
	m2.ExecutionConfigV2 = sha256.Sum256([]byte("checked profile and collector"))
	if _, _, err := s.Initialize(context.Background(), m2); !errors.Is(err, ErrVersion) {
		t.Fatalf("legacy descriptor accepted: %v", err)
	}
}

func TestM2DescriptorVersionRefused(t *testing.T) {
	f := newFixture(t, 0)
	id := sha256.Sum256([]byte("checked profile and collector"))
	d, err := descriptorFor(f.origin)
	if err != nil {
		t.Fatal(err)
	}
	wire := descriptorM2Wire{Version: 4, OriginIdentity: d.OriginIdentity, LegacyExecutionConfigIdentity: d.ExecutionConfigIdentity, Context: d.Context, B0: d.B0, S0: d.S0, RootInputVersion: d.RootInputVersion, RegistryLayoutVersion: d.RegistryLayoutVersion, ExecutionConfigV2: id[:]}
	payload, err := marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeEnvelope(kindDescriptor, payload, MaxDescriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDescriptor(raw, f.origin, id); !errors.Is(err, ErrVersion) {
		t.Fatalf("wrong m2 descriptor version: %v", err)
	}
}
