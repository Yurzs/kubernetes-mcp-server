package redaction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSalt(t *testing.T) {
	s := newSalt()
	require.NotNil(t, s)
	assert.Len(t, s.bytes, 32)
	assert.Len(t, s.generationID, 8) // 4 bytes = 8 hex chars
}

func TestSaltHashConsistency(t *testing.T) {
	s := newSalt()
	hash1 := s.Hash("my-secret-value")
	hash2 := s.Hash("my-secret-value")
	assert.Equal(t, hash1, hash2, "same value should produce same hash with same salt")
	assert.Len(t, hash1, 16)
}

func TestSaltHashDifference(t *testing.T) {
	s := newSalt()
	hash1 := s.Hash("value-a")
	hash2 := s.Hash("value-b")
	assert.NotEqual(t, hash1, hash2, "different values should produce different hashes")
}

func TestDifferentSaltsDifferentHashes(t *testing.T) {
	s1 := newSalt()
	s2 := newSalt()
	hash1 := s1.Hash("same-value")
	hash2 := s2.Hash("same-value")
	assert.NotEqual(t, hash1, hash2, "different salts should produce different hashes for same value")
}

func TestGlobalSaltIsSingleton(t *testing.T) {
	salt1 := GlobalSalt()
	salt2 := GlobalSalt()
	assert.Equal(t, salt1, salt2, "GlobalSalt should return the same instance")
}
