package noiseutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPQKEMKeypair(t *testing.T) {
	pub, priv, err := PQKEMKeypair()
	require.NoError(t, err)
	assert.Len(t, pub, PQKEMPublicKeySize)
	assert.NotEmpty(t, priv)
}

func TestPQKEMEncapsulateDecapsulate(t *testing.T) {
	pub, priv, err := PQKEMKeypair()
	require.NoError(t, err)

	ct, ss1, err := PQKEMEncapsulate(pub)
	require.NoError(t, err)
	assert.Len(t, ct, PQKEMCiphertextSize)
	assert.Len(t, ss1, PQKEMSharedKeySize)

	ss2, err := PQKEMDecapsulate(priv, ct)
	require.NoError(t, err)
	assert.Len(t, ss2, PQKEMSharedKeySize)

	// Both sides must derive the same shared secret
	assert.Equal(t, ss1, ss2, "encapsulate and decapsulate must produce identical shared secrets")
}

func TestPQKEMDifferentKeypairsDifferentSecrets(t *testing.T) {
	pub1, _, err := PQKEMKeypair()
	require.NoError(t, err)

	pub2, _, err := PQKEMKeypair()
	require.NoError(t, err)

	_, ss1, err := PQKEMEncapsulate(pub1)
	require.NoError(t, err)

	_, ss2, err := PQKEMEncapsulate(pub2)
	require.NoError(t, err)

	// Different keypairs should produce different shared secrets
	assert.NotEqual(t, ss1, ss2)
}

func TestPQKEMEncapsulateInvalidKey(t *testing.T) {
	_, _, err := PQKEMEncapsulate([]byte("too short"))
	assert.Error(t, err)
}

func TestPQKEMDecapsulateInvalidKey(t *testing.T) {
	pub, _, err := PQKEMKeypair()
	require.NoError(t, err)

	ct, _, err := PQKEMEncapsulate(pub)
	require.NoError(t, err)

	_, err = PQKEMDecapsulate([]byte("bad key"), ct)
	assert.Error(t, err)
}

func TestHybridMixKeys(t *testing.T) {
	noiseKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	kemSS := []byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}

	hybrid1, err := HybridMixKeys(noiseKey, kemSS)
	require.NoError(t, err)
	assert.Len(t, hybrid1, 32)

	// Deterministic: same inputs produce same output
	hybrid2, err := HybridMixKeys(noiseKey, kemSS)
	require.NoError(t, err)
	assert.Equal(t, hybrid1, hybrid2)

	// Different KEM secret produces different hybrid key
	kemSS2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	hybrid3, err := HybridMixKeys(noiseKey, kemSS2)
	require.NoError(t, err)
	assert.NotEqual(t, hybrid1, hybrid3)

	// Different noise key produces different hybrid key
	noiseKey2 := [32]byte{}
	hybrid4, err := HybridMixKeys(noiseKey2, kemSS)
	require.NoError(t, err)
	assert.NotEqual(t, hybrid1, hybrid4)
}

func TestPQKEMFullRoundtrip(t *testing.T) {
	// Simulate the full handshake KEM exchange
	// Initiator generates KEM keypair
	initiatorPub, initiatorPriv, err := PQKEMKeypair()
	require.NoError(t, err)

	// Responder encapsulates to initiator's public key
	ct, responderSS, err := PQKEMEncapsulate(initiatorPub)
	require.NoError(t, err)

	// Initiator decapsulates
	initiatorSS, err := PQKEMDecapsulate(initiatorPriv, ct)
	require.NoError(t, err)

	// Both sides have the same shared secret
	assert.Equal(t, responderSS, initiatorSS)

	// Mix with a simulated Noise-derived key
	noiseKey := [32]byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
		42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}

	initiatorHybrid, err := HybridMixKeys(noiseKey, initiatorSS)
	require.NoError(t, err)

	responderHybrid, err := HybridMixKeys(noiseKey, responderSS)
	require.NoError(t, err)

	// Both sides derive the same hybrid key
	assert.Equal(t, initiatorHybrid, responderHybrid)
}
