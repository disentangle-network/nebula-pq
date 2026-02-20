// Package noiseutil provides cryptographic utilities for the Noise protocol.
//
// pq.go implements post-quantum KEM (Key Encapsulation Mechanism) helpers
// for the hybrid X25519 + ML-KEM-1024 handshake. The hybrid construction
// provides security against both classical and quantum adversaries:
//   - X25519 DH provides classical security (unchanged from upstream Nebula)
//   - ML-KEM-1024 KEM provides NIST FIPS 203 post-quantum security
//   - Both shared secrets are mixed via HKDF, so breaking either alone is insufficient
//
// Theoretical basis: NIST SP 800-227 (hybrid key establishment)
// KEM implementation: cloudflare/circl ML-KEM-1024 (FIPS 203)
package noiseutil

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"golang.org/x/crypto/hkdf"
)

const (
	// PQKEMPublicKeySize is the size of an ML-KEM-1024 public key
	PQKEMPublicKeySize = 1568 // mlkem1024.PublicKeySize is not a const, so we hardcode

	// PQKEMCiphertextSize is the size of an ML-KEM-1024 ciphertext
	PQKEMCiphertextSize = 1568

	// PQKEMSharedKeySize is the size of the shared secret from ML-KEM-1024
	PQKEMSharedKeySize = 32
)

// PQKEMKeypair generates an ML-KEM-1024 keypair.
// Returns (publicKey, privateKeySeed) as byte slices.
// The private key seed can be used with PQKEMDecapsulate.
func PQKEMKeypair() (publicKey []byte, privateKey []byte, err error) {
	pk, sk, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 key generation failed: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 public key marshal failed: %w", err)
	}

	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 private key marshal failed: %w", err)
	}

	return pubBytes, privBytes, nil
}

// PQKEMEncapsulate encapsulates a shared secret to the given ML-KEM-1024 public key.
// Returns (ciphertext, sharedSecret).
func PQKEMEncapsulate(publicKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	pk := new(mlkem1024.PublicKey)
	if err := pk.Unpack(publicKey); err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 public key unmarshal failed: %w", err)
	}

	ct := make([]byte, mlkem1024.CiphertextSize)
	ss := make([]byte, mlkem1024.SharedKeySize)

	seed := make([]byte, mlkem1024.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate encapsulation seed: %w", err)
	}

	pk.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}

// PQKEMDecapsulate decapsulates a shared secret from a ciphertext using the private key.
// Returns the shared secret.
func PQKEMDecapsulate(privateKey []byte, ciphertext []byte) (sharedSecret []byte, err error) {
	sk := new(mlkem1024.PrivateKey)
	if err := sk.Unpack(privateKey); err != nil {
		return nil, fmt.Errorf("ML-KEM-1024 private key unmarshal failed: %w", err)
	}

	ss := make([]byte, mlkem1024.SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}

// HybridMixKeys combines a classical DH shared secret with a KEM shared secret
// using HKDF-SHA256. This is the NIST-recommended hybrid combiner construction.
//
// The output is a 64-byte key that can be split into two 32-byte symmetric keys
// (for encrypt and decrypt directions), matching the Noise Split() output format.
//
// Security property: the hybrid key is at least as strong as the stronger
// of the two input secrets. An adversary must break BOTH X25519 AND ML-KEM-1024
// to recover the hybrid key.
func HybridMixKeys(noiseKey [32]byte, kemSharedSecret []byte) (hybridKey [32]byte, err error) {
	// HKDF with the noise-derived key as IKM and KEM shared secret as salt
	// This follows the NIST SP 800-56C rev2 two-step key derivation pattern
	h := hkdf.New(sha256.New, noiseKey[:], kemSharedSecret, []byte("nebula-pq-hybrid-v1"))

	if _, err := io.ReadFull(h, hybridKey[:]); err != nil {
		return hybridKey, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return hybridKey, nil
}
