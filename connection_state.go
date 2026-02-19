package nebula

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/noiseutil"
)

const ReplayWindow = 1024

type ConnectionState struct {
	eKey           *NebulaCipherState
	dKey           *NebulaCipherState
	H              *noise.HandshakeState
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
	writeLock      sync.Mutex

	// Post-quantum KEM state (only used for Curve_PQ)
	pqKemPubKey  []byte // Our ephemeral ML-KEM-1024 public key
	pqKemPrivKey []byte // Our ephemeral ML-KEM-1024 private key
	pqKemSS      []byte // Shared secret from KEM exchange
}

func NewConnectionState(l *logrus.Logger, cs *CertState, crt cert.Certificate, initiator bool, pattern noise.HandshakePattern) (*ConnectionState, error) {
	var dhFunc noise.DHFunc
	var pqKemPub, pqKemPriv []byte

	switch crt.Curve() {
	case cert.Curve_CURVE25519:
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		if cs.pkcs11Backed {
			dhFunc = noiseutil.DHP256PKCS11
		} else {
			dhFunc = noiseutil.DHP256
		}
	case cert.Curve_PQ:
		// Hybrid mode: X25519 DH for classical security + ML-KEM-1024 for PQ security.
		// The Noise IX handshake uses X25519 for the DH tokens. The ML-KEM-1024
		// exchange is layered on top via the handshake payload (KemPublicKey/KemCiphertext).
		// Both shared secrets are mixed into the final symmetric keys via HKDF.
		dhFunc = noise.DH25519

		// Generate ephemeral ML-KEM-1024 keypair for this handshake
		var err error
		pqKemPub, pqKemPriv, err = noiseutil.PQKEMKeypair()
		if err != nil {
			return nil, fmt.Errorf("NewConnectionState: ML-KEM-1024 keygen failed: %s", err)
		}
	default:
		return nil, fmt.Errorf("invalid curve: %s", crt.Curve())
	}

	var ncs noise.CipherSuite
	if cs.cipher == "chachapoly" {
		ncs = noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256)
	} else {
		ncs = noise.NewCipherSuite(dhFunc, noiseutil.CipherAESGCM, noise.HashSHA256)
	}

	// For PQ hybrid mode, use a fresh X25519 keypair as the Noise "static" key.
	// The actual identity authentication comes from the ML-DSA-87 cert signature,
	// not from the DH static key. This is safe because:
	// 1. The cert is verified against the CA in the handshake payload
	// 2. The KEM exchange provides the PQ-secure key agreement
	// 3. The X25519 DH provides defense-in-depth
	var static noise.DHKey
	if crt.Curve() == cert.Curve_PQ {
		// Generate ephemeral X25519 keypair (cert's public key is ML-KEM, not X25519)
		var err error
		static, err = noise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("NewConnectionState: X25519 keygen failed: %s", err)
		}
	} else {
		static = noise.DHKey{Private: cs.privateKey, Public: crt.PublicKey()}
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   ncs,
		Random:        rand.Reader,
		Pattern:       pattern,
		Initiator:     initiator,
		StaticKeypair: static,
		//NOTE: These should come from CertState (pki.go) when we finally implement it
		PresharedKey:          []byte{},
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("NewConnectionState: %s", err)
	}

	// The queue and ready params prevent a counter race that would happen when
	// sending stored packets and simultaneously accepting new traffic.
	ci := &ConnectionState{
		H:            hs,
		initiator:    initiator,
		window:       NewBits(ReplayWindow),
		myCert:       crt,
		pqKemPubKey:  pqKemPub,
		pqKemPrivKey: pqKemPriv,
	}
	// always start the counter from 2, as packet 1 and packet 2 are handshake packets.
	ci.messageCounter.Add(2)

	return ci, nil
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter.Load(),
	})
}

func (cs *ConnectionState) Curve() cert.Curve {
	return cs.myCert.Curve()
}
