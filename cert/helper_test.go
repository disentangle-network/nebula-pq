package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/netip"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// NewTestCaCert will create a new ca certificate
func NewTestCaCert(version Version, curve Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (Certificate, []byte, []byte, []byte) {
	var err error
	var pub, priv []byte

	switch curve {
	case Curve_CURVE25519:
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
	case Curve_P256:
		privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		pub = elliptic.Marshal(elliptic.P256(), privk.PublicKey.X, privk.PublicKey.Y)
		priv = privk.D.FillBytes(make([]byte, 32))
	case Curve_PQ:
		// CA certs use ML-DSA-87 signing keys
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pub = pk.Bytes()
		priv = sk.Bytes()
	default:
		// There is no default to allow the underlying lib to respond with an error
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	t := &TBSCertificate{
		Curve:          curve,
		Version:        version,
		Name:           "test ca",
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		IsCA:           true,
	}

	c, err := t.Sign(nil, curve, priv)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, priv, pem
}

// NewTestCert will generate a signed certificate with the provided details.
// Expiry times are defaulted if you do not pass them in
func NewTestCert(v Version, curve Curve, ca Certificate, key []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (Certificate, []byte, []byte, []byte) {
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}

	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	if len(networks) == 0 {
		networks = []netip.Prefix{netip.MustParsePrefix("10.0.0.123/8")}
	}

	var pub, priv []byte
	switch curve {
	case Curve_CURVE25519:
		pub, priv = X25519Keypair()
	case Curve_P256:
		pub, priv = P256Keypair()
	case Curve_PQ:
		pub, priv = MLKEM1024Keypair()
	default:
		panic("unknown curve")
	}

	nc := &TBSCertificate{
		Version:        v,
		Curve:          curve,
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, MarshalPrivateKeyToPEM(curve, priv), pem
}

func X25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}

func P256Keypair() ([]byte, []byte) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes()
}

// MLKEM1024Keypair generates an ML-KEM-1024 key pair for PQ host certificates.
// Returns (publicKey, privateKey) as raw byte slices.
func MLKEM1024Keypair() ([]byte, []byte) {
	pk, sk, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubBytes, _ := pk.MarshalBinary()
	privBytes, _ := sk.MarshalBinary()
	return pubBytes, privBytes
}
