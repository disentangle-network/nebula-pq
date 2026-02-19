package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/slackhq/nebula/cert/p256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateV1_Sign(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/24"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      false,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	c, err := tbs.Sign(&certificateV1{details: detailsV1{notBefore: before, notAfter: after}}, Curve_CURVE25519, priv)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.CheckSignature(pub))

	b, err := c.Marshal()
	require.NoError(t, err)
	uc, err := unmarshalCertificateV1(b, nil)
	require.NoError(t, err)
	assert.NotNil(t, uc)
}

func TestCertificateV1_SignP256(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("01234567890abcedfghij1234567890ab1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/16"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      false,
		Curve:     Curve_P256,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

	c, err := tbs.Sign(&certificateV1{details: detailsV1{notBefore: before, notAfter: after}}, Curve_P256, rawPriv)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.True(t, c.CheckSignature(pub))

	b, err := c.Marshal()
	require.NoError(t, err)
	uc, err := unmarshalCertificateV1(b, nil)
	require.NoError(t, err)
	assert.NotNil(t, uc)
}

func TestCertificate_SignP256_AlwaysNormalized(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("01234567890abcedfghij1234567890ab1234567890abcedfghij1234567890ab")

	tbs := TBSCertificate{
		Version: Version1,
		Name:    "testing",
		Networks: []netip.Prefix{
			mustParsePrefixUnmapped("10.1.1.1/24"),
			mustParsePrefixUnmapped("10.1.1.2/16"),
		},
		UnsafeNetworks: []netip.Prefix{
			mustParsePrefixUnmapped("9.1.1.2/24"),
			mustParsePrefixUnmapped("9.1.1.3/16"),
		},
		Groups:    []string{"test-group1", "test-group2", "test-group3"},
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubKey,
		IsCA:      true,
		Curve:     Curve_P256,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

	for i := 0; i < 1000; i++ {
		if i&1 == 1 {
			tbs.Version = Version1
		} else {
			tbs.Version = Version2
		}
		c, err := tbs.Sign(nil, Curve_P256, rawPriv)
		require.NoError(t, err)
		assert.NotNil(t, c)
		assert.True(t, c.CheckSignature(pub))
		normie, err := p256.IsNormalized(c.Signature())
		require.NoError(t, err)
		assert.True(t, normie)
	}
}

func TestCertificateV2_SignPQ(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)

	// Generate ML-DSA-87 keypair for CA
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes := pub.Bytes()
	privBytes := priv.Bytes()

	// PQ is V2-only (V1 protobuf format can't handle large keys)
	tbs := TBSCertificate{
		Version:   Version2,
		Name:      "test-pq-ca",
		NotBefore: before,
		NotAfter:  after,
		PublicKey: pubBytes,
		IsCA:      true,
		Curve:     Curve_PQ,
	}

	// Sign as self-signed CA
	c, err := tbs.Sign(nil, Curve_PQ, privBytes)
	require.NoError(t, err)
	assert.NotNil(t, c)

	// Verify the signature
	assert.True(t, c.CheckSignature(pubBytes), "PQ CA cert signature must verify")

	// Verify curve
	assert.Equal(t, Curve_PQ, c.Curve())

	// Verify public key matches
	assert.Equal(t, pubBytes, c.PublicKey())

	// Verify signature length matches ML-DSA-87
	assert.Equal(t, mldsa87.SignatureSize, len(c.Signature()))

	// Marshal and unmarshal roundtrip
	b, err := c.Marshal()
	require.NoError(t, err)
	uc, err := unmarshalCertificateV2(b, nil, Curve_PQ)
	require.NoError(t, err)
	assert.NotNil(t, uc)
	assert.Equal(t, "test-pq-ca", uc.Name())
	assert.True(t, uc.IsCA())

	// Verify signature still valid after roundtrip
	assert.True(t, uc.CheckSignature(pubBytes), "PQ cert signature must verify after marshal/unmarshal roundtrip")

	// Fingerprint should be deterministic
	fp1, err := c.Fingerprint()
	require.NoError(t, err)
	fp2, err := uc.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, fp1, fp2)
}

func TestCertificateV2_SignPQ_HostCert(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)

	// Create PQ CA
	ca, _, caPriv, _ := NewTestCaCert(Version2, Curve_PQ, before, after, nil, nil, []string{"pq-group"})

	// Create PQ host cert signed by CA
	hostCert, hostPub, _, hostPEM := NewTestCert(
		Version2, Curve_PQ, ca, caPriv, "pq-host",
		before, after,
		[]netip.Prefix{netip.MustParsePrefix("10.42.0.1/24")},
		nil,
		[]string{"pq-group"},
	)

	// Verify host cert is signed by CA
	assert.True(t, hostCert.CheckSignature(ca.PublicKey()), "host cert must verify against CA public key")
	assert.Equal(t, Curve_PQ, hostCert.Curve())
	assert.Equal(t, "pq-host", hostCert.Name())
	assert.False(t, hostCert.IsCA())

	// Host public key should be ML-KEM-1024 sized (key agreement key, not signing key)
	assert.NotEmpty(t, hostPub)

	// PEM roundtrip
	assert.NotEmpty(t, hostPEM)
	uc, _, err := UnmarshalCertificateFromPEM(hostPEM)
	require.NoError(t, err)
	assert.Equal(t, "pq-host", uc.Name())
	assert.True(t, uc.CheckSignature(ca.PublicKey()), "PEM roundtrip must preserve valid signature")
}
