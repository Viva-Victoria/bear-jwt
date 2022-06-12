package alg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"testing"
)

func encodeEcdsa(privateKey *ecdsa.PrivateKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

func decodeEcdsa(private string, public string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	blockPrivate, _ := pem.Decode([]byte(private))
	privateKey, _ := x509.ParseECPrivateKey(blockPrivate.Bytes)

	blockPublic, _ := pem.Decode([]byte(public))
	genericPublicKey, _ := x509.ParsePKIXPublicKey(blockPublic.Bytes)

	return privateKey, genericPublicKey.(*ecdsa.PublicKey)
}

func Test_generateECDSAKey(t *testing.T) {
	//t.Skip()
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		private, _ := ecdsa.GenerateKey(curve, rand.Reader)
		priv, pub := encodeEcdsa(private)
		log.Printf("%d:\n%s\n%s\n", curve.Params().BitSize, priv, pub)
	}
}

func testEcdsa(a Algorithm, private *ecdsa.PrivateKey, public *ecdsa.PublicKey) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		es, err := NewECDSA(a, private, public)
		require.NoError(t, err)

		payload := []byte("You are welcome, Martin :D")
		signature, err := es.Sign(payload)
		require.NoError(t, err)

		ok, err := es.Verify(payload, signature)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestECDSA(t *testing.T) {
	t.Run("ES256", testEcdsa(ES256, ecdsa256PrivateKey, ecdsa256PublicKey))
	t.Run("ES384", testEcdsa(ES384, ecdsa384PrivateKey, ecdsa384PublicKey))
	t.Run("ES512", testEcdsa(ES512, ecdsa521PrivateKey, ecdsa521PublicKey))
	t.Run("ES256 with 384 key", func(t *testing.T) {
		t.Helper()

		_, err := NewECDSA(ES256, ecdsa384PrivateKey, ecdsa384PublicKey)
		assert.Error(t, err)
	})
	t.Run("ES512 with nil keys", func(t *testing.T) {
		t.Helper()

		require.NotPanics(t, func() {
			_, err := NewECDSA(ES512, ecdsa521PrivateKey, nil)
			assert.Error(t, err)
		})
		require.NotPanics(t, func() {
			_, err := NewECDSA(ES512, nil, ecdsa521PublicKey)
			assert.Error(t, err)
		})
	})
	t.Run("incorrect signature", func(t *testing.T) {
		primary, err := NewECDSA(ES256, ecdsa256PrivateKey, ecdsa256PublicKey)
		require.NoError(t, err)

		secondary, err := NewECDSA(ES256, ecdsa256PrivateKeyAlternative, ecdsa256PublicKeyAlternative)
		require.NoError(t, err)

		payload := []byte("we developing secure soft")
		signature, err := primary.Sign(payload)
		require.NoError(t, err)

		ok, err := secondary.Verify(payload, signature)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("incorrect algorithm", func(t *testing.T) {
		_, err := NewECDSA(RS384, nil, nil)
		assert.Error(t, err)
	})
}

var (
	ecdsa256PrivateKey, ecdsa256PublicKey = decodeEcdsa(`-----BEGIN PRIVATE KEY-----
MHcCAQEEIDEd8GbFzL444ytO6nsE2aIKmkcFYm5qsIQBRfX/YxDyoAoGCCqGSM49
AwEHoUQDQgAE6/ndwXPKvSdHatHzaqclIDawgcI4H5sWCCPr0t40AJdrRKWiuLOs
pALEVOAz0BoubR+CYF3cTElX9TXaXsVGGA==
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6/ndwXPKvSdHatHzaqclIDawgcI4
H5sWCCPr0t40AJdrRKWiuLOspALEVOAz0BoubR+CYF3cTElX9TXaXsVGGA==
-----END PUBLIC KEY-----`)

	ecdsa256PrivateKeyAlternative, ecdsa256PublicKeyAlternative = decodeEcdsa(`-----BEGIN PRIVATE KEY-----
MHcCAQEEIN7+8T51WBsDCd4l1rTv4KOrjBTAOfSsSX2/d/o+M1o4oAoGCCqGSM49
AwEHoUQDQgAE/EcQqWWnLIhQ4uTXAwMmH+JsdkCI89gftNUBdGWsDjB5IWreRGZ7
GUdEJTI8CkvDna0HxyiWGa+crtP4y2vnyg==
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/EcQqWWnLIhQ4uTXAwMmH+JsdkCI
89gftNUBdGWsDjB5IWreRGZ7GUdEJTI8CkvDna0HxyiWGa+crtP4y2vnyg==
-----END PUBLIC KEY-----`)

	ecdsa384PrivateKey, ecdsa384PublicKey = decodeEcdsa(`-----BEGIN PRIVATE KEY-----
MIGkAgEBBDASppIubVYt+1GhHz4kGJP1WuoWui0hlFFXQ3HXgpCSxMvvA2xZY7Kz
NGrmC8lMaLigBwYFK4EEACKhZANiAAToXpH01qYTKIM9Aw3Bf62CxI2YJ4lpTdK/
d3eMr77nsO2IETOjysVCxOuKfQSpAyNWdiZOQH2ct/8aTKk3AhAnBeBT+dcuuZKh
jy6SeNv7VVBqW0L5kFWCqjvwIhkYHJ4=
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE6F6R9NamEyiDPQMNwX+tgsSNmCeJaU3S
v3d3jK++57DtiBEzo8rFQsTrin0EqQMjVnYmTkB9nLf/GkypNwIQJwXgU/nXLrmS
oY8uknjb+1VQaltC+ZBVgqo78CIZGBye
-----END PUBLIC KEY-----`)

	ecdsa521PrivateKey, ecdsa521PublicKey = decodeEcdsa(`-----BEGIN PRIVATE KEY-----
MIHcAgEBBEIADW2cotbW1LCZgMisCAOogDCKnzXcsvCA1VF/QmNWm46lJHUfcaZx
VtlDmNQJvNq50mpxjQVK+Wr7RgVMqryzKe6gBwYFK4EEACOhgYkDgYYABAB8nTbD
XevhgSpJxmT1yVFELexvTqVbd4mgbYGr5spxGoamFTS80amGkqiHvSdhJPAs3+TQ
OpbCYm/XrZINOwEVIgCWdWXuzYYt2eUjp8EJjV4yqKVmJpsMZMLtItcq4MoGFSSX
R23BtcPAOETEmapEwBgul9uycpNhfLVtIXE61zB4kA==
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAfJ02w13r4YEqScZk9clRRC3sb06l
W3eJoG2Bq+bKcRqGphU0vNGphpKoh70nYSTwLN/k0DqWwmJv162SDTsBFSIAlnVl
7s2GLdnlI6fBCY1eMqilZiabDGTC7SLXKuDKBhUkl0dtwbXDwDhExJmqRMAYLpfb
snKTYXy1bSFxOtcweJA=
-----END PUBLIC KEY-----`)
)
