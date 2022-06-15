package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeRsa(private, public string) (*rsa.PrivateKey, *rsa.PublicKey) {
	blockPrivate, _ := pem.Decode([]byte(private))
	privateKey, _ := x509.ParsePKCS1PrivateKey(blockPrivate.Bytes)

	blockPublic, _ := pem.Decode([]byte(public))
	genericPublicKey, _ := x509.ParsePKIXPublicKey(blockPublic.Bytes)

	return privateKey, genericPublicKey.(*rsa.PublicKey)
}

func Test_generateRsaKeys(t *testing.T) {
	t.Skip()

	for _, bits := range []int{1024, 2048, 4096} {
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)

		x509Encoded := x509.MarshalPKCS1PrivateKey(privateKey)
		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

		x509EncodedPub, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
		pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

		log.Printf("%d:\n%s\n%s\n", bits, string(pemEncoded), string(pemEncodedPub))
	}
}

func testRsaSsaPkcs(a Algorithm, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, payload []byte) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		rs, err := NewRsaSsaPkcs1(a, privateKey, publicKey)
		require.NoError(t, err)

		signature, err := rs.Sign(payload)
		require.NoError(t, err)

		ok, err := rs.Verify(payload, signature)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestRsaSsaPkcs(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		rs, err := NewRsaSsaPkcs1(RS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)
		assert.Equal(t, rsa256PrivateKey.Size(), rs.Size())
	})
	t.Run("256", testRsaSsaPkcs(RS256, rsa256PublicKey, rsa256PrivateKey, []byte("My name Joseph, im a software developer")))
	t.Run("384", testRsaSsaPkcs(RS384, rsa384PublicKey, rsa384PrivateKey, []byte("BadComedian is not my lover")))
	t.Run("512", testRsaSsaPkcs(RS512, rsa512PublicKey, rsa512PrivateKey, []byte("No fear, no pain")))
	t.Run("invalid type", func(t *testing.T) {
		_, err := NewRsaSsaPkcs1(HS256, rsa256PrivateKey, rsa256PublicKey)
		require.Error(t, err)
	})
	t.Run("nil keys", func(t *testing.T) {
		_, err := NewRsaSsaPkcs1(RS256, nil, rsa256PublicKey)
		require.Error(t, err)

		_, err = NewRsaSsaPkcs1(RS256, rsa256PrivateKey, nil)
		require.Error(t, err)
	})
	t.Run("incorrect keys", func(t *testing.T) {
		primary, err := NewRsaSsaPkcs1(RS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)

		secondary, err := NewRsaSsaPkcs1(RS256, rsa256PrivateKeyAlternative, rsa256PublicKeyAlternative)
		require.NoError(t, err)

		payload := []byte("im beach, im a boss")
		signature, err := primary.Sign(payload)
		require.NoError(t, err)

		ok, err := secondary.Verify(payload, signature)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("nil signature", func(t *testing.T) {
		rs, err := NewRsaSsaPkcs1(RS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)

		rs.hash = crypto.MD5

		_, err = rs.Verify(nil, nil)
		require.Error(t, err)
	})
	t.Run("error hash", func(t *testing.T) {
		rs, err := NewRsaSsaPkcs1(RS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)

		rs.pool = NewHashPool(func() hash.Hash {
			return &errorHash{}
		})

		_, err = rs.Verify([]byte("message"), []byte("signature"))
		require.Error(t, err)

		_, err = rs.Sign([]byte("message"))
		require.Error(t, err)
	})
}

var (
	rsa256PrivateKey, rsa256PublicKey = decodeRsa(`-----BEGIN PRIVATE KEY-----
MIICXAIBAAKBgQDD8jqKGL07rDKSx5bHSh+UDePdDE+DEYpaHD00jqlKfnJEpCHN
VX1ghK3lGL/HQxeWa8higFu/El/4Q9l03DSYJwmdDfTqrfuDHIGiiUjcVHBas3Ss
uDaR7I3UXt3OIIj5EC9moUAVuhORQfjhV6xikbFi/fPhvx/im238nATiZQIDAQAB
AoGBALJP4XPANZxzBIbL+GsdCgWaakzDIixdLvD3l78XP/mZffT3BAeuj2zg8Lp1
vjff1zw8k1sIAfWsDAeJ/v64UWa4R1H7kpAYvkq3BLynLDpBSjmKLTdlu8a71mZW
jsIdl8xMfXKk0TIo/r56sbqqWjA38IjGnc0evIZLPtuommjhAkEA0dDujCEbgrKA
UfbNda5oax1c4f9WTkDtV5T49t98mV/STGqvP/kNHV9iHS4jJ8GfV36l7GlKQgr1
7nScsl+OmQJBAO8TuxN183X23idGgGUITe76ySf6mHVa+UmPngPiLIrW/Cf8gVqB
Lgq2V1uzXU0L6Tyf4FxaTn8qRV0md7vpza0CQE7lxg4jlPi8rswjhncuMk21KOxC
2+1pNNauSkBrIat7ANWDeIsR2ACnkXlvlACrKoP4N+SCY04aWQhmCVZ54GECQCiI
WNQw0Cj0xK819birUsMsg4QiqUxkMxV0ot6XruOPFUsWNTwJ4KtyRJdIbo4MceuU
U2505RAMM5xaVDxopDUCQEobt2U0kC6sKaRTVYWQald+srbSBfsLIplwIz9Bfivy
mIWj8EP43Cij+jSyJVBsJt09i2B23TmK5gS6KuQGIe0=
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDD8jqKGL07rDKSx5bHSh+UDePd
DE+DEYpaHD00jqlKfnJEpCHNVX1ghK3lGL/HQxeWa8higFu/El/4Q9l03DSYJwmd
DfTqrfuDHIGiiUjcVHBas3SsuDaR7I3UXt3OIIj5EC9moUAVuhORQfjhV6xikbFi
/fPhvx/im238nATiZQIDAQAB
-----END PUBLIC KEY-----`)

	rsa256PrivateKeyAlternative, rsa256PublicKeyAlternative = decodeRsa(`-----BEGIN PRIVATE KEY-----
MIICXAIBAAKBgQC9E3U96JbcAXssufZQRTwqqvYbfXWfO/riFCFvpnnS9+Vs4Hls
QKO/ctSlgyYWqtyKBQxWsyYSjMJeals7zAItrBjZGitl+dAojEtYS3K3GOLoypYq
ai0EAcS1H0oAsXK4Kp1l6SgFnVL2GONco0bDOEG4ZPSRQR/pm9zgyseRVwIDAQAB
AoGANauPTSp3oC2/dBu5YmG0yXvL7lO3jqKs/X2vXA0Kaas6caRqcyMKGC8VU4Id
zrNjdL4oGXgy53MTPU+9ZATt3OIFMHmeip/Edbq4wop66kSsTRuXQXeIYurH5HUQ
EqJQWGuEodl3fYnfaE2odeFIoSDSb4zlvTAaEmRrIWT9fRkCQQDmC4Es47nyAnLc
C2Jp0Op7oWptl7QCe4Ssdtg8mkhWBY+/rsGfgJAu1NEBlWyXHIVWTfh8zWTZIMSP
+0o28461AkEA0mig60VGMXUmQLValSscuVkxhadFR8h48holF1toyNCLiqozv0C7
KyHfnBb3zHGL9SQrlXU2UQaOIlUTLwPbWwJATF0HTVpu8EolzKuuyIeEPvPvO1//
bk+IVCPDViK03nFMLYoaVhM8SX91vfvXJzZdgK+zS+J2lqkM9uqo0SL6fQJBALmK
N/SfdsFgG6ZOBZ2qkb7D7057bTVai4R6F6EcIy+J7rMNWWpaK3JigWuEOWlX62H1
TlWSMZ6LmESgHrWDwicCQHk/ZT9KuedCOIPiX/SWFRpt8QzGG0M6Jy+wmplcsLIx
jHMFXTB+sfUmS6CbTN4XYNgOMBFgfJAZY94Fix5r1B8=
-----END PRIVATE KEY-----
`, `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9E3U96JbcAXssufZQRTwqqvYb
fXWfO/riFCFvpnnS9+Vs4HlsQKO/ctSlgyYWqtyKBQxWsyYSjMJeals7zAItrBjZ
Gitl+dAojEtYS3K3GOLoypYqai0EAcS1H0oAsXK4Kp1l6SgFnVL2GONco0bDOEG4
ZPSRQR/pm9zgyseRVwIDAQAB
-----END PUBLIC KEY-----`)

	rsa384PrivateKey, rsa384PublicKey = decodeRsa(`-----BEGIN PRIVATE KEY-----
MIIEogIBAAKCAQEAueRCKkb3YDRbtcgZuh2s3IKB52EGymI27mX2oqi73KtKWQge
C9r0zAn2HuKpTyh7XzGDzIVPCog9Vt9k3Jl49/vqzEX5ijyYcdWXfF762aGj35Lq
7DvAODJM3nrnmNzh406M+dgrw3bftubNTirUdpIn7SkB4boMn8Ixk9sDDEStY+y+
Fu+LsA+JPXVGgWGT8h/FkBDIEe97CLiGjIR71jCfJOfeSCFE6Gsg/7vvawpVPDPm
ue//tQcAFiXaRVi7prhh1nVFhRv5voRnm6L+Ea+7oA1d1h5m5CINISBz2l3yh8xR
VBbfoDFzlkU4CRjkRJLliQ+hKLdgcu1007tFmQIDAQABAoIBAG7oVeWdc6hNdM4v
NdJKNEFYCCNBS2jiUj3ITe9cVsFg3TnjUvHl0BoQc2yX9UYKNBlmlGkovDDfeiFj
pWzMkFT8U2lO8oRchOOd+QS2Mlo4S2pv4IPTXmro793pXFZiqs8QpaHHLM0xFmas
q59QhHS93N5tkfbYJwIGPcgmaloddykJrUNO4gMnUp19kWJ4D2qzi0DYDAXFYqc2
QCYUyC1T9crnYNLRky+m31Bg9Z2pGaXsMTn/uSVbpoeNzrgtx3TPnOHOGT3yZ9Es
3wQrjMoIZFWC3fALeB5nJZwLLP1utGu745MrqmWSjLJnqRQQKgVVTxxQ7yh7x0iO
iqo5lGUCgYEA30S14eKcEaabFXTbCpA0ux67+MMucdlqVZ+cpsVa819u68uXKEmG
DAPPVHwrDcHPwadls9kKZB6ZgYS4Xhhu5ZmSLu+2pGrVuRtoqdc2CnYTl4+j4Ly1
tv0Ap99iXLdJtoas8EH7bDgHsIcUZFBS6kRX5mPnACvrQLWmtBHmUZ8CgYEA1STL
JQCR5tL3o5Q5XrNeAPK+kDrp3D+ls8tFWRMmHR9pBnWSV1+3shyoiIbWdUMuJ49L
Ny3BEuBH5sO71utDDMnHU32E3ry3zsj1n15dbbcCMFjhkSQBj9r710zhcdtbZyCo
fM3Wq1gac/T+RfpUDj968+0A53pW3bjnbny7TccCgYAlifz2xM4u3Y9XtTUa+pIT
ICDEu7R0afTJ/rMtCyO2pcYVmT6KBIqoPH/Ambv3bS3MRqP/8C8iFE8FCtag44TJ
z99XSvCvhlL285fObqPkcGPs6LbKE5CN+s4Aa7uzERIwwUYUg1ONp4ILeTrBfwvh
3anVz9hIHBpK3//uaNALywKBgHPHA636zEYUzL2HU050ohhjw023Ircnv4uVW/sR
or9pA3SlwrNBZBgU5xsaGz4hGt4UQSgc62ake4oHQm5w5r/4jxRz9wvCeRmTIZDL
AncJVOAMN6LOaybILcp6kW92VwUCwWLhsLzsI5pfNwut+aCvrMr5L2eNlcfkm5nx
mRCbAoGAMK6oDSAQqu5sYh2f5ACJkLGzX4GZUclGpYh3AJZSrgcOSLOdeB9xbsML
Bspz0GHyBea7id+LBxBt+bXd+J+sVgdhwfPGJ3/mTSAKdBlKJVnX8CT1LCFg50NI
bYLgxfUN8Kmks/VfHSno8ySuLmLtlO8gNM7Dqz4fE0NkAGhEgwU=
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueRCKkb3YDRbtcgZuh2s
3IKB52EGymI27mX2oqi73KtKWQgeC9r0zAn2HuKpTyh7XzGDzIVPCog9Vt9k3Jl4
9/vqzEX5ijyYcdWXfF762aGj35Lq7DvAODJM3nrnmNzh406M+dgrw3bftubNTirU
dpIn7SkB4boMn8Ixk9sDDEStY+y+Fu+LsA+JPXVGgWGT8h/FkBDIEe97CLiGjIR7
1jCfJOfeSCFE6Gsg/7vvawpVPDPmue//tQcAFiXaRVi7prhh1nVFhRv5voRnm6L+
Ea+7oA1d1h5m5CINISBz2l3yh8xRVBbfoDFzlkU4CRjkRJLliQ+hKLdgcu1007tF
mQIDAQAB
-----END PUBLIC KEY-----`)

	rsa512PrivateKey, rsa512PublicKey = decodeRsa(`-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvKx0Pp/p49alGgs87f7p
76d9cAm4xf5XgiLO+gWT4fscMureJPPiPXk+gpt74JHBcci1udDXf6aeU3Uj0tEW
fg5Db/sGmEBdnQm+PedWBnOrOl2TYQngw9JGs0IN8187Hmx4ipy3qnozzYIWnGsc
SaAMrDAfJQHEu9w2G70nNX5HWusLNJGIBwJxi+uE+aCbcKB13j+921v18PyNtscC
Jr0g8dU76qu7FlKfxJYRjb2tmqz/pJsCjhXJIV2nx2e5I2xxVS6VvluL/RegsK3C
hZnm4wLEhij0xeKpGjLxSIPxCmLL790II/gTShi1047KarbpqINNtdOcQUoGTYJ4
ZIfLoiwVJJRjBlhs/bRGHibA43vhU9uv8UtupMcsbJFr2uoSIZvTOzY0CikDml81
pYxY0WUm33SqH4rBBDlKICiHQEhjqu322KA0EfooMyj56yq0cnXSsecj8gGww+G8
OLD4NMy3NbtQF/dOnhZMuDulNv0Dg69EzwIlSpTwnPu5YQNhkHAHd7xItJAFrwSn
qUoLpGFbgLGGgoD9XUAbzbVkA8qhgYAukhYhxnUxiXPL6Xwqm7Fu2p3YSYVFvrm9
ZElspugSF4TRckQMMKioORkc1TZyaSeChLBUEvazxPxMX3dcgGahViSeydn3QqGZ
syHEZfGBLOyJ4KLRhm6TZ6cCAwEAAQ==
-----END PUBLIC KEY-----`)
)
