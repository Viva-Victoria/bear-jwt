package alg

import (
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateEd25519Key(t *testing.T) {
	t.Skip()

	public, private, _ := ed25519.GenerateKey(rand.Reader)
	log.Println(toBase64(public), toBase64(private))
}

var (
	ed25519PublicKey, _  = fromBase64("jJJCjYSnW2VCldC-kK3fywk3O34wKXjD989G3mQ8scU")
	ed25519PrivateKey, _ = fromBase64("L475Xyu_EJRTG3td7lARzb-Xf3x0fswNbPnZAw3GBPqMkkKNhKdbZUKV0L6Qrd_LCTc7fjApeMP3z0beZDyxxQ")

	ed25519PublicAlternative, _  = fromBase64("lH75Fw25lKyKDYBj11xO06WNVbcaRPJFa2Gd6CILMCI")
	ed25519PrivateAlternative, _ = fromBase64("g3RlGCvbMbcS0x0uHErzeSyOUCTdhGQ0K5sGG678BYuUfvkXDbmUrIoNgGPXXE7TpY1VtxpE8kVrYZ3oIgswIg")
)

func TestEdDSA(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		ed, err := NewEd25519(ed25519PublicKey, ed25519PrivateKey)
		require.NoError(t, err)

		assert.Equal(t, ed25519.SignatureSize, ed.Size())
	})
	t.Run("simple", func(t *testing.T) {
		ed, err := NewEd25519(ed25519PublicKey, ed25519PrivateKey)
		require.NoError(t, err)

		payload := []byte("Hello, Mr Daemon!")
		signature, err := ed.Sign(payload)
		require.NoError(t, err)
		require.Equal(t, "VP1EzZy_GYYqASbnys1u4j5W4Fh70cFDMQOPc2Q1kPPbkIGhRZBNGI40HWejvS9V1UEyl_OTj_-FNSalnLC1Bw", toBase64(signature))

		ok, err := ed.Verify(payload, signature)
		require.NoError(t, err)
		require.True(t, ok)

		ed, err = NewEd25519(ed25519PublicAlternative, ed25519PrivateAlternative)
		require.NoError(t, err)

		ok, err = ed.Verify(payload, signature)
		require.NoError(t, err)
		require.False(t, ok)
	})
	t.Run("nil keys", func(t *testing.T) {
		_, err := NewEd25519(nil, ed25519PrivateKey)
		require.Error(t, err)

		_, err = NewEd25519(ed25519PublicKey, nil)
		require.Error(t, err)
	})
}
