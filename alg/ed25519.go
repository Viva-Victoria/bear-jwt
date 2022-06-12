package alg

import "crypto/ed25519"

type Ed25519 struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func NewEd25519(public ed25519.PublicKey, private ed25519.PrivateKey) Ed25519 {
	return Ed25519{public: public, private: private}
}

func (e Ed25519) Size() int {
	return ed25519.SignatureSize
}

func (e Ed25519) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(e.private, payload), nil
}

func (e Ed25519) Verify(payload, signature []byte) (bool, error) {
	return ed25519.Verify(e.public, payload, signature), nil
}
