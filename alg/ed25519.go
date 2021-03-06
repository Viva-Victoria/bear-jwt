package alg

import "crypto/ed25519"

type Ed25519 struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func NewEd25519(private ed25519.PrivateKey, public ed25519.PublicKey) (Ed25519, error) {
	if len(public) == 0 || len(private) == 0 {
		return Ed25519{}, ErrNilKey
	}

	return Ed25519{public: public, private: private}, nil
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
