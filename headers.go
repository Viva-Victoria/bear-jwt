package jwt

import (
	"github.com/Viva-Victoria/bear-jwt/alg"
)

type Header interface {
	GetAlgorithm() alg.Algorithm
	SetAlgorithm(a alg.Algorithm)
	GetType() Type
	SetType(t Type)
	GetKeyId() string
}

type BasicHeader struct {
	Algorithm alg.Algorithm `json:"alg"`
	Type      Type          `json:"typ"`
	KeyId     string        `json:"kid,omitempty"`
}

func NewBasicHeader(alg alg.Algorithm) *BasicHeader {
	return &BasicHeader{
		Algorithm: alg,
		Type:      JsonWebTokenType,
	}
}

func (h *BasicHeader) GetAlgorithm() alg.Algorithm {
	return h.Algorithm
}

func (h *BasicHeader) SetAlgorithm(a alg.Algorithm) {
	h.Algorithm = a
}

func (h *BasicHeader) GetType() Type {
	return h.Type
}

func (h *BasicHeader) SetType(t Type) {
	h.Type = t
}

func (h *BasicHeader) GetKeyId() string {
	return h.KeyId
}

func (h *BasicHeader) SetKeyId(id string) {
	h.KeyId = id
}
