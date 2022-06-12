package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Viva-Victoria/bear-jwt/alg"
)

// Parser parses byte array to Token
type Parser struct {
	verifiers map[alg.Algorithm]alg.Verifier
	signers   map[alg.Algorithm]alg.Signer
}

func NewParser() Parser {
	return Parser{
		verifiers: make(map[alg.Algorithm]alg.Verifier),
		signers:   make(map[alg.Algorithm]alg.Signer),
	}
}

// Register registers new verifier and signer for specified algorithm.
// If another implementation of the algorithm was registered earlier, it will be overwritten
func (p Parser) Register(algorithm alg.Algorithm, verifier alg.Verifier, signer alg.Signer) {
	p.verifiers[algorithm] = verifier
	p.signers[algorithm] = signer
}

// Parse returns Token parsed from byte array data or error if some troubles occurred
func (p Parser) Parse(data []byte) (Token, error) {
	if len(data) == 0 {
		return Token{}, ErrNoData
	}

	firstDot := bytes.Index(data, dotBytes)
	if firstDot == -1 {
		return Token{}, ErrIncorrectFormat
	}

	secondDot := bytes.Index(data[firstDot+1:], dotBytes)
	if secondDot == -1 {
		secondDot = len(data)
	} else {
		secondDot += firstDot
	}

	payloadBytes := data[:secondDot]
	headerBytes, err := fromBase64(payloadBytes[:firstDot])
	if err != nil {
		return Token{}, fmt.Errorf("bad header: %v", err)
	}

	claimsBytes, err := fromBase64(payloadBytes[firstDot+1:])
	if err != nil {
		return Token{}, fmt.Errorf("bad claims: %v", err)
	}

	var signatureBytes []byte
	if len(payloadBytes) < len(data) {
		signatureBytes, err = fromBase64(data[secondDot+1:])
		if err != nil {
			return Token{}, fmt.Errorf("bad signature: %v", err)
		}
	}

	header := Header{}
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return Token{}, err
	}
	if header.Type != JsonWebTokenType {
		return Token{}, fmt.Errorf("token type \"%s\" not supported", header.Type)
	}

	verifier, ok := p.verifiers[header.Algorithm]
	if !ok {
		return Token{}, fmt.Errorf("unknown algorithm \"%s\"", header.Algorithm)
	}

	ok, err = verifier.Verify(payloadBytes, signatureBytes)
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, ErrIncorrectSignature
	}

	claims := Claims{}
	if err = json.Unmarshal(claimsBytes, &claims); err != nil {
		return Token{}, err
	}

	return Token{
		Header:    header,
		Claims:    claims,
		signer:    p.signers[header.Algorithm],
		signature: signatureBytes,
		rawClaims: claimsBytes,
	}, nil
}
