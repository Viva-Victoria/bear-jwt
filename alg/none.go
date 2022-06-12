package alg

// None is None algorithm
type None struct{}

// Size returns 0 cause signature is empty
func (s None) Size() int {
	return 0
}

// Sign returns nil as signature
func (s None) Sign(payload []byte) ([]byte, error) {
	return nil, nil
}

// Verify always returns true
func (s None) Verify(payload, signature []byte) (bool, error) {
	return true, nil
}
