package jwt

import "errors"

type Type string

const (
	JsonWebTokenType Type = "JWT"
)

var (
	ErrNoData             = errors.New("no data")
	ErrIncorrectFormat    = errors.New("incorrect format")
	ErrIncorrectSignature = errors.New("incorrect signature")
)

type State int

const (
	StateUnknown State = iota
	StateValid
	StateExpired
	StateInactive
	StateNotIssued
)
