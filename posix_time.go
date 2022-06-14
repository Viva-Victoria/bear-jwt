package jwt

import (
	"strconv"
	"strings"
	"time"
)

type PosixTime struct {
	time.Time
}

func NewPosixTime(t time.Time) *PosixTime {
	return &PosixTime{Time: t}
}

func (p PosixTime) MarshalJSON() ([]byte, error) {
	if p.Time.IsZero() {
		return []byte("null"), nil
	}

	return []byte(strconv.FormatInt(p.Time.Unix(), 10)), nil
}

func (p *PosixTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if len(s) == 0 || strings.ToLower(s) == "null" {
		p.Time = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
		return nil
	}

	unix, err := strconv.Atoi(s)
	if err != nil {
		return err
	}

	p.Time = time.Unix(int64(unix), 0)
	return nil
}
