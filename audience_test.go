package jwt

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type audienceWrapper struct {
	Audience *Audience `json:"aud"`
}

func testMarshal(t *testing.T, expected string, actual *Audience) {
	t.Helper()

	raw, err := json.Marshal(audienceWrapper{actual})
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf(`{"aud":%s}`, expected), string(raw))
}

func TestAudience_MarshalJSON(t *testing.T) {
	t.Run("marshal empty", func(t *testing.T) {
		testMarshal(t, `null`, nil)
		testMarshal(t, `null`, &Audience{})
	})
	t.Run("marshal one item", func(t *testing.T) {
		testMarshal(t, `"office"`, &Audience{"office"})
	})
	t.Run("marshal two items", func(t *testing.T) {
		testMarshal(t, `["api","office"]`, &Audience{"api", "office"})
	})
}

func testUnmarshalCorrupted(t *testing.T, j string) {
	t.Helper()

	var a Audience
	err := json.Unmarshal([]byte(j), &a)
	assert.Error(t, err)
}

func testUnmarshal(t *testing.T, j string, expected *Audience) {
	var wrapper audienceWrapper
	err := json.Unmarshal([]byte(fmt.Sprintf(`{"aud": %s}`, j)), &wrapper)
	require.NoError(t, err)

	assert.Equal(t, expected, wrapper.Audience)
}

func TestAudience_UnmarshalJSON(t *testing.T) {
	t.Run("unmarshal corrupted", func(t *testing.T) {
		testUnmarshalCorrupted(t, "")
		testUnmarshalCorrupted(t, "[{}]")
		testUnmarshalCorrupted(t, "noquote")
		testUnmarshalCorrupted(t, "1206")
		testUnmarshalCorrupted(t, "{}")
	})
	t.Run("unmarshal one string", func(t *testing.T) {
		testUnmarshal(t, `"office"`, &Audience{"office"})
	})
	t.Run("unmarshal one array", func(t *testing.T) {
		testUnmarshal(t, `["office"]`, &Audience{"office"})
	})
	t.Run("unmarshal array", func(t *testing.T) {
		testUnmarshal(t, `["api", "office"]`, &Audience{"api", "office"})
	})
	t.Run("unmarshal null", func(t *testing.T) {
		testUnmarshal(t, `null`, nil)
	})
}
