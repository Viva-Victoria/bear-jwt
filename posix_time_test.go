package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type posixTimeWrapper struct {
	Wisdom *PosixTime `json:"wisdom,omitempty"`
}

var (
	time01011970 = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	unix01011970 = int64(0)
	time12062022 = time.Date(2022, 6, 12, 0, 0, 0, 0, time.UTC)
	unix12062022 = int64(1654992000)
)

func TestPosixTime_MarshalJSON(t *testing.T) {
	t.Run("marshal now", func(t *testing.T) {
		now := time.Now()
		pt := NewPosixTime(now)

		actual, err := json.Marshal(posixTimeWrapper{Wisdom: pt})
		require.NoError(t, err)

		expected := fmt.Sprintf(`{"wisdom":%s}`, strconv.FormatInt(now.Unix(), 10))
		assert.Equal(t, expected, string(actual))
	})
	t.Run("marshal 01.01.1970", func(t *testing.T) {
		pt := NewPosixTime(time01011970)

		actual, err := json.Marshal(posixTimeWrapper{Wisdom: pt})
		require.NoError(t, err)

		expected := fmt.Sprintf(`{"wisdom":%d}`, unix01011970)
		assert.Equal(t, expected, string(actual))
	})
	t.Run("marshal 12.06.2022", func(t *testing.T) {
		pt := NewPosixTime(time12062022)

		actual, err := json.Marshal(posixTimeWrapper{Wisdom: pt})
		require.NoError(t, err)

		expected := fmt.Sprintf(`{"wisdom":%d}`, unix12062022)
		assert.Equal(t, expected, string(actual))
	})
	t.Run("marshal empty", func(t *testing.T) {
		actual, err := json.Marshal(posixTimeWrapper{})
		require.NoError(t, err)

		expected := fmt.Sprintf(`{}`)
		assert.Equal(t, expected, string(actual))
	})
	t.Run("marshal zero", func(t *testing.T) {
		_, err := json.Marshal(posixTimeWrapper{
			Wisdom: &PosixTime{},
		})
		require.NoError(t, err)
	})
	t.Run("unmarshal invalid", func(t *testing.T) {
		posixTime := &PosixTime{}
		err := posixTime.UnmarshalJSON([]byte("19a"))
		require.Error(t, err)
	})
}

func TestPosixTime_UnmarshalJSON(t *testing.T) {
	t.Run("unmarshal now", func(t *testing.T) {
		now := time.Now()

		var ptw posixTimeWrapper
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"wisdom":%s}`, strconv.FormatInt(now.Unix(), 10))), &ptw)
		require.NoError(t, err)

		assert.Equal(t, time.Now().Unix(), ptw.Wisdom.Time.Unix())
	})
	t.Run("unmarshal now", func(t *testing.T) {
		now := time.Now()

		var ptw posixTimeWrapper
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"wisdom":%s}`, strconv.FormatInt(now.Unix(), 10))), &ptw)
		require.NoError(t, err)

		assert.Equal(t, now.Unix(), ptw.Wisdom.Time.Unix())
	})
	t.Run("unmarshal 12.06.2022", func(t *testing.T) {
		var ptw posixTimeWrapper
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"wisdom":%d}`, unix12062022)), &ptw)
		require.NoError(t, err)

		assert.Equal(t, unix12062022, ptw.Wisdom.Time.Unix())
	})
	t.Run("unmarshal 01.01.1970", func(t *testing.T) {
		var ptw posixTimeWrapper
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"wisdom":%d}`, unix01011970)), &ptw)
		require.NoError(t, err)

		assert.Equal(t, unix01011970, ptw.Wisdom.Time.Unix())
	})
	t.Run("unmarshal empty", func(t *testing.T) {
		var actual posixTimeWrapper
		err := json.Unmarshal([]byte(`{"wisdom":"null"}`), &actual)
		require.NoError(t, err)

		assert.Equal(t, unix01011970, actual.Wisdom.Time.Unix())
	})
}
