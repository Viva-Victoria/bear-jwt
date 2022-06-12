package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

var (
	ErrAudienceTypeMismatch = errors.New("aud field should be string or array of strings")
)

type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte("null"), nil
	case 1:
		return []byte(fmt.Sprintf(`"%s"`, a[0])), nil
	default:
		return json.Marshal([]string(a))
	}
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var value interface{}
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	if value == nil {
		*a = make([]string, 0)
		return nil
	}

	valueType := reflect.TypeOf(value)
	switch valueType.Kind() {
	case reflect.Array, reflect.Slice:
		array, ok := value.([]interface{})
		if !ok {
			return ErrAudienceTypeMismatch
		}

		aud := make(Audience, len(array))
		for i, item := range array {
			itemString, ok := item.(string)
			if !ok {
				return ErrAudienceTypeMismatch
			}

			aud[i] = itemString
		}
		*a = aud
		return nil

	case reflect.String:
		*a = Audience{value.(string)}
		return nil

	default:
		return ErrAudienceTypeMismatch
	}
}
