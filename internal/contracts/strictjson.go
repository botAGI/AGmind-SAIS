package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var integerJSON = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// DecodeStrict consumes one bounded JSON object, rejecting duplicates, floats,
// unknown fields, and trailing values before handing a typed contract to callers.
func DecodeStrict[T any](r io.Reader, maxBytes int64) (T, error) {
	var zero T
	if maxBytes < 1 {
		return zero, fmt.Errorf("invalid explicit JSON byte limit")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return zero, err
	}
	if int64(len(raw)) > maxBytes {
		return zero, fmt.Errorf("JSON input exceeds explicit byte limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := strictValue(decoder)
	if err != nil {
		return zero, err
	}
	if value == nil {
		return zero, fmt.Errorf("contract JSON must be an object")
	}
	if _, ok := value.(map[string]any); !ok {
		return zero, fmt.Errorf("contract JSON must be an object")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return zero, fmt.Errorf("trailing JSON data is forbidden: %v", token)
		}
		return zero, fmt.Errorf("trailing JSON data: %w", err)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return zero, err
	}
	typed := json.NewDecoder(bytes.NewReader(normalized))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&zero); err != nil {
		return zero, err
	}
	if err := validateContract(any(zero)); err != nil {
		return zero, err
	}
	return zero, nil
}

func strictValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON key: %s", key)
				}
				child, err := strictValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := strictValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	case json.Number:
		if !integerJSON.MatchString(token.String()) {
			return nil, fmt.Errorf("floating-point JSON is forbidden")
		}
		return token, nil
	case string, bool, nil:
		return token, nil
	default:
		return nil, fmt.Errorf("unsupported JSON value")
	}
}
