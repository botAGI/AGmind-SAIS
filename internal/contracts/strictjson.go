package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

var integerJSON = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// DecodeStrict consumes one bounded JSON object. The Contract constraint makes
// exhaustive validation a compile-time obligation for every generic type.
func DecodeStrict[T Contract](r io.Reader, maxBytes int64) (T, error) {
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
	if !utf8.Valid(raw) {
		return zero, fmt.Errorf("invalid UTF-8 JSON")
	}
	if err := validateEscapedSurrogates(raw); err != nil {
		return zero, err
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
	typed.UseNumber()
	typed.DisallowUnknownFields()
	if err := typed.Decode(&zero); err != nil {
		return zero, err
	}
	if err := zero.Validate(); err != nil {
		return zero, err
	}
	return zero, nil
}

func validateEscapedSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			if i+1 >= len(raw) {
				return fmt.Errorf("unterminated JSON escape")
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			first, err := readHexQuad(raw, i+1)
			if err != nil {
				return err
			}
			i += 4
			if first >= 0xd800 && first <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return fmt.Errorf("unpaired high surrogate escape")
				}
				second, err := readHexQuad(raw, i+3)
				if err != nil {
					return err
				}
				if second < 0xdc00 || second > 0xdfff {
					return fmt.Errorf("unpaired high surrogate escape")
				}
				i += 6
			} else if first >= 0xdc00 && first <= 0xdfff {
				return fmt.Errorf("unpaired low surrogate escape")
			}
		}
	}
	return nil
}

func readHexQuad(raw []byte, start int) (uint16, error) {
	if start+4 > len(raw) {
		return 0, fmt.Errorf("short Unicode escape")
	}
	var value uint16
	for _, char := range raw[start : start+4] {
		value <<= 4
		switch {
		case char >= '0' && char <= '9':
			value += uint16(char - '0')
		case char >= 'a' && char <= 'f':
			value += uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value += uint16(char-'A') + 10
		default:
			return 0, fmt.Errorf("invalid Unicode escape")
		}
	}
	return value, nil
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
