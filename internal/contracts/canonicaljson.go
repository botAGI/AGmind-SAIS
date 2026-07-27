package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"unicode/utf8"
)

// CanonicalJSON emits the byte-for-byte AGmind Canonical JSON v1 form.
func CanonicalJSON(v any) ([]byte, error) {
	if err := rejectInvalidStrings(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := strictValue(decoder)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func rejectInvalidStrings(value reflect.Value, containerDepth int) error {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return rejectInvalidStrings(value.Elem(), containerDepth)
	}
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return fmt.Errorf("invalid UTF-8 string")
		}
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("floating-point JSON is forbidden")
	case reflect.Map:
		depth := containerDepth + 1
		if depth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		for _, key := range value.MapKeys() {
			if key.Kind() != reflect.String {
				return fmt.Errorf("JSON object keys must be strings")
			}
			if err := rejectInvalidStrings(key, depth); err != nil {
				return err
			}
			if err := rejectInvalidStrings(value.MapIndex(key), depth); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		depth := containerDepth + 1
		if depth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		for i := 0; i < value.Len(); i++ {
			if err := rejectInvalidStrings(value.Index(i), depth); err != nil {
				return err
			}
		}
	case reflect.Struct:
		depth := containerDepth + 1
		if depth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		for i := 0; i < value.NumField(); i++ {
			if value.Field(i).CanInterface() {
				if err := rejectInvalidStrings(value.Field(i), depth); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeCanonical(out *bytes.Buffer, value any, containerDepth int) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeQuoted(out, value)
	case json.Number:
		if err := validateCanonicalInteger(value.String()); err != nil {
			return err
		}
		out.WriteString(value.String())
	case []any:
		depth := containerDepth + 1
		if depth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item, depth); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		depth := containerDepth + 1
		if depth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeQuoted(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, value[key], depth); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func writeQuoted(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteString(fmt.Sprintf("%02x", r))
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
