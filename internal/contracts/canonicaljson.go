package contracts

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	jsonNumberType     = reflect.TypeOf(json.Number(""))
	jsonRawMessageType = reflect.TypeOf(json.RawMessage(nil))
	jsonMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType  = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

type programmaticReference struct {
	valueType reflect.Type
	pointer   uintptr
	length    int
}

// CanonicalJSON emits the byte-for-byte AGmind Canonical JSON v1 form.
func CanonicalJSON(v any) ([]byte, error) {
	value, err := programmaticJSONValue(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func programmaticJSONValue(value any) (any, error) {
	if err := validateProgrammaticJSON(
		reflect.ValueOf(value),
		make(map[programmaticReference]bool),
	); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	// Defense in depth: encoding/json has historically repaired invalid UTF-8
	// and unpaired surrogate output returned by custom marshalers. The
	// pre-marshal domain walk rejects those custom types, and these checks keep
	// the cryptographic preimage boundary closed if the standard library's
	// behavior changes or a path is missed.
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8 JSON after marshal")
	}
	if err := validateEscapedSurrogates(raw); err != nil {
		return nil, err
	}
	// The pre-marshal walk enforces the closed producer domain and terminates
	// reference cycles; it deliberately does not approximate encoded depth
	// from Go reflection. Programmatic inputs are trusted in-process producer
	// values, while untrusted wire inputs are byte-bounded by DecodeStrict.
	// strictValue below is authoritative for the actual encoded 64-container
	// limit after encoding/json has applied field promotion and omitempty.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoded, err := strictValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON data is forbidden: %v", token)
		}
		return nil, fmt.Errorf("trailing JSON data: %w", err)
	}
	return decoded, nil
}

func implementsForbiddenMarshaler(valueType reflect.Type) bool {
	if valueType.Implements(jsonMarshalerType) ||
		valueType.Implements(textMarshalerType) {
		return true
	}
	return valueType.Kind() != reflect.Pointer &&
		(reflect.PointerTo(valueType).Implements(jsonMarshalerType) ||
			reflect.PointerTo(valueType).Implements(textMarshalerType))
}

func validateProgrammaticJSON(
	value reflect.Value,
	activeReferences map[programmaticReference]bool,
) error {
	if !value.IsValid() {
		return nil
	}
	valueType := value.Type()
	if valueType == jsonRawMessageType {
		return fmt.Errorf("json.RawMessage is forbidden in canonical JSON")
	}
	if implementsForbiddenMarshaler(valueType) {
		return fmt.Errorf("custom JSON/text marshaler %s is forbidden", valueType)
	}
	if valueType == jsonNumberType {
		return validateCanonicalInteger(value.String())
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		return validateProgrammaticJSON(value.Elem(), activeReferences)
	}
	if value.Kind() == reflect.Pointer ||
		value.Kind() == reflect.Map ||
		value.Kind() == reflect.Slice {
		if value.IsNil() {
			if value.Kind() == reflect.Slice &&
				value.Type().Elem().Kind() == reflect.Uint8 {
				return fmt.Errorf("byte slices are forbidden in canonical JSON")
			}
			return nil
		}
		reference := programmaticReference{
			valueType: value.Type(),
			pointer:   uintptr(value.UnsafePointer()),
		}
		if value.Kind() == reflect.Slice {
			// encoding/json observes a slice's data and length, not capacity.
			// Omitting capacity also ensures a cycle whose recurring logical
			// header was full-sliced to a different cap still fails closed.
			reference.length = value.Len()
		}
		if activeReferences[reference] {
			return fmt.Errorf("cyclic canonical JSON value")
		}
		activeReferences[reference] = true
		defer delete(activeReferences, reference)
	}
	if value.Kind() == reflect.Pointer {
		return validateProgrammaticJSON(value.Elem(), activeReferences)
	}
	switch value.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Uintptr:
		return nil
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return fmt.Errorf("invalid UTF-8 string")
		}
		return nil
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("floating-point JSON is forbidden")
	case reflect.Map:
		for _, key := range value.MapKeys() {
			if err := validateProgrammaticMapKey(key); err != nil {
				return err
			}
			if err := validateProgrammaticJSON(
				value.MapIndex(key),
				activeReferences,
			); err != nil {
				return err
			}
		}
		return nil
	case reflect.Array, reflect.Slice:
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			return fmt.Errorf("byte slices are forbidden in canonical JSON")
		}
		for i := 0; i < value.Len(); i++ {
			if err := validateProgrammaticJSON(
				value.Index(i),
				activeReferences,
			); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			tagName := strings.Split(field.Tag.Get("json"), ",")[0]
			if tagName == "-" {
				continue
			}
			if field.PkgPath != "" && !field.Anonymous {
				continue
			}
			for _, option := range strings.Split(field.Tag.Get("json"), ",")[1:] {
				if option == "string" {
					return fmt.Errorf("json string tag coercion is forbidden")
				}
			}
			if err := validateProgrammaticJSON(
				value.Field(i),
				activeReferences,
			); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported canonical JSON value %s", valueType)
	}
}

func validateProgrammaticMapKey(key reflect.Value) error {
	if key.Kind() != reflect.String {
		return fmt.Errorf("JSON object keys must be strings")
	}
	if !utf8.ValidString(key.String()) {
		return fmt.Errorf("invalid UTF-8 string")
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
