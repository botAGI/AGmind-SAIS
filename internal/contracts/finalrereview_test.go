package contracts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type fourthNamedStringKey string

type fourthTextStringKey string

func (key fourthTextStringKey) MarshalText() ([]byte, error) {
	return []byte("text-marshaled-" + string(key)), nil
}

type fourthFlatValue0 struct {
	Value int `json:"value"`
}

type fourthFlatValue1 struct{ fourthFlatValue0 }
type fourthFlatValue2 struct{ fourthFlatValue1 }
type fourthFlatValue3 struct{ fourthFlatValue2 }
type fourthFlatValue4 struct{ fourthFlatValue3 }
type fourthFlatValue5 struct{ fourthFlatValue4 }
type fourthFlatValue6 struct{ fourthFlatValue5 }
type fourthFlatValue7 struct{ fourthFlatValue6 }
type fourthFlatValue8 struct{ fourthFlatValue7 }
type fourthFlatValue9 struct{ fourthFlatValue8 }
type fourthFlatValue10 struct{ fourthFlatValue9 }
type fourthFlatValue11 struct{ fourthFlatValue10 }
type fourthFlatValue12 struct{ fourthFlatValue11 }
type fourthFlatValue13 struct{ fourthFlatValue12 }
type fourthFlatValue14 struct{ fourthFlatValue13 }
type fourthFlatValue15 struct{ fourthFlatValue14 }
type fourthFlatValue16 struct{ fourthFlatValue15 }
type fourthFlatValue17 struct{ fourthFlatValue16 }
type fourthFlatValue18 struct{ fourthFlatValue17 }
type fourthFlatValue19 struct{ fourthFlatValue18 }
type fourthFlatValue20 struct{ fourthFlatValue19 }
type fourthFlatValue21 struct{ fourthFlatValue20 }
type fourthFlatValue22 struct{ fourthFlatValue21 }
type fourthFlatValue23 struct{ fourthFlatValue22 }
type fourthFlatValue24 struct{ fourthFlatValue23 }
type fourthFlatValue25 struct{ fourthFlatValue24 }
type fourthFlatValue26 struct{ fourthFlatValue25 }
type fourthFlatValue27 struct{ fourthFlatValue26 }
type fourthFlatValue28 struct{ fourthFlatValue27 }
type fourthFlatValue29 struct{ fourthFlatValue28 }
type fourthFlatValue30 struct{ fourthFlatValue29 }
type fourthFlatValue31 struct{ fourthFlatValue30 }
type fourthFlatValue32 struct{ fourthFlatValue31 }
type fourthFlatValue33 struct{ fourthFlatValue32 }
type fourthFlatValue34 struct{ fourthFlatValue33 }
type fourthFlatValue35 struct{ fourthFlatValue34 }
type fourthFlatValue36 struct{ fourthFlatValue35 }
type fourthFlatValue37 struct{ fourthFlatValue36 }
type fourthFlatValue38 struct{ fourthFlatValue37 }
type fourthFlatValue39 struct{ fourthFlatValue38 }
type fourthFlatValue40 struct{ fourthFlatValue39 }
type fourthFlatValue41 struct{ fourthFlatValue40 }
type fourthFlatValue42 struct{ fourthFlatValue41 }
type fourthFlatValue43 struct{ fourthFlatValue42 }
type fourthFlatValue44 struct{ fourthFlatValue43 }
type fourthFlatValue45 struct{ fourthFlatValue44 }
type fourthFlatValue46 struct{ fourthFlatValue45 }
type fourthFlatValue47 struct{ fourthFlatValue46 }
type fourthFlatValue48 struct{ fourthFlatValue47 }
type fourthFlatValue49 struct{ fourthFlatValue48 }
type fourthFlatValue50 struct{ fourthFlatValue49 }
type fourthFlatValue51 struct{ fourthFlatValue50 }
type fourthFlatValue52 struct{ fourthFlatValue51 }
type fourthFlatValue53 struct{ fourthFlatValue52 }
type fourthFlatValue54 struct{ fourthFlatValue53 }
type fourthFlatValue55 struct{ fourthFlatValue54 }
type fourthFlatValue56 struct{ fourthFlatValue55 }
type fourthFlatValue57 struct{ fourthFlatValue56 }
type fourthFlatValue58 struct{ fourthFlatValue57 }
type fourthFlatValue59 struct{ fourthFlatValue58 }
type fourthFlatValue60 struct{ fourthFlatValue59 }
type fourthFlatValue61 struct{ fourthFlatValue60 }
type fourthFlatValue62 struct{ fourthFlatValue61 }
type fourthFlatValue63 struct{ fourthFlatValue62 }
type fourthFlatValue64 struct{ fourthFlatValue63 }

type FourthFlatPointer0 struct {
	Value int `json:"value"`
}

type FourthFlatPointer1 struct{ *FourthFlatPointer0 }
type FourthFlatPointer2 struct{ *FourthFlatPointer1 }
type FourthFlatPointer3 struct{ *FourthFlatPointer2 }
type FourthFlatPointer4 struct{ *FourthFlatPointer3 }
type FourthFlatPointer5 struct{ *FourthFlatPointer4 }
type FourthFlatPointer6 struct{ *FourthFlatPointer5 }
type FourthFlatPointer7 struct{ *FourthFlatPointer6 }
type FourthFlatPointer8 struct{ *FourthFlatPointer7 }
type FourthFlatPointer9 struct{ *FourthFlatPointer8 }
type FourthFlatPointer10 struct{ *FourthFlatPointer9 }
type FourthFlatPointer11 struct{ *FourthFlatPointer10 }
type FourthFlatPointer12 struct{ *FourthFlatPointer11 }
type FourthFlatPointer13 struct{ *FourthFlatPointer12 }
type FourthFlatPointer14 struct{ *FourthFlatPointer13 }
type FourthFlatPointer15 struct{ *FourthFlatPointer14 }
type FourthFlatPointer16 struct{ *FourthFlatPointer15 }
type FourthFlatPointer17 struct{ *FourthFlatPointer16 }
type FourthFlatPointer18 struct{ *FourthFlatPointer17 }
type FourthFlatPointer19 struct{ *FourthFlatPointer18 }
type FourthFlatPointer20 struct{ *FourthFlatPointer19 }
type FourthFlatPointer21 struct{ *FourthFlatPointer20 }
type FourthFlatPointer22 struct{ *FourthFlatPointer21 }
type FourthFlatPointer23 struct{ *FourthFlatPointer22 }
type FourthFlatPointer24 struct{ *FourthFlatPointer23 }
type FourthFlatPointer25 struct{ *FourthFlatPointer24 }
type FourthFlatPointer26 struct{ *FourthFlatPointer25 }
type FourthFlatPointer27 struct{ *FourthFlatPointer26 }
type FourthFlatPointer28 struct{ *FourthFlatPointer27 }
type FourthFlatPointer29 struct{ *FourthFlatPointer28 }
type FourthFlatPointer30 struct{ *FourthFlatPointer29 }
type FourthFlatPointer31 struct{ *FourthFlatPointer30 }
type FourthFlatPointer32 struct{ *FourthFlatPointer31 }
type FourthFlatPointer33 struct{ *FourthFlatPointer32 }
type FourthFlatPointer34 struct{ *FourthFlatPointer33 }
type FourthFlatPointer35 struct{ *FourthFlatPointer34 }
type FourthFlatPointer36 struct{ *FourthFlatPointer35 }
type FourthFlatPointer37 struct{ *FourthFlatPointer36 }
type FourthFlatPointer38 struct{ *FourthFlatPointer37 }
type FourthFlatPointer39 struct{ *FourthFlatPointer38 }
type FourthFlatPointer40 struct{ *FourthFlatPointer39 }
type FourthFlatPointer41 struct{ *FourthFlatPointer40 }
type FourthFlatPointer42 struct{ *FourthFlatPointer41 }
type FourthFlatPointer43 struct{ *FourthFlatPointer42 }
type FourthFlatPointer44 struct{ *FourthFlatPointer43 }
type FourthFlatPointer45 struct{ *FourthFlatPointer44 }
type FourthFlatPointer46 struct{ *FourthFlatPointer45 }
type FourthFlatPointer47 struct{ *FourthFlatPointer46 }
type FourthFlatPointer48 struct{ *FourthFlatPointer47 }
type FourthFlatPointer49 struct{ *FourthFlatPointer48 }
type FourthFlatPointer50 struct{ *FourthFlatPointer49 }
type FourthFlatPointer51 struct{ *FourthFlatPointer50 }
type FourthFlatPointer52 struct{ *FourthFlatPointer51 }
type FourthFlatPointer53 struct{ *FourthFlatPointer52 }
type FourthFlatPointer54 struct{ *FourthFlatPointer53 }
type FourthFlatPointer55 struct{ *FourthFlatPointer54 }
type FourthFlatPointer56 struct{ *FourthFlatPointer55 }
type FourthFlatPointer57 struct{ *FourthFlatPointer56 }
type FourthFlatPointer58 struct{ *FourthFlatPointer57 }
type FourthFlatPointer59 struct{ *FourthFlatPointer58 }
type FourthFlatPointer60 struct{ *FourthFlatPointer59 }
type FourthFlatPointer61 struct{ *FourthFlatPointer60 }
type FourthFlatPointer62 struct{ *FourthFlatPointer61 }
type FourthFlatPointer63 struct{ *FourthFlatPointer62 }
type FourthFlatPointer64 struct{ *FourthFlatPointer63 }

type fourthExplicitAnonymous struct {
	fourthFlatValue0 `json:"nested"`
}

type fourthOmitEmpty struct {
	Present string         `json:"present"`
	Slice   []any          `json:"slice,omitempty"`
	Map     map[string]any `json:"map,omitempty"`
}

type fourthObjectNode struct {
	Next         *fourthObjectNode `json:"next,omitempty"`
	OmittedSlice []any             `json:"omitted_slice,omitempty"`
	OmittedMap   map[string]any    `json:"omitted_map,omitempty"`
	Ignored      any               `json:"-"`
	hidden       any
}

func fourthAssertCanonical(t *testing.T, value any, want string) {
	t.Helper()
	got, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical bytes %q != %q", got, want)
	}
}

func fourthNonNilPointerEmbedding(t *testing.T, root reflect.Type) any {
	t.Helper()
	value := reflect.New(root).Elem()
	current := value
	for current.NumField() == 1 && current.Field(0).Kind() == reflect.Pointer {
		field := current.Field(0)
		field.Set(reflect.New(field.Type().Elem()))
		current = field.Elem()
	}
	return value.Interface()
}

func fourthNestedMaps(depth int) any {
	var value any = nil
	for range depth {
		value = map[string]any{"next": value}
	}
	return value
}

func fourthObjectChain(depth int, omittedAtLeaf bool) *fourthObjectNode {
	var root *fourthObjectNode
	for range depth {
		root = &fourthObjectNode{Next: root}
	}
	if omittedAtLeaf {
		current := root
		for current.Next != nil {
			current = current.Next
		}
		current.OmittedSlice = []any{}
		current.OmittedMap = map[string]any{}
	}
	return root
}

func TestCanonicalJSONAllowsFiniteNestedAndOverlappingSliceAliases(t *testing.T) {
	parent := make([]any, 2)
	child := parent[:1]
	parent[1] = child
	fourthAssertCanonical(t, parent, `[null,[null]]`)

	overlapping := make([]any, 3)
	overlapping[2] = overlapping[:2]
	fourthAssertCanonical(t, overlapping, `[null,null,[null,null]]`)

	backing := []any{"a", "b", "c"}
	fourthAssertCanonical(t, []any{backing[:2], backing[1:]}, `[["a","b"],["b","c"]]`)

	if _, err := EventSigningMessage(EventEnvelopeV1{
		NormalizedFields: map[string]any{"finite": parent},
	}); err != nil {
		t.Fatalf("event signing rejected finite slice alias: %v", err)
	}
	if _, err := ActionRecordHash(ActionRecordV1{
		Details: map[string]any{"finite": parent},
	}); err != nil {
		t.Fatalf("action hash rejected finite slice alias: %v", err)
	}
}

func TestCanonicalJSONStillRejectsActualSliceCycles(t *testing.T) {
	direct := make([]any, 1)
	direct[0] = direct

	capChanging := make([]any, 1, 2)
	capChanging[0] = capChanging[:1:1]

	first := make([]any, 1)
	second := make([]any, 1)
	first[0] = second
	second[0] = first

	for _, test := range []struct {
		name  string
		value any
	}{
		{"direct", direct},
		{"same-data-and-length-different-capacity", capChanging},
		{"indirect", first},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalJSON(test.value)
			if err == nil || !strings.Contains(err.Error(), "cyclic") {
				t.Fatalf("actual slice cycle did not fail explicitly: %v", err)
			}
		})
	}
}

func TestCanonicalJSONStillRejectsPointerAndMapCycles(t *testing.T) {
	pointerCycle := &fourthObjectNode{}
	pointerCycle.Next = pointerCycle
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle

	for _, test := range []struct {
		name  string
		value any
	}{
		{"pointer", pointerCycle},
		{"map", mapCycle},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalJSON(test.value)
			if err == nil || !strings.Contains(err.Error(), "cyclic") {
				t.Fatalf("actual reference cycle did not fail explicitly: %v", err)
			}
		})
	}
}

func TestCanonicalJSONDepthUsesEncodedContainers(t *testing.T) {
	fourthAssertCanonical(t, fourthFlatValue64{}, `{"value":0}`)
	fourthAssertCanonical(
		t,
		fourthNonNilPointerEmbedding(t, reflect.TypeOf(FourthFlatPointer64{})),
		`{"value":0}`,
	)
	fourthAssertCanonical(
		t,
		fourthExplicitAnonymous{fourthFlatValue0{Value: 1}},
		`{"nested":{"value":1}}`,
	)
	fourthAssertCanonical(
		t,
		fourthOmitEmpty{
			Present: "kept",
			Slice:   []any{},
			Map:     map[string]any{},
		},
		`{"present":"kept"}`,
	)

	fourthAssertCanonical(t, fourthNestedMaps(64), string(mustMarshalJSON(t, fourthNestedMaps(64))))
	fourthAssertCanonical(t, nestedArrays(64), string(mustMarshalJSON(t, nestedArrays(64))))
	fourthAssertCanonical(
		t,
		fourthObjectChain(64, true),
		string(mustMarshalJSON(t, fourthObjectChain(64, true))),
	)

	for _, test := range []struct {
		name  string
		value any
	}{
		{"map", fourthNestedMaps(65)},
		{"list", nestedArrays(65)},
		{"object", fourthObjectChain(65, false)},
	} {
		t.Run(test.name+"-depth-65", func(t *testing.T) {
			_, err := CanonicalJSON(test.value)
			if err == nil || !strings.Contains(err.Error(), "depth") {
				t.Fatalf("encoded depth 65 did not fail cleanly: %v", err)
			}
		})
	}
}

func TestCanonicalJSONIgnoredAndUnexportedFieldsDoNotAffectEncodedDepth(t *testing.T) {
	value := fourthObjectNode{
		Ignored: fourthNestedMaps(65),
		hidden:  nestedArrays(65),
	}
	fourthAssertCanonical(t, value, `{}`)
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCanonicalJSONValidatesStringKindMapKeysInKeyContext(t *testing.T) {
	fourthAssertCanonical(
		t,
		map[json.Number]any{json.Number("not-a-number"): 1},
		`{"not-a-number":1}`,
	)
	fourthAssertCanonical(
		t,
		map[json.Number]any{json.Number("-0"): 1},
		`{"-0":1}`,
	)
	fourthAssertCanonical(
		t,
		map[string]any{
			"nested": map[json.Number]any{json.Number("not-a-number"): 1},
		},
		`{"nested":{"not-a-number":1}}`,
	)
	fourthAssertCanonical(
		t,
		map[fourthNamedStringKey]any{"named": 1},
		`{"named":1}`,
	)

	textKeyValue := map[fourthTextStringKey]any{"literal": 1}
	if raw := string(mustMarshalJSON(t, textKeyValue)); raw != `{"literal":1}` {
		t.Fatalf("encoding/json invoked TextMarshaler for string-kind key: %s", raw)
	}
	fourthAssertCanonical(t, textKeyValue, `{"literal":1}`)

	invalidKey := fourthNamedStringKey(string([]byte{0xff}))
	if encoded, err := CanonicalJSON(map[fourthNamedStringKey]any{invalidKey: 1}); err == nil {
		t.Fatalf("invalid UTF-8 map key canonicalized as %s", encoded)
	}
	if encoded, err := CanonicalJSON(map[int]any{1: "x"}); err == nil {
		t.Fatalf("non-string map key canonicalized as %s", encoded)
	}
}

func TestCanonicalJSONKeepsJSONNumberValueRulesSeparateFromMapKeys(t *testing.T) {
	fourthAssertCanonical(
		t,
		map[string]any{"value": json.Number("1")},
		`{"value":1}`,
	)
	for _, number := range []json.Number{
		"not-a-number",
		"-0",
		"1.5",
		"18446744073709551616",
	} {
		t.Run(string(number), func(t *testing.T) {
			if encoded, err := CanonicalJSON(map[string]any{"value": number}); err == nil {
				t.Fatalf("invalid json.Number value canonicalized as %s", encoded)
			}
		})
	}
}

func TestSigningAndHashHelpersAllowJSONNumberStringKeys(t *testing.T) {
	numberKeyObject := map[json.Number]any{json.Number("not-a-number"): 1}
	if _, err := EventSigningMessage(EventEnvelopeV1{
		NormalizedFields: map[string]any{"object": numberKeyObject},
	}); err != nil {
		t.Fatalf("event signing rejected json.Number string key: %v", err)
	}
	if _, err := ActionRecordHash(ActionRecordV1{
		Details: map[string]any{"object": numberKeyObject},
	}); err != nil {
		t.Fatalf("action hash rejected json.Number string key: %v", err)
	}
}
