package storage

import (
	"reflect"
	"strings"
	"testing"
)

// TestEdgeRowsCarryNoKeyMaterial extends the edge report's "not a byte of
// key material" rule (api's TestEdgeReportCarriesNoKeyMaterial) to what the
// brain writes from those reports (E6.5): no row type may carry a field whose
// name smells of a secret, a byte slice, or a free-form container.
func TestEdgeRowsCarryNoKeyMaterial(t *testing.T) {
	bad := []string{"key", "private", "secret", "pem", "token", "credential", "passphrase", "password", "chain"}
	for _, rt := range []reflect.Type{reflect.TypeOf(EdgeWindowRow{}), reflect.TypeOf(EdgeSourceRow{}), reflect.TypeOf(EdgeEventRow{})} {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "" {
				t.Errorf("%s.%s has no json tag — every row column is named explicitly (an untagged field is still written, under its Go name)", rt.Name(), f.Name)
			}
			for _, b := range bad {
				if strings.Contains(strings.ToLower(tag+" "+f.Name), b) {
					t.Errorf("%s.%s (json %q) — a history row must never carry key material", rt.Name(), f.Name, tag)
				}
			}
			switch f.Type.Kind() {
			case reflect.Slice, reflect.Map, reflect.Interface, reflect.Pointer, reflect.Struct:
				t.Errorf("%s.%s is a %s — a history row is flat scalars only", rt.Name(), f.Name, f.Type.Kind())
			}
		}
	}
}
