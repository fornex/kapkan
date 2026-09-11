package api

// The console's half of the edge-history contract (E6.7).
//
// console/views2.js reads the three edge-history responses by json key —
// `p.window_seconds`, `s.first_seen`, `e.event_time` — and a missing key in
// JavaScript is `undefined`, not an error: renaming one on the Go side leaves
// every Go gate green while the rps chart flat-lines at zero and the sources
// table renders em dashes. The console is embedded in this binary and shipped
// with it, so the two sides are one release and the field names are an internal
// contract this test writes down.
//
// The lists below are hand-maintained: they are what views2.js and api.js read
// TODAY, not every field the structs carry (the responses deliberately carry
// more — `decided`, `cleared`, `status_2xx` — for an API client that is not
// this console). Adding a field to a struct does not belong here; renaming one
// the console reads does.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/storage"
)

func TestConsoleEdgeHistoryContract(t *testing.T) {
	for _, tc := range []struct {
		what   string // where the console reads it
		typ    any
		fields []string
	}{
		{
			"EdgeHistoryDoc (api.js getEdgeHistory)",
			EdgeHistoryDoc{},
			[]string{"available", "zone", "step_seconds", "points"},
		},
		{
			// the two charts and the stats row under them
			"EdgeHistoryPoint (views2.js edgeHistoryCard)",
			storage.EdgeHistoryPoint{},
			[]string{"requests", "window_seconds", "denied", "challenged",
				"would_deny", "would_challenge", "h3_requests", "status_4xx", "status_5xx", "nodes"},
		},
		{
			"EdgeHistorySourcesDoc (api.js getEdgeHistorySources)",
			EdgeHistorySourcesDoc{},
			[]string{"available", "sources"},
		},
		{
			"EdgeSourceAgg (views2.js edgeHistorySourcesCard)",
			storage.EdgeSourceAgg{},
			[]string{"source", "state", "requests", "windows", "nodes", "first_seen", "last_seen"},
		},
		{
			"EdgeEventsDoc (api.js getEdgeEvents)",
			EdgeEventsDoc{},
			[]string{"available", "events"},
		},
		{
			"EdgeEventRow (views2.js edgeEventsCard)",
			storage.EdgeEventRow{},
			[]string{"event_time", "kind", "node", "zone", "detail"},
		},
	} {
		have := jsonKeys(reflect.TypeOf(tc.typ))
		for _, key := range tc.fields {
			if !have[key] {
				t.Errorf("%s: the console reads %q, which is not a json key of this struct any more — console/views2.js and console/api.js read it by name and would silently render nothing",
					tc.what, key)
			}
		}
	}
}

// jsonKeys is the set of json names a struct marshals, "-" and unnamed fields
// aside.
func jsonKeys(rt reflect.Type) map[string]bool {
	keys := make(map[string]bool, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}
