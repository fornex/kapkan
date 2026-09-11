package api

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Locale parity gate for the operator console.
//
// console/locales/{en,de,ru,fr,es}.js are hand-maintained with no sync tooling,
// and i18n.js resolves any key a catalog is missing against the English one
// (see t(), label(), labelShort(), plural()). A forgotten key therefore renders
// perfectly — in English — so the bug ships invisibly and nothing in the build
// notices. This file is the only guard: it compares the key sets of every
// catalog against en.js and fails with the exact missing/extra keys.
//
// It reads the CANONICAL console/ source, never the generated copy that the
// engine embeds from internal/api/static/ (gitignored, refreshed by `make
// console-sync`) — a stale copy would let the gate pass on the wrong bytes.
//
// Because those inputs live outside the module, `go test` can serve a cached
// PASS after a locale file changes. `make -C engine test` passes -count=1, so
// the gate is honest there and in CI; add -count=1 when running it by hand.

const (
	localesDir = "../../../console/locales"
	i18nPath   = "../../../console/i18n.js"

	// baseLocale is the catalog i18n.js falls back to, i.e. the one that
	// defines the complete key set every other locale has to match.
	baseLocale = "en"
)

// parityDepth caps how many levels of a top-level catalog object take part in
// the comparison. 0 walks all the way down to the leaves; the only exception is
// plurals, whose form names are language grammar rather than translator choice
// (ru carries one/few/many, en/de/fr/es only one/other). Its *keys* still have
// to match — TestLocaleParityPluralForms checks the forms instead.
var parityDepth = map[string]int{"plurals": 1}

// cldrForms are the plural categories Intl.PluralRules can select.
var cldrForms = map[string]bool{
	"zero": true, "one": true, "two": true, "few": true, "many": true, "other": true,
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestLocaleParityKeySets is the gate. Every catalog must expose the same
// top-level objects as en.js, and within each one the same key paths.
func TestLocaleParityKeySets(t *testing.T) {
	cats := loadCatalogs(t)
	base := cats[baseLocale]
	codes := otherCodes(cats)

	// 1. same top-level objects. A catalog missing "enumsShort" entirely does
	// not fail per-key below (there is nothing to compare), so check it first.
	baseTop := base.paths("", 1)
	for _, code := range codes {
		missing, extra := diffKeys(baseTop, cats[code].paths("", 1))
		if len(missing)+len(extra) > 0 {
			t.Error(report(code, "<top level>", len(baseTop), missing, extra))
		}
	}

	// 2. same keys inside each object.
	for _, obj := range baseTop {
		depth := parityDepth[obj]
		child := base.fields[obj]
		if child == nil {
			t.Fatalf("%s.js: top-level %q is not an object", baseLocale, obj)
		}
		want := child.paths("", depth)
		for _, code := range codes {
			got := cats[code].fields[obj]
			if got == nil {
				continue // already reported in step 1
			}
			missing, extra := diffKeys(want, got.paths("", depth))
			if len(missing)+len(extra) > 0 {
				t.Error(report(code, obj, len(want), missing, extra))
			}
		}
	}
}

// TestLocaleParityPluralForms covers what the key-set gate deliberately skips.
// i18n.plural() does `forms[cat] || forms.other`, so "other" is the one form
// that must exist in every catalog; anything outside the CLDR set is a typo
// that can never be selected.
func TestLocaleParityPluralForms(t *testing.T) {
	cats := loadCatalogs(t)
	for _, code := range allCodes(cats) {
		plurals := cats[code].fields["plurals"]
		if plurals == nil {
			continue // reported by TestLocaleParityKeySets
		}
		for _, key := range plurals.keys {
			forms := plurals.fields[key]
			if forms == nil {
				t.Errorf("%s.js: plurals.%s is not an object", code, key)
				continue
			}
			if _, ok := forms.fields["other"]; !ok {
				t.Errorf("%s.js: plurals.%s has no \"other\" form — i18n.plural() falls back to it", code, key)
			}
			for _, form := range forms.keys {
				if !cldrForms[form] {
					t.Errorf("%s.js: plurals.%s.%s is not a CLDR plural category — Intl.PluralRules can never select it", code, key, form)
				}
			}
		}
	}
}

// TestLocaleParityRegistered pins the AVAILABLE list in i18n.js against the
// catalogs on disk. A locale offered in the switcher with no catalog renders
// 100% English and reads as a broken translation rather than a missing file.
func TestLocaleParityRegistered(t *testing.T) {
	cats := loadCatalogs(t)
	src, err := os.ReadFile(i18nPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("%s not present — see loadCatalogs", i18nPath)
		}
		t.Fatalf("read %s: %v", i18nPath, err)
	}
	// AVAILABLE is an array literal, not an object, so it is matched rather
	// than parsed; the entries are a fixed `code: "xx"` shape.
	var declared []string
	for _, m := range regexp.MustCompile(`\bcode:\s*"([a-zA-Z-]+)"`).FindAllSubmatch(src, -1) {
		declared = append(declared, string(m[1]))
	}
	if len(declared) == 0 {
		t.Fatalf("%s: found no `code: \"xx\"` entries — AVAILABLE changed shape, update this test", i18nPath)
	}
	missing, extra := diffKeys(declared, allCodes(cats))
	for _, code := range missing {
		t.Errorf("%s offers locale %q but %s/%s.js does not exist — the switcher would serve English", i18nPath, code, localesDir, code)
	}
	for _, code := range extra {
		t.Errorf("%s/%s.js exists but %q is not in AVAILABLE in %s — the catalog is unreachable", localesDir, code, code, i18nPath)
	}
}

// TestLocaleParityParserSelfCheck validates the parser against a hand count of
// en.js, so a parser that silently swallowed half the catalog cannot make the
// gate above pass vacuously. The counts were taken with:
//
//	cd console/locales
//	awk '/^    strings: \{/{f=1;next} /^    \},?$/{f=0} f' en.js |
//	    grep -oE '"[^"]+"[[:space:]]*:' | sort -u | wc -l    # → 265 strings
//
// and by counting the enum members by hand (direction 2, scope 2, method 4,
// banState 3, action 5, calc 2, attackType 12, metric 13 = 43 across 8 groups).
// Bump these when the catalog legitimately grows.
//
// The data plane added: 3 strings (dryrun.dp.{simulating,enforcing,also}), one
// member to enums.method, one to enums.action, and one to enumsShort.action.
//
// Measured in-kernel drops added 22 more strings, all of them new keys and none
// of them renamed: col.dropped, the seven dp.*/ac.inkernel keys the bans table
// and the drawer panel render, and the fourteen se.dp.* keys of the Settings
// card (243 + 22 = 265).
//
// The filter-bypass alarm added 4: dp.bypass.{banner,act,card,tip}, the text of
// the "packets were passed with no rule evaluated" warning on Overview and on
// the data-plane card (265 + 4 = 269).
//
// The scrubbing Nodes view added 23: nav.nodes, col.node, and the twenty-one
// nd.* keys of the inventory table, its states, its provenance labels and its
// error/empty notes (269 + 23 + 32 = 324).
//
// The Edge view's HTTP/3 cell (E5.5) added 12 strings — ed.h3 (the column),
// ed.h3.{on,off}, the four ed.h3.state.* readings a node's terminator.h3 can
// report, and the five ed.h3.tip.* tooltips (324 + 12 = 336) — plus two plural
// keys, edgeH3ReadyNodes and edgeH3StillServing (10 + 2 = 12 keys; in en, 20 +
// 4 = 24 forms).
//
// The fleet console (E6.7) added 34 strings: nine ed.* for the zones table's
// tenant chips, its placement cell and the three readings a file-seeded row
// can carry where a rung cannot be read off, plus nav.edgenodes and 24 en.*
// for the Edge nodes view (336 + 34 = 370), and one plural key,
// edgeUnboundTokens (12 + 1 = 13 keys; in en, 24 + 2 = 26 forms).
//
// The Edge view's zone-history card (E6.7) added 36 strings — the nineteen
// ed.hist.* of the card itself (its title, the three range ids, the chart and
// stats labels, and its loading / error / gone / empty / storage-off states),
// the seven ed.srcs.* of the "who would have been challenged over the period"
// table (its own error state included: a sources read can fail while the
// charts' read succeeds), ed.state.{denied,challenged} (the two states the
// stored history has and a ten-second window does not), and the eight ed.ev.*
// of the fleet-events card (336 + 34 + 36 = 406) — plus a NINTH enum group,
// edgeEventKind, whose sixteen members are the event kinds the write path
// emits (43 + 16 = 59): an enum rather than sixteen strings so a newer
// kapkan's seventeenth kind renders as its raw name instead of vanishing.
// TestLocaleEdgeEventKindsMatchWritePath pins that group to the Go list.
func TestLocaleParityParserSelfCheck(t *testing.T) {
	en := loadCatalogs(t)[baseLocale]
	for _, tc := range []struct {
		object string
		depth  int // 0 = leaves
		want   int
	}{
		{"units", 0, 4},
		{"plurals", 1, 13},
		{"plurals", 0, 26},  // 13 keys × {one, other}: 5 + edgeNodesUp, edgeWatchOnlyNodes, edgeReportingNodes, edgeActiveOnNodes, edgeBitingNodes + edgeH3ReadyNodes, edgeH3StillServing (E5.5) + edgeUnboundTokens (E6.7)
		{"strings", 0, 406}, // +23: nav.nodes, col.node, nd.*; +32: nav.edge, ed.* (E4.5); +12: ed.h3* (E5.5); +34: ed.tenant/placement + nav.edgenodes + en.* (E6.7 fleet); +36: ed.hist/srcs/ev/state (E6.7 history)
		{"enums", 1, 9},
		{"enums", 0, 59}, // +16: edgeEventKind (E6.7)
		{"enumsShort", 1, 1},
		{"enumsShort", 0, 5},
	} {
		obj := en.fields[tc.object]
		if obj == nil {
			t.Errorf("%s.js: no top-level %q", baseLocale, tc.object)
			continue
		}
		if got := len(obj.paths("", tc.depth)); got != tc.want {
			t.Errorf("%s.js: %s at depth %d: parsed %d keys, hand count says %d — the parser is wrong, or the catalog grew and this count needs bumping",
				baseLocale, tc.object, tc.depth, got, tc.want)
		}
	}
}

// TestLocaleEdgeEventKindsMatchWritePath pins the console's edgeEventKind enum
// to the kinds the write path actually emits (edgeEventKindList).
//
// The console renders an unknown kind as its raw name on purpose, so a newer
// kapkan's kind is never dropped from the fleet-events table — which also means
// a kind added here with no locale entry ships as `report_cut` in five
// languages with every other gate green. The parity gate cannot see it: it
// compares the catalogs against one another, and en.js is the one being
// forgotten. The reverse, a label for a kind the brain no longer emits, is dead
// weight a translator keeps re-translating, so both directions fail.
func TestLocaleEdgeEventKindsMatchWritePath(t *testing.T) {
	en := loadCatalogs(t)[baseLocale]
	enums := en.fields["enums"]
	if enums == nil {
		t.Fatalf("%s.js: no top-level %q", baseLocale, "enums")
	}
	kinds := enums.fields["edgeEventKind"]
	if kinds == nil {
		t.Fatalf("%s.js: enums.edgeEventKind is missing — the fleet-events card would label every kind with its raw name", baseLocale)
	}
	missing, extra := diffKeys(edgeEventKindList, kinds.paths("", 0))
	for _, k := range missing {
		t.Errorf("%s/%s.js: enums.edgeEventKind has no entry for %q, which the write path emits — the card renders the raw kind name in every language",
			localesDir, baseLocale, k)
	}
	for _, k := range extra {
		t.Errorf("%s/%s.js: enums.edgeEventKind labels %q, which edgeEventKindList does not emit — a renamed or dropped kind leaves a label nothing can reach",
			localesDir, baseLocale, k)
	}
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

// loadCatalogs parses every console/locales/*.js. Locales are discovered from
// the directory rather than hard-coded so a sixth language is covered the day
// it lands.
func loadCatalogs(t *testing.T) map[string]*jsObject {
	t.Helper()
	entries, err := os.ReadDir(localesDir)
	if err != nil {
		if os.IsNotExist(err) {
			// console/ is checked in, so this only happens in a partial
			// checkout (engine/ pulled out of the monorepo on its own).
			t.Skipf("%s not present — locale parity cannot be checked from this checkout", localesDir)
		}
		t.Fatalf("read %s: %v", localesDir, err)
	}
	cats := make(map[string]*jsObject)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".js") {
			continue
		}
		code := strings.TrimSuffix(name, ".js")
		path := filepath.Join(localesDir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		obj, err := parseCatalog(name, code, src)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		cats[code] = obj
	}
	if cats[baseLocale] == nil {
		t.Fatalf("%s/%s.js is missing — there is no catalog to compare against", localesDir, baseLocale)
	}
	return cats
}

func allCodes(cats map[string]*jsObject) []string {
	codes := make([]string, 0, len(cats))
	for code := range cats {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

func otherCodes(cats map[string]*jsObject) []string {
	var codes []string
	for _, code := range allCodes(cats) {
		if code != baseLocale {
			codes = append(codes, code)
		}
	}
	return codes
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

// diffKeys returns what `want` has that `got` lacks, and vice versa, sorted so
// the failure output diffs cleanly.
func diffKeys(want, got []string) (missing, extra []string) {
	in := func(list []string) map[string]bool {
		set := make(map[string]bool, len(list))
		for _, s := range list {
			set[s] = true
		}
		return set
	}
	wantSet, gotSet := in(want), in(got)
	for _, k := range want {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for _, k := range got {
		if !wantSet[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func report(code, object string, total int, missing, extra []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "locale %s.js is out of sync with %s.js in %q (%d keys expected)",
		code, baseLocale, object, total)
	if len(missing) > 0 {
		fmt.Fprintf(&b, "\n  missing from %s.js (%d):\n    %s", code, len(missing), strings.Join(missing, "\n    "))
	}
	if len(extra) > 0 {
		fmt.Fprintf(&b, "\n  not in %s.js (%d):\n    %s", baseLocale, len(extra), strings.Join(extra, "\n    "))
	}
	b.WriteString("\n  fix " + localesDir + "/" + code + ".js")
	switch {
	case len(missing) > 0 && len(extra) > 0:
		b.WriteString(" — likely a misspelled key: the missing one renders in English, the extra one is dead weight.")
	case len(missing) > 0:
		b.WriteString(" — a missing key silently renders the English string.")
	default:
		b.WriteString(" — the key is unreachable; either it is misspelled or en.js dropped it.")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// a very small JS object-literal reader
// ---------------------------------------------------------------------------
//
// The catalogs are plain nested object literals inside an IIFE, so a scanner is
// enough and keeps the engine free of a JS-parser dependency. It is written as
// a scanner rather than a regex on purpose: it tracks string literals and both
// comment forms, which a line-oriented regex cannot. Translated values contain
// apostrophes, quotes, commas, braces from {var} placeholders and — in fr/es —
// colons ("FlowSpec : limitation"), every one of which fools the obvious
// `/"key":/` pattern. TestLocaleParityParserSelfCheck pins the result against a
// hand count.

// jsObject is a parsed object literal: keys in source order, and for each key
// either a nested object or nil for a primitive (every catalog leaf is a
// string).
type jsObject struct {
	keys   []string
	fields map[string]*jsObject
}

// paths returns every key path in the object, joined with "/". maxDepth limits
// how far down it walks; 0 (or below) means all the way to the leaves.
func (o *jsObject) paths(prefix string, maxDepth int) []string {
	var out []string
	for _, k := range o.keys {
		path := k
		if prefix != "" {
			path = prefix + "/" + k
		}
		child := o.fields[k]
		if child == nil || maxDepth == 1 {
			out = append(out, path)
			continue
		}
		next := maxDepth
		if next > 0 {
			next--
		}
		out = append(out, child.paths(path, next)...)
	}
	return out
}

type jsParser struct {
	src  []byte
	pos  int
	name string // file name, for error messages
}

// parseCatalog returns the object assigned to w.KAPKAN_LOCALES.<code>.
func parseCatalog(name, code string, src []byte) (*jsObject, error) {
	marker := []byte("KAPKAN_LOCALES." + code)
	for off := 0; ; {
		i := bytes.Index(src[off:], marker)
		if i < 0 {
			return nil, fmt.Errorf("%s: no assignment to w.KAPKAN_LOCALES.%s found "+
				"(the catalog must register itself under its own file name)", name, code)
		}
		p := &jsParser{src: src, pos: off + i + len(marker), name: name}
		off = p.pos
		if p.pos < len(src) && isIdentByte(src[p.pos]) {
			continue // a longer code, e.g. .en matching .enUS
		}
		p.skipSpace()
		if p.pos >= len(src) || src[p.pos] != '=' {
			continue
		}
		if p.pos+1 < len(src) && src[p.pos+1] == '=' {
			continue // a comparison, not the assignment
		}
		p.pos++
		p.skipSpace()
		return p.parseObject()
	}
}

func (p *jsParser) parseObject() (*jsObject, error) {
	if p.pos >= len(p.src) || p.src[p.pos] != '{' {
		return nil, p.fail("expected '{'")
	}
	p.pos++
	obj := &jsObject{fields: make(map[string]*jsObject)}
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated object literal")
		}
		switch p.src[p.pos] {
		case '}':
			p.pos++
			return obj, nil
		case ',':
			p.pos++
			continue
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, p.fail("key %q: expected ':'", key)
		}
		p.pos++
		p.skipSpace()
		var child *jsObject
		if p.pos < len(p.src) && p.src[p.pos] == '{' {
			if child, err = p.parseObject(); err != nil {
				return nil, err
			}
		} else if err := p.skipValue(); err != nil {
			return nil, err
		}
		if _, dup := obj.fields[key]; dup {
			// A duplicated key is legal JS (last wins) and would otherwise
			// hide a lost translation behind a matching key count.
			return nil, p.fail("duplicate key %q", key)
		}
		obj.keys = append(obj.keys, key)
		obj.fields[key] = child
	}
}

// parseKey reads a quoted or bare-identifier object key. Both appear in the
// catalogs: "nav.overview" is quoted, ntp_amplification is not.
func (p *jsParser) parseKey() (string, error) {
	if p.pos >= len(p.src) {
		return "", p.fail("expected an object key, got end of file")
	}
	if isQuote(p.src[p.pos]) {
		return p.readString()
	}
	start := p.pos
	for p.pos < len(p.src) && isIdentByte(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", p.fail("expected an object key, got %q", string(p.src[p.pos]))
	}
	return string(p.src[start:p.pos]), nil
}

// skipValue consumes a non-object value up to the ',' or '}' that ends it,
// stepping over quoted strings and bracketed groups so punctuation inside a
// translation cannot terminate it early.
func (p *jsParser) skipValue() error {
	depth := 0
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case isQuote(c):
			if _, err := p.readString(); err != nil {
				return err
			}
			continue
		case c == '/' && p.pos+1 < len(p.src) && (p.src[p.pos+1] == '/' || p.src[p.pos+1] == '*'):
			p.skipSpace()
			continue
		case c == '[' || c == '(' || c == '{':
			depth++
		case c == ']' || c == ')':
			depth--
		case c == '}':
			if depth == 0 {
				return nil
			}
			depth--
		case c == ',':
			if depth == 0 {
				return nil
			}
		}
		p.pos++
	}
	return p.fail("unterminated value")
}

// readString consumes a quoted literal and returns its raw contents. Backslash
// escapes are honoured so an escaped quote cannot end the token early.
func (p *jsParser) readString() (string, error) {
	quote := p.src[p.pos]
	p.pos++
	start := p.pos
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\\':
			p.pos += 2
			continue
		case quote:
			s := string(p.src[start:p.pos])
			p.pos++
			return s, nil
		}
		p.pos++
	}
	return "", p.fail("unterminated string literal")
}

// skipSpace advances past whitespace and both comment forms.
func (p *jsParser) skipSpace() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.pos++
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '*':
			end := bytes.Index(p.src[p.pos+2:], []byte("*/"))
			if end < 0 {
				p.pos = len(p.src)
				return
			}
			p.pos += 2 + end + 2
		default:
			return
		}
	}
}

func (p *jsParser) fail(format string, a ...any) error {
	return fmt.Errorf("%s:%d: %s", p.name, 1+bytes.Count(p.src[:p.pos], []byte("\n")), fmt.Sprintf(format, a...))
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
