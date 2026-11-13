package api

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Gates on the console's references OUT of itself: the i18n keys its source
// asks a catalog for. They are plain strings that nothing in the build checks —
// i18n.t() returns the key itself on a miss — so a typo ships green and is
// noticed only by a reader who sees "en.tokns" in the header.
//
// locale_parity_test.go guards the other direction: that every catalog carries
// the same keys as en.js. Nothing there notices a key the SOURCE asks for and
// no catalog has, because the five catalogs agree about not having it.
//
// Like the parity gate, this reads the canonical console/ tree rather than the
// copy embedded under internal/api/static/ (gitignored, refreshed by
// `make console-sync`), and skips when that tree is absent — engine/ checked
// out on its own. Because the input lives outside the module, `go test` can
// serve a cached PASS after it changes; `make -C engine test` and CI pass
// -count=1.

const (
	consoleDir = "../../../console"
)

// ---------------------------------------------------------------------------
// i18n keys the console asks for
// ---------------------------------------------------------------------------

// TestLocaleKeysUsedExist fails on a key the console renders that en.js does
// not define. A concatenated key — I.t("ed.h3.state." + state) — reaches us as
// the literal prefix "ed.h3.state." and is satisfied by any key beginning with
// it; the run-time half is the node's word and cannot be checked here.
func TestLocaleKeysUsedExist(t *testing.T) {
	en := loadCatalogs(t)[baseLocale]
	srcs := consoleSources(t)

	strs := en.fields["strings"]
	plur := en.fields["plurals"]
	if strs == nil || plur == nil {
		t.Fatalf("%s.js: no top-level \"strings\"/\"plurals\" — locale_parity_test.go covers that", baseLocale)
	}
	// i18n.js resolves t()/label-less lookups in `strings` and plural() in
	// `plurals`; the two namespaces are separate, so each call shape is
	// checked against its own.
	catalogs := map[string][]string{
		"strings": strs.paths("", 0),
		"plurals": plur.paths("", 1),
	}

	for _, file := range sortedKeys(srcs) {
		src := srcs[file]
		// I.t("k"), I.t(cond ? "a" : "b", {…}) and the two table-header
		// helpers, whose only argument is a key; I.plural(n, "k", {…}).
		used := map[string][]string{
			"strings": concat(
				callArgLiterals(src, "I.t", 0),
				callArgLiterals(src, "th", 0),
				callArgLiterals(src, "thNum", 0),
			),
			"plurals": callArgLiterals(src, "I.plural", 1),
		}
		for object, keys := range used {
			for _, key := range dedup(keys) {
				if hasKeyOrPrefix(catalogs[object], key) {
					continue
				}
				t.Errorf("%s asks for %s key %q, which %s/%s.js does not define — "+
					"i18n.js renders a missing key as the key itself, in every locale",
					file, object, key, localesDir, baseLocale)
			}
		}
	}
}

// hasKeyOrPrefix matches a literal key exactly, and a literal ENDING in "."
// (the stem of a computed key) against any key that starts with it.
func hasKeyOrPrefix(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
		if strings.HasSuffix(want, ".") && strings.HasPrefix(k, want) {
			return true
		}
	}
	return false
}

// callArgLiterals returns the double-quoted literals that make up argument
// argIndex of every call to fn in src. It is a scanner rather than a regex
// because the argument is not always one literal: `I.t(x ? "a" : "b")` is two,
// `I.t("ed.h3.state." + s)` is a prefix, and `I.t(item.key)` is none — while a
// regex stopping at the first comma would read `{ t: a.join(", ") }` as a key
// and one stopping at the first `)` would miss `I.plural(n, "k")` entirely.
func callArgLiterals(src []byte, fn string, argIndex int) []string {
	var out []string
	s := string(src)
	open := fn + "("
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], open)
		if j < 0 {
			break
		}
		start := i + j
		i = start + len(open)
		// `hgth(` and `width(` are not `th(`: a call is only ours when the
		// character before the name cannot continue an identifier.
		if start > 0 && isIdentByte(s[start-1]) {
			continue
		}
		out = append(out, argLiterals(s, i, argIndex)...)
	}
	return out
}

// argLiterals scans one argument list, starting just after its "(", and
// returns the literals of argument argIndex. Nested calls, objects and arrays
// keep their own depth, so only a top-level comma advances the argument and
// only a top-level literal is a candidate key; it stops at the matching ")".
//
// A ternary is where the argument holds more than one literal, and the test
// `a.direction === "outgoing" ? "ac.topdest" : "ac.topsources"` puts a
// NON-key among them. Once a top-level "?" is seen, therefore, only what
// follows it counts — the condition is a comparison, never a key.
func argLiterals(s string, pos, argIndex int) []string {
	var before, after []string
	depth, arg, ternary := 0, 0, false
	for p := pos; p < len(s); p++ {
		switch c := s[p]; c {
		case '"', '\'', '`':
			end := p + 1
			for ; end < len(s) && s[end] != c; end++ {
				if s[end] == '\\' {
					end++
				}
			}
			if c == '"' && arg == argIndex && depth == 0 {
				lit := s[p+1 : min(end, len(s))]
				if ternary {
					after = append(after, lit)
				} else {
					before = append(before, lit)
				}
			}
			p = end
		case '(', '[', '{':
			depth++
		case ')':
			if depth == 0 {
				return pick(before, after, ternary)
			}
			depth--
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				arg++
			}
		case '?':
			if depth == 0 && arg == argIndex {
				ternary = true
			}
		}
	}
	return pick(before, after, ternary)
}

func pick(before, after []string, ternary bool) []string {
	if ternary {
		return after
	}
	return before
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// consoleSources reads every console/*.js. The locale catalogs are deliberately
// excluded: they are the definitions these gates check against, not call sites.
func consoleSources(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(consoleDir, "*.js"))
	if err != nil {
		t.Fatalf("glob %s: %v", consoleDir, err)
	}
	if len(paths) == 0 {
		t.Skipf("%s/*.js not present — the console's references cannot be checked from this checkout", consoleDir)
	}
	srcs := make(map[string][]byte, len(paths))
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		srcs[filepath.ToSlash(p)] = src
	}
	return srcs
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func dedup(list []string) []string {
	seen := make(map[string]bool, len(list))
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
