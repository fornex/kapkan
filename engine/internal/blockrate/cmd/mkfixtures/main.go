// Command mkfixtures writes the block-rate suite's committed pcap fixtures
// from the catalog in internal/blockrate.
//
// Run it via `make blockrate-fixtures` after changing a fixture; the drift gate
// (TestCommittedFixturesMatchTheCatalog) fails until the result is committed.
// It deliberately does NOT run as part of the build: the captures are the
// artifact of record, exactly as the BPF object and docs/config-schema.json
// are, and an artifact regenerated on every build is an artifact nobody
// reviews.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kapkan-io/kapkan/internal/blockrate"
)

func main() {
	dir := "internal/blockrate/testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := run(dir); err != nil {
		fmt.Fprintf(os.Stderr, "mkfixtures: %v\n", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fixtures := blockrate.Fixtures()
	keep := make(map[string]bool, len(fixtures))

	var total int
	for _, f := range fixtures {
		if err := f.Validate(); err != nil {
			return err
		}
		b, err := f.Pcap()
		if err != nil {
			return err
		}
		p := filepath.Join(dir, f.PcapName())
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		keep[f.PcapName()] = true
		total += len(b)
		fmt.Printf("%-28s %5d frames (%d attack, %d legit, %d allowlisted)  %7d bytes\n",
			f.PcapName(), len(f.Frames),
			f.Count(blockrate.RoleAttack), f.Count(blockrate.RoleLegit), f.Count(blockrate.RoleAllow),
			len(b))
	}

	// Sweep captures whose fixture was renamed or removed: a stale file would
	// still be embedded and would still look like part of the suite.
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".pcap" || keep[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
		fmt.Printf("removed stale %s\n", e.Name())
	}

	fmt.Printf("\n%d fixtures, %d bytes total\n", len(fixtures), total)
	return nil
}
