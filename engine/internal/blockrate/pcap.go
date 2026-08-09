package blockrate

// The committed captures.
//
// WHY THEY ARE COMMITTED AT ALL, given that the catalog can regenerate them in
// microseconds: a block-rate number is only reproducible if the bytes that
// produced it are. An operator, a reviewer or a future maintainer must be able
// to open the exact frames a claim was measured on in Wireshark, replay them
// with tcpreplay against a real NIC, or diff them across a release — none of
// which is possible against a generator that runs inside the test binary.
//
// WHY THEY ARE ALSO BYTE-COMPARED against the catalog on every run: a capture
// nothing checks is a capture that silently stops being the thing the code
// under test believes it is. TestCommittedFixturesMatchTheCatalog is the gate,
// and it runs on every host — including the macOS development loop, where the
// kernel half of the suite cannot run at all — so a fixture edit that forgot to
// regenerate fails in one second rather than in CI.

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"

	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

// fixtureFS holds the committed captures. Embedding rather than opening
// testdata/ by path is load-bearing: the kernel half of this suite runs from a
// different package's directory (and, under `make dataplane-test`, from inside
// a container with a different working directory), so a relative path would
// work in exactly one of the three places it is used.
//
//go:embed testdata/*.pcap
var fixtureFS embed.FS

// pcapDir is where the captures live inside fixtureFS and on disk.
const pcapDir = "testdata"

// Pcap renders the fixture's frames as a classic libpcap stream. It is
// deterministic: identical input yields byte-identical output, which is what
// makes the committed files diffable.
func (f Fixture) Pcap() ([]byte, error) {
	var buf bytes.Buffer
	if err := pktgen.WritePcap(&buf, f.Frames); err != nil {
		return nil, fmt.Errorf("blockrate: %s: %w", f.Name, err)
	}
	return buf.Bytes(), nil
}

// CommittedPcap returns the raw bytes of the fixture's committed capture.
func (f Fixture) CommittedPcap() ([]byte, error) {
	b, err := fixtureFS.ReadFile(path.Join(pcapDir, f.PcapName()))
	if err != nil {
		return nil, fmt.Errorf("blockrate: %s: %w (run `make blockrate-fixtures`)", f.Name, err)
	}
	return b, nil
}

// CommittedFrames reads the fixture's committed capture back into frames.
//
// THIS, not Fixture.Frames, is what the suite replays. The distinction is the
// whole reason the files exist: the numbers must come from the bytes on disk,
// so that a corrupted, truncated or stale capture produces a failing run rather
// than a passing one measured on something else.
func (f Fixture) CommittedFrames() ([]pktgen.Frame, error) {
	b, err := f.CommittedPcap()
	if err != nil {
		return nil, err
	}
	frames, err := pktgen.ReadPcap(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("blockrate: %s: %w", f.Name, err)
	}
	if len(frames) != len(f.Roles) {
		return nil, fmt.Errorf(
			"blockrate: %s: the committed capture holds %d frames but the catalog labels %d; "+
				"the roles would be misaligned and every rate meaningless (run `make blockrate-fixtures`)",
			f.Name, len(frames), len(f.Roles))
	}
	return frames, nil
}

// CommittedNames lists every capture file present in the embedded set, so a
// stale file left behind by a renamed fixture can be detected instead of
// quietly shipping.
func CommittedNames() ([]string, error) {
	ents, err := fs.ReadDir(fixtureFS, pcapDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}
