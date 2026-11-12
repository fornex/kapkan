package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// releaseConfig is what the repository's .goreleaser.yaml says a release
// ships: the files each archive carries and what each package lays out.
type releaseConfig struct {
	Archives []struct {
		ID    string        `yaml:"id"`
		Files []shippedFile `yaml:"files"`
	} `yaml:"archives"`
	NFPMs []struct {
		ID       string        `yaml:"id"`
		Formats  []string      `yaml:"formats"`
		Contents []shippedFile `yaml:"contents"`
	} `yaml:"nfpms"`
}

// shippedFile is an archive file or a package's content: Src as goreleaser
// reads it, from the repository root, and Dst where it lands. A bare archive
// entry lands at its own path. Packager, when set on a package's content,
// puts it in that format only.
type shippedFile struct {
	Src, Dst, Packager string
}

func (f *shippedFile) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Src, f.Dst = n.Value, n.Value
		return nil
	}
	var entry struct {
		Src      string `yaml:"src"`
		Dst      string `yaml:"dst"`
		Packager string `yaml:"packager"`
	}
	if err := n.Decode(&entry); err != nil {
		return err
	}
	f.Src, f.Dst, f.Packager = entry.Src, entry.Dst, entry.Packager
	return nil
}

// A release ships the edge role's systemd unit and annotated config as it
// ships the brain's unit: in the archive's deploy/ and in both packages, at
// the paths kapkan.io/docs/edge-install and the README send operators to. 1.8.0's notes
// said the edge pair shipped while .goreleaser.yaml never listed it, and
// `goreleaser check` passes a config that drops an entry, so the config itself
// is read here.
func TestReleaseShipsTheUnitsAndTheEdgeExample(t *testing.T) {
	root := filepath.Join("..", "..", "..") // where goreleaser runs
	raw, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var rc releaseConfig
	if err := yaml.Unmarshal(raw, &rc); err != nil {
		t.Fatalf(".goreleaser.yaml: %v", err)
	}
	if len(rc.Archives) == 0 || len(rc.NFPMs) == 0 {
		t.Fatalf(".goreleaser.yaml has %d archives and %d nfpms; want both", len(rc.Archives), len(rc.NFPMs))
	}
	formats := []string{"deb", "rpm"}
	for _, p := range rc.NFPMs {
		for _, format := range formats {
			if !slices.Contains(p.Formats, format) {
				t.Errorf("nfpm %q builds no %s", p.ID, format)
			}
		}
	}
	for _, f := range []struct{ src, archive, pkg string }{
		{"engine/deploy/kapkan.service", "deploy/kapkan.service", "/usr/lib/systemd/system/kapkan.service"},
		{"engine/deploy/kapkan-edge.service", "deploy/kapkan-edge.service", "/usr/share/kapkan/kapkan-edge.service"},
		{"engine/deploy/edge.example.yaml", "deploy/edge.example.yaml", "/usr/share/kapkan/edge.example.yaml"},
	} {
		if fi, err := os.Stat(filepath.Join(root, f.src)); err != nil {
			t.Error(err)
		} else if !fi.Mode().IsRegular() {
			t.Errorf("%s is not a regular file", f.src)
		}
		for _, a := range rc.Archives {
			if !slices.Contains(a.Files, shippedFile{Src: f.src, Dst: f.archive}) {
				t.Errorf("archive %q does not carry %s as %s", a.ID, f.src, f.archive)
			}
		}
		for _, p := range rc.NFPMs {
			for _, format := range formats {
				if !slices.ContainsFunc(p.Contents, func(c shippedFile) bool {
					return c.Src == f.src && c.Dst == f.pkg && (c.Packager == "" || c.Packager == format)
				}) {
					t.Errorf("nfpm %q does not put %s in its %s as %s", p.ID, f.src, format, f.pkg)
				}
			}
		}
	}
}
