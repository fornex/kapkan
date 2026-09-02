package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cert is what a node holds for a zone: paths (for the renderer) and public
// metadata (for the report). Never the key.
type Cert struct {
	Zone      string    `json:"zone"`
	Fullchain string    `json:"fullchain"`
	Key       string    `json:"key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Issuer    string    `json:"issuer"`
	// Directory is the CA directory that issued it.
	Directory string    `json:"directory"`
	IssuedAt  time.Time `json:"issued_at"`
}

// store is the on-disk layout under StateDir.
type store struct {
	dir string
}

func newStore(dir string) (*store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("acme: state dir %q must be absolute", dir)
	}
	for _, sub := range []string{"acme", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &store{dir: dir}, nil
}

// accountKey loads or creates the account key for a CA directory URL.
func (s *store) accountKey(directory string) (*ecdsa.PrivateKey, error) {
	sum := sha256.Sum256([]byte(directory))
	path := filepath.Join(s.dir, "acme", hex.EncodeToString(sum[:8])+".key")
	if raw, err := os.ReadFile(path); err == nil {
		return parseECKey(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func parseECKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("acme: key file is not an EC PRIVATE KEY")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func (s *store) certDir(zone string) string {
	return filepath.Join(s.dir, "certs", zone)
}

// load reads a zone's certificate metadata; ok is false when the zone has no
// complete certificate (no meta.json).
func (s *store) load(zone string) (Cert, bool, error) {
	raw, err := os.ReadFile(filepath.Join(s.certDir(zone), "meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Cert{}, false, nil
	}
	if err != nil {
		return Cert{}, false, err
	}
	var c Cert
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cert{}, false, fmt.Errorf("acme: %s meta.json: %w", zone, err)
	}
	if c.Zone != zone {
		return Cert{}, false, fmt.Errorf("acme: %s meta.json names zone %q", zone, c.Zone)
	}
	return c, true, nil
}

// save writes a new certificate for zone: the key first (0600), then the
// chain, then meta.json — the marker that the set is complete. Each file is
// written whole and renamed into place.
func (s *store) save(zone string, key *ecdsa.PrivateKey, chain [][]byte, directory string, now time.Time) (Cert, error) {
	dir := s.certDir(zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Cert{}, err
	}
	if len(chain) == 0 {
		return Cert{}, errors.New("acme: empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return Cert{}, fmt.Errorf("acme: leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Cert{}, err
	}
	var chainPEM []byte
	for _, der := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	c := Cert{
		Zone:      zone,
		Fullchain: filepath.Join(dir, "fullchain.pem"),
		Key:       filepath.Join(dir, "privkey.pem"),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Issuer:    leaf.Issuer.CommonName,
		Directory: directory,
		IssuedAt:  now,
	}
	if err := writeFileAtomic(c.Key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return Cert{}, err
	}
	if err := writeFileAtomic(c.Fullchain, chainPEM, 0o644); err != nil {
		return Cert{}, err
	}
	meta, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return Cert{}, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "meta.json"), append(meta, '\n'), 0o644); err != nil {
		return Cert{}, err
	}
	return c, nil
}

// inventory lists every zone with a complete certificate.
func (s *store) inventory() ([]Cert, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "certs"))
	if err != nil {
		return nil, err
	}
	var out []Cert
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, ok, err := s.load(e.Name())
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, c)
		}
	}
	return out, nil
}

// writeFileAtomic writes data to path.tmp with mode, fsyncs and renames.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// A pre-existing file keeps its old mode through OpenFile's O_CREATE; be
	// explicit so a key file is 0600 whatever was there before.
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
