package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Cert is what a node holds for a zone: paths (for the renderer) and public
// metadata (for the report and the renderer's generation marker). Never the
// key. Everything but Directory and IssuedAt is read from the files on disk,
// not from meta.json.
type Cert struct {
	Zone      string    `json:"zone"`
	Fullchain string    `json:"fullchain"`
	Key       string    `json:"key"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Issuer    string    `json:"issuer"`
	// Directory is the CA directory that issued it.
	Directory string    `json:"directory"`
	IssuedAt  time.Time `json:"issued_at"`
}

// meta.json carries only what the files cannot say.
type certMeta struct {
	Zone      string    `json:"zone"`
	Directory string    `json:"directory"`
	IssuedAt  time.Time `json:"issued_at"`
}

// zoneNameRe is a lower-case RFC 1123 hostname — what the brain emits and
// the only thing that may become a directory name under certs/.
var zoneNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// checkZoneName refuses anything that is not a hostname or would not be a
// plain path component.
func checkZoneName(zone string) error {
	if len(zone) > 238 || !zoneNameRe.MatchString(zone) || filepath.Base(zone) != zone {
		return fmt.Errorf("acme: zone %q is not a lower-case hostname", zone)
	}
	return nil
}

// store is the on-disk layout under StateDir:
//
//	acme/<hash of directory URL>.key           account key per CA (0600)
//	certs/<zone>/<generation>/privkey.pem       0600
//	certs/<zone>/<generation>/fullchain.pem
//	certs/<zone>/<generation>/meta.json         written last
//	certs/<zone>/current -> <generation>        the set nginx is pointed at
//
// A new certificate is a whole new generation directory, written and fsynced
// completely before ONE rename retargets `current` — so a crash at any point
// leaves either the previous set or the new one, never a key from one and a
// chain from another. The renderer names the files through `current`, so its
// paths are stable; a generation marker (the serial) tells it something
// changed.
type store struct {
	dir string
}

const (
	currentLink = "current"
	// keepGenerations is how many superseded certificate sets stay on disk
	// besides the current one.
	keepGenerations = 1
)

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

func (s *store) zoneDir(zone string) string {
	return filepath.Join(s.dir, "certs", zone)
}

// load reads a zone's current certificate set and verifies it: the chain
// parses, the key matches the leaf, and the dates come from the leaf. ok is
// false when the zone has no current set; an error means it has one that is
// unusable (corrupt or mismatched) — the caller treats that as "no
// certificate" and says so.
func (s *store) load(zone string) (Cert, bool, error) {
	if err := checkZoneName(zone); err != nil {
		return Cert{}, false, err
	}
	zd := s.zoneDir(zone)
	target, err := os.Readlink(filepath.Join(zd, currentLink))
	if errors.Is(err, os.ErrNotExist) {
		return Cert{}, false, nil
	}
	if err != nil {
		return Cert{}, false, fmt.Errorf("acme: %s: %w", zone, err)
	}
	gen := filepath.Join(zd, target)
	c := Cert{Zone: zone, Fullchain: filepath.Join(zd, currentLink, "fullchain.pem"), Key: filepath.Join(zd, currentLink, "privkey.pem")}
	if err := c.readFiles(filepath.Join(gen, "fullchain.pem"), filepath.Join(gen, "privkey.pem")); err != nil {
		return Cert{}, false, fmt.Errorf("acme: %s: %w", zone, err)
	}
	if raw, err := os.ReadFile(filepath.Join(gen, "meta.json")); err == nil {
		var m certMeta
		if json.Unmarshal(raw, &m) == nil && (m.Zone == "" || m.Zone == zone) {
			c.Directory, c.IssuedAt = m.Directory, m.IssuedAt
		}
	}
	return c, true, nil
}

// readFiles fills the certificate's public metadata from its files and
// verifies that the key belongs to the leaf.
func (c *Cert) readFiles(chainPath, keyPath string) error {
	pair, err := tls.LoadX509KeyPair(chainPath, keyPath)
	if err != nil {
		return fmt.Errorf("certificate and key do not form a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(c.Zone); err != nil {
		return fmt.Errorf("certificate does not cover %s: %w", c.Zone, err)
	}
	c.Serial = serialHex(leaf)
	c.NotBefore, c.NotAfter, c.Issuer = leaf.NotBefore, leaf.NotAfter, leaf.Issuer.CommonName
	return nil
}

func serialHex(leaf *x509.Certificate) string {
	if leaf.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(leaf.SerialNumber.Text(16))
}

// save installs a new certificate set for zone as a new generation: every
// file written and fsynced into a fresh directory, then `current` retargeted
// with one rename. Superseded generations beyond keepGenerations are removed.
func (s *store) save(zone string, key *ecdsa.PrivateKey, chain [][]byte, directory string, now time.Time) (Cert, error) {
	if err := checkZoneName(zone); err != nil {
		return Cert{}, err
	}
	if len(chain) == 0 {
		return Cert{}, errors.New("acme: empty certificate chain")
	}
	zd := s.zoneDir(zone)
	if err := os.MkdirAll(zd, 0o700); err != nil {
		return Cert{}, err
	}
	// The generation name is the issue time; a clock that stood still or
	// stepped back (a fake clock in tests, NTP in life) must not collide with
	// the set already there.
	genName := fmt.Sprintf("%d", now.UnixNano())
	for i := 1; ; i++ {
		if _, err := os.Lstat(filepath.Join(zd, genName)); errors.Is(err, os.ErrNotExist) {
			break
		}
		genName = fmt.Sprintf("%d-%d", now.UnixNano(), i)
	}
	gen := filepath.Join(zd, genName)
	tmp := gen + ".tmp"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return Cert{}, err
	}
	fail := func(err error) (Cert, error) {
		_ = os.RemoveAll(tmp)
		return Cert{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fail(err)
	}
	var chainPEM []byte
	for _, der := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := writeFileAtomic(filepath.Join(tmp, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(filepath.Join(tmp, "fullchain.pem"), chainPEM, 0o644); err != nil {
		return fail(err)
	}
	meta, err := json.MarshalIndent(certMeta{Zone: zone, Directory: directory, IssuedAt: now}, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(filepath.Join(tmp, "meta.json"), append(meta, '\n'), 0o644); err != nil {
		return fail(err)
	}
	// Verify what was written before pointing anything at it.
	c := Cert{Zone: zone, Fullchain: filepath.Join(zd, currentLink, "fullchain.pem"), Key: filepath.Join(zd, currentLink, "privkey.pem"), Directory: directory, IssuedAt: now}
	if err := c.readFiles(filepath.Join(tmp, "fullchain.pem"), filepath.Join(tmp, "privkey.pem")); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, gen); err != nil {
		return fail(err)
	}
	syncDir(zd)
	// One rename switches the set.
	link := filepath.Join(zd, currentLink)
	tmpLink := link + ".tmp"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(genName, tmpLink); err != nil {
		_ = os.RemoveAll(gen)
		return Cert{}, err
	}
	if err := os.Rename(tmpLink, link); err != nil {
		_ = os.Remove(tmpLink)
		_ = os.RemoveAll(gen)
		return Cert{}, err
	}
	syncDir(zd)
	s.prune(zd, genName)
	return c, nil
}

// prune removes superseded generations beyond keepGenerations and any
// leftover temporary directory.
func (s *store) prune(zd, current string) {
	entries, err := os.ReadDir(zd)
	if err != nil {
		return
	}
	var gens []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			_ = os.RemoveAll(filepath.Join(zd, name))
			continue
		}
		if name != current {
			gens = append(gens, name)
		}
	}
	// Generation names are nanosecond timestamps: lexical order by width is
	// unsafe across digit counts, so sort numerically-by-length-then-value.
	sort.Slice(gens, func(i, j int) bool {
		if len(gens[i]) != len(gens[j]) {
			return len(gens[i]) > len(gens[j])
		}
		return gens[i] > gens[j]
	})
	for i, g := range gens {
		if i >= keepGenerations {
			_ = os.RemoveAll(filepath.Join(zd, g))
		}
	}
}

// brokenZone is a certs/ entry the store could not load.
type brokenZone struct {
	zone string
	err  error
}

// inventory lists every zone with a usable current certificate set, and the
// zones whose set is unusable — one bad directory must not stop the others.
func (s *store) inventory() ([]Cert, []brokenZone, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "certs"))
	if err != nil {
		return nil, nil, err
	}
	var out []Cert
	var broken []brokenZone
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, ok, err := s.load(e.Name())
		if err != nil {
			broken = append(broken, brokenZone{zone: e.Name(), err: err})
			continue
		}
		if ok {
			out = append(out, c)
		}
	}
	return out, broken, nil
}

// writeFileAtomic writes data to path.tmp with mode, fsyncs, renames, and
// fsyncs the directory so the rename is durable.
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir makes renames in dir durable; best-effort, some filesystems refuse.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
