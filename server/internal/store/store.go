// Package store keeps the secrets (specs/003) and the variables (specs/018): one JSON document in memory,
// written after every change to an AES-256-GCM-encrypted file when a path is configured. Nothing here logs
// material or a value.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// Secret is one stored secret. Params keep the protocol's typed values verbatim.
type Secret struct {
	Name       string                     `json:"name"`
	Type       string                     `json:"type"`
	Provider   string                     `json:"provider"`
	Scope      []string                   `json:"scope"`
	Params     map[string]json.RawMessage `json:"params"`
	RedactKeys []string                   `json:"redact_keys"`
	Comment    string                     `json:"comment"`
	Owner      string                     `json:"owner"`
	CreatedAt  time.Time                  `json:"created_at"`
	UpdatedAt  time.Time                  `json:"updated_at"`
	Version    int64                      `json:"version"`
	Grants     []Grant                    `json:"grants"`
	// (a file written before specs/009 may carry "delegations": rules, which are dropped on load)
}

// Grant gives a principal verbs on one secret.
type Grant struct {
	ID        string   `json:"id"`
	Principal string   `json:"principal"`
	Verbs     []string `json:"verbs"`
}

// ErrNotFound and ErrPrecondition are the store's two refusals; the API maps them to 404 and 412.
var (
	ErrNotFound     = errors.New("not found")
	ErrPrecondition = errors.New("precondition failed")
)

// sealAAD binds the file to this format. It keeps the binary's former name: a file written before the
// rename to ref-server still opens.
const sealAAD = "tresor-server/1"

// Store is safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	secrets   map[string]*Secret
	variables map[string]*Secret // specs/018: a variable is kept as a secret whose params hold "value"
	path      string
	aead      cipher.AEAD
}

type document struct {
	Secrets   []*Secret `json:"secrets"`
	Variables []*Secret `json:"variables,omitempty"`
}

// Open returns an in-memory store for an empty path; otherwise it decrypts the file (a missing file is
// an empty store). A file that does not decrypt is an error: the store is never overwritten blind.
func Open(path string, key []byte) (*Store, error) {
	s := &Store{secrets: map[string]*Secret{}, variables: map[string]*Secret{}, path: path}
	if path == "" {
		return s, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("store: the key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if s.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("store: the file is truncated")
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(sealAAD))
	if err != nil {
		return nil, errors.New("store: the file does not decrypt with this key - refusing to start")
	}
	var doc document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	for _, sec := range doc.Secrets {
		s.secrets[sec.Name] = sec
	}
	for _, v := range doc.Variables {
		s.variables[v.Name] = v
	}
	return s, nil
}

// persist writes the whole document, encrypted, atomically. Called with the lock held.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	doc := document{Secrets: make([]*Secret, 0, len(s.secrets))}
	for _, sec := range s.secrets {
		doc.Secrets = append(doc.Secrets, sec)
	}
	for _, v := range s.variables {
		doc.Variables = append(doc.Variables, v)
	}
	plain, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(sealAAD))
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".secrets-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func clone(sec *Secret) *Secret {
	data, _ := json.Marshal(sec)
	var out Secret
	_ = json.Unmarshal(data, &out)
	return &out
}

// List returns copies of every secret, sorted by name.
func (s *Store) List() []*Secret { return s.list(s.secrets) }

// Get returns a copy of one secret.
func (s *Store) Get(name string) (*Secret, error) { return s.get(s.secrets, name) }

// Update runs fn on the current secret (nil when absent) under the store's lock. fn returns the new
// secret (nil: delete) or an error that aborts the change; the result is persisted before Update
// returns. This is the one write path, so every check fn makes is atomic with the write.
func (s *Store) Update(name string, fn func(current *Secret) (*Secret, error)) (*Secret, error) {
	return s.update(s.secrets, name, fn)
}

// Variables is the store's other namespace (specs/018): the same methods, its own names, the same file.
type Variables struct{ s *Store }

// Variables returns the variables' namespace.
func (s *Store) Variables() *Variables { return &Variables{s} }

func (v *Variables) List() []*Secret                  { return v.s.list(v.s.variables) }
func (v *Variables) Get(name string) (*Secret, error) { return v.s.get(v.s.variables, name) }
func (v *Variables) Update(name string, fn func(current *Secret) (*Secret, error)) (*Secret, error) {
	return v.s.update(v.s.variables, name, fn)
}

func (s *Store) list(m map[string]*Secret) []*Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Secret, 0, len(m))
	for _, sec := range m {
		out = append(out, clone(sec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) get(m map[string]*Secret, name string) (*Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(sec), nil
}

func (s *Store) update(m map[string]*Secret, name string, fn func(current *Secret) (*Secret, error)) (*Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current *Secret
	if sec, ok := m[name]; ok {
		current = clone(sec)
	}
	next, err := fn(current)
	if err != nil {
		return nil, err
	}
	previous, existed := m[name]
	if next == nil {
		if !existed {
			return nil, ErrNotFound
		}
		delete(m, name)
	} else {
		next.Name = name
		m[name] = clone(next)
	}
	if err := s.persist(); err != nil {
		// the change did not reach the disk: undo it in memory too
		if existed {
			m[name] = previous
		} else {
			delete(m, name)
		}
		return nil, fmt.Errorf("store: %w", err)
	}
	return next, nil
}

// VerbsOf is the grant part of a caller's verbs on sec: the union of the grants to its principals.
func VerbsOf(sec *Secret, principals []string) []string {
	var out []string
	for _, g := range sec.Grants {
		if slices.Contains(principals, g.Principal) {
			for _, v := range g.Verbs {
				if !slices.Contains(out, v) {
					out = append(out, v)
				}
			}
		}
	}
	return out
}
