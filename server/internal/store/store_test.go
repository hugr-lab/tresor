package store

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "secrets.enc")
	k := key(t)
	s, err := Open(path, k)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Update("crm_ro", func(cur *Secret) (*Secret, error) {
		return &Secret{Type: "mssql", Params: map[string]json.RawMessage{"password": json.RawMessage(`"hunter2"`)}, Version: 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("hunter2")) || bytes.Contains(raw, []byte("crm_ro")) {
		t.Fatal("the file carries plaintext")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	again, err := Open(path, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Get("crm_ro")
	if err != nil || string(got.Params["password"]) != `"hunter2"` {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := Open(path, key(t)); err == nil {
		t.Fatal("a wrong key must refuse to start, not start empty")
	}
	if _, err := Open(path, []byte("short")); err == nil {
		t.Fatal("a short key must be refused")
	}
}

func TestUpdateSemantics(t *testing.T) {
	s, _ := Open("", nil)
	if _, err := s.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Update("x", func(cur *Secret) (*Secret, error) { return nil, nil }); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleting a missing secret is not found")
	}
	_, _ = s.Update("x", func(cur *Secret) (*Secret, error) { return &Secret{Type: "s3"}, nil })
	got, _ := s.Get("x")
	got.Type = "changed"
	if again, _ := s.Get("x"); again.Type != "s3" {
		t.Fatal("Get must return a copy")
	}
	boom := errors.New("boom")
	if _, err := s.Update("x", func(cur *Secret) (*Secret, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := s.Get("x"); err != nil {
		t.Fatal("a refused change must leave the secret")
	}
	if len(s.List()) != 1 {
		t.Fatal("list")
	}
}

func TestVerbsOf(t *testing.T) {
	sec := &Secret{Grants: []Grant{{ID: "a", Principal: "role:x", Verbs: []string{"use"}},
		{ID: "b", Principal: "group:y", Verbs: []string{"use", "annotate"}}}}
	got := VerbsOf(sec, []string{"role:x", "group:y"})
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if len(VerbsOf(sec, []string{"role:z"})) != 0 {
		t.Fatal("no grant, no verbs")
	}
}

// a change that cannot reach the disk is undone in memory too
func TestPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "secrets.enc"), key(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update("kept", func(*Secret) (*Secret, error) { return &Secret{Type: "s3"}, nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := s.Update("lost", func(*Secret) (*Secret, error) { return &Secret{Type: "s3"}, nil }); err == nil {
		t.Skip("the directory is writable anyway (running as root?)")
	}
	if _, err := s.Get("lost"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a create that did not persist must not stay in memory")
	}
	if _, err := s.Update("kept", func(*Secret) (*Secret, error) { return nil, nil }); err == nil {
		t.Fatal("the delete should fail to persist")
	}
	if _, err := s.Get("kept"); err != nil {
		t.Fatal("a delete that did not persist must not stay in memory")
	}
}
