package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	in := &natsCreds{
		AgentID:  "agt_42",
		NATSURL:  "wss://nats.example.invalid",
		UserJWT:  "eyJhbGciOiJF...",
		UserSeed: "SUAATESTSEED",
		APIBase:  "https://api.example.invalid",
	}
	if err := saveCreds(path, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Permissions: must be tight — file holds an nkey seed.
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("creds file has loose perms: %o", st.Mode().Perm())
	}
	out, err := loadCreds(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.AgentID != in.AgentID || out.NATSURL != in.NATSURL || out.UserJWT != in.UserJWT {
		t.Errorf("round-trip mismatch: got %+v want %+v", *out, *in)
	}
}

func TestLoadCredsMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := loadCreds(filepath.Join(dir, "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

func TestDefaultCredsPathRespectsEnv(t *testing.T) {
	t.Setenv("HUGIN_AGENT_CREDS", "/tmp/custom/creds.json")
	if got := defaultCredsPath(); got != "/tmp/custom/creds.json" {
		t.Errorf("got %q", got)
	}
}
