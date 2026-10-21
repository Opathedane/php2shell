package rules

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleBundle() Bundle {
	return Bundle{Schema: Schema, Sequence: 10, Issued: time.Now().UTC().Add(-time.Hour), Expires: time.Now().UTC().Add(48 * time.Hour), Indicators: []Indicator{{ID: "unit.http.001", Type: "http_target_literal", Value: "test-marker", Severity: "medium", Confidence: "suspected", Description: "Synthetic test only", Source: "https://example.org/test"}, {ID: "unit.sha.002", Type: "file_sha256", Value: strings.Repeat("a", 64), Severity: "high", Confidence: "corroborated", Source: "https://example.org/test"}}}
}
func TestEd25519SigningAndTamper(t *testing.T) {
	pub, priv, e := Keygen()
	if e != nil {
		t.Fatal(e)
	}
	signed, e := Sign(sampleBundle(), priv)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(signed, pub, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	var env Envelope
	json.Unmarshal(signed, &env)
	env.Payload = env.Payload[:len(env.Payload)-8] + "AAAAAA=="
	changed, _ := json.Marshal(env)
	if _, e = Verify(changed, pub, time.Now().UTC()); e == nil {
		t.Fatal("tampered rule data accepted")
	}
	wrong, _, _ := Keygen()
	if _, e = Verify(signed, wrong, time.Now().UTC()); e == nil {
		t.Fatal("wrong signing key accepted")
	}
}
func TestValidationRejectsInvalidOrExpired(t *testing.T) {
	b := sampleBundle()
	b.Indicators[0].Type = "shell"
	if Validate(b, time.Now().UTC()) == nil {
		t.Fatal("executable rule type accepted")
	}
	b = sampleBundle()
	b.Indicators[0].Value = "x"
	if Validate(b, time.Now().UTC()) == nil {
		t.Fatal("short rule accepted")
	}
	b = sampleBundle()
	b.Expires = time.Now().UTC().Add(-time.Minute)
	if Validate(b, time.Now().UTC()) == nil {
		t.Fatal("expired bundle accepted")
	}
	b = sampleBundle()
	b.Indicators[1].Value = "bad"
	if Validate(b, time.Now().UTC()) == nil {
		t.Fatal("invalid file sha accepted")
	}
	b = sampleBundle()
	b.Indicators[1].ID = b.Indicators[0].ID
	if Validate(b, time.Now().UTC()) == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestCachedRuleRollbackRefused(t *testing.T) {
	// Override user config for this isolated test process.
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", home)
	}
	pub, priv, _ := Keygen()
	fp := filepath.Join(home, "public.hex")
	// Ed25519 public key accepts fixed hex representation.
	if e := os.WriteFile(fp, []byte(fmtHex(pub)), 0600); e != nil {
		t.Fatal(e)
	}
	if e := InstallPublic(fp); e != nil {
		t.Fatal(e)
	}
	first, _ := Sign(sampleBundle(), priv)
	if _, e := InstallSigned(first, ed25519.PublicKey(pub)); e != nil {
		t.Fatal(e)
	}
	if _, e := InstallSigned(first, ed25519.PublicKey(pub)); e != nil {
		t.Fatal("identical signed bundle should be an idempotent no-op:", e)
	}
	next := sampleBundle()
	next.Sequence = 11
	second, _ := Sign(next, priv)
	if _, e := InstallSigned(second, ed25519.PublicKey(pub)); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadCached(); e != nil {
		t.Fatal(e)
	}
	if _, e := InstallSigned(first, ed25519.PublicKey(pub)); e == nil {
		t.Fatal("old signed rule pack was accepted")
	}

}
func fmtHex(data []byte) string {
	const digits = "0123456789abcdef"
	s := make([]byte, len(data)*2)
	for i, b := range data {
		s[i*2] = digits[b>>4]
		s[i*2+1] = digits[b&15]
	}
	return string(s) + "\n"
}
