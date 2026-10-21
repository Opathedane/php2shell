// Package rules implements data-only Ed25519-signed indicator bundles.
// It never evaluates scripts, loads plugins, or executes downloaded content.
package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Schema = "php2shell-indicators/v1"
const limit = 1024 * 1024

var idRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{2,79}$`)
var hashRE = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// A signed rule pack is untrusted data until signature verification succeeds.
// Rules are deliberately limited to fixed substrings and SHA256, never code or regex.
type Indicator struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // http_target_literal or file_sha256
	Value       string `json:"value"`
	Severity    string `json:"severity"`   // info, low, medium, high
	Confidence  string `json:"confidence"` // unconfirmed, suspected, corroborated
	Description string `json:"description"`
	Source      string `json:"source"`
}
type Bundle struct {
	Schema     string      `json:"schema"`
	Sequence   uint64      `json:"sequence"`
	Issued     time.Time   `json:"issued_utc"`
	Expires    time.Time   `json:"expires_utc"`
	Indicators []Indicator `json:"indicators"`
}
type Envelope struct {
	Payload   string `json:"payload_base64"`
	Signature string `json:"signature_base64"`
}

func Validate(p Bundle, now time.Time) error {
	if p.Schema != Schema {
		return fmt.Errorf("unsupported rules schema")
	}
	if p.Sequence == 0 {
		return fmt.Errorf("invalid sequence")
	}
	if p.Issued.IsZero() || p.Expires.IsZero() || !p.Expires.After(p.Issued) {
		return fmt.Errorf("missing/invalid rule validity")
	}
	if p.Issued.After(now.Add(10 * time.Minute)) {
		return fmt.Errorf("rules issued in future")
	}
	if now.After(p.Expires) {
		return fmt.Errorf("rules expired")
	}
	if p.Expires.Sub(p.Issued) > 90*24*time.Hour {
		return fmt.Errorf("rules validity exceeds 90 days")
	}
	if len(p.Indicators) > 256 {
		return fmt.Errorf("too many indicators")
	}
	seen := map[string]bool{}
	for _, in := range p.Indicators {
		if !idRE.MatchString(in.ID) || seen[in.ID] {
			return fmt.Errorf("invalid/duplicate rule ID")
		}
		seen[in.ID] = true
		if in.Type != "http_target_literal" && in.Type != "file_sha256" {
			return fmt.Errorf("unsupported indicator type: %s", in.Type)
		}
		if in.Type == "file_sha256" {
			if !hashRE.MatchString(in.Value) {
				return fmt.Errorf("invalid SHA256 for %s", in.ID)
			}
		} else if len(in.Value) < 5 || len(in.Value) > 256 || strings.ContainsAny(in.Value, "\r\n\x00") {
			return fmt.Errorf("invalid HTTP literal %s", in.ID)
		}
		switch in.Severity {
		case "info", "low", "medium", "high":
		default:
			return fmt.Errorf("invalid severity %s", in.ID)
		}
		switch in.Confidence {
		case "unconfirmed", "suspected", "corroborated":
		default:
			return fmt.Errorf("invalid confidence %s", in.ID)
		}
		if len(in.Description) > 500 || len(in.Source) > 1024 || len(in.Source) < 8 {
			return fmt.Errorf("invalid source/description %s", in.ID)
		}
	}
	return nil
}

func Verify(data []byte, pub ed25519.PublicKey, now time.Time) (*Bundle, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	if len(data) > limit {
		return nil, fmt.Errorf("rule envelope exceeds limit")
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || len(payload) > limit {
		return nil, errors.New("invalid rule payload")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, errors.New("rule signature verification FAILED")
	}
	var bundle Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return nil, err
	}
	if err := Validate(bundle, now); err != nil {
		return nil, err
	}
	return &bundle, nil
}
func Sign(b Bundle, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key")
	}
	if err := Validate(b, time.Now().UTC()); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	env := Envelope{base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))}
	return json.MarshalIndent(env, "", "  ")
}
func Keygen() (pub, priv []byte, err error) {
	p, k, e := ed25519.GenerateKey(rand.Reader)
	return p, k, e
}
func ReadPublic(path string) (ed25519.PublicKey, error) {
	b, err := readRegular(path, 4096)
	if err != nil {
		return nil, err
	}
	bb, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(bb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected Ed25519 public key as 64 hexadecimal digits")
	}
	return ed25519.PublicKey(bb), nil
}
func ReadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := readRegular(path, 4096)
	if err != nil {
		return nil, err
	}
	bb, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(bb) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("expected Ed25519 private key as 128 hexadecimal digits")
	}
	return ed25519.PrivateKey(bb), nil
}
func readRegular(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not regular non-symlink file: %s", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("file too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("changed input type")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("could not read bounded regular file")
	}
	return b, nil
}
func WriteNew(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, e := f.Write(data)
	c := f.Close()
	if e != nil || c != nil {
		_ = os.Remove(path)
		return fmt.Errorf("could not write file: %v %v", e, c)
	}
	return nil
}
func ConfigDir() (string, error) {
	d, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "php2shell-assessment"), nil
}
func InstalledPublic() (ed25519.PublicKey, error) {
	d, e := ConfigDir()
	if e != nil {
		return nil, e
	}
	return ReadPublic(filepath.Join(d, "trusted-key.hex"))
}
func InstallPublic(path string) error {
	key, err := ReadPublic(path)
	if err != nil {
		return err
	}
	d, err := ConfigDir()
	if err != nil {
		return err
	}
	return WriteNew(filepath.Join(d, "trusted-key.hex"), []byte(hex.EncodeToString(key)+"\n"))
}
func FetchHTTPS(rawURL string) ([]byte, error) {
	u, e := url.Parse(rawURL)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() != "raw.githubusercontent.com" || u.Port() != "" || u.Fragment != "" {
		return nil, errors.New("rule update URL must be direct https://raw.githubusercontent.com/... without redirects or credentials")
	}
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused for rule update") }}
	resp, e := client.Get(rawURL)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("rules HTTP status %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil || len(b) > limit {
		return nil, errors.New("rules download too large or incomplete")
	}
	return b, nil
}

// Cache is updated only after verification and monotonic rollback checking.
// A never-overwritten backup state can be kept by the operator for stronger rollback resistance.
func InstallSigned(data []byte, pub ed25519.PublicKey) (*Bundle, error) {
	bundle, e := Verify(data, pub, time.Now().UTC())
	if e != nil {
		return nil, e
	}
	dir, e := ConfigDir()
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	existingPath := filepath.Join(dir, "signed-rules.json")
	if old, err := readRegular(existingPath, limit); err == nil {
		prev, e := Verify(old, pub, time.Now().UTC())
		if e == nil && bundle.Sequence <= prev.Sequence {
			if bundle.Sequence == prev.Sequence && string(data) == string(old) {
				return prev, nil
			}
			return nil, errors.New("rule sequence rollback or conflicting duplicate refused")
		}
		// Expired old bundles must not weaken rollback checks.
		if e != nil {
			var x Envelope
			if json.Unmarshal(old, &x) == nil {
				pay, _ := base64.StdEncoding.DecodeString(x.Payload)
				sig, _ := base64.StdEncoding.DecodeString(x.Signature)
				if ed25519.Verify(pub, pay, sig) {
					var p Bundle
					if json.Unmarshal(pay, &p) == nil && bundle.Sequence <= p.Sequence {
						return nil, errors.New("rule sequence rollback refused")
					}
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	temp, e := os.CreateTemp(dir, ".rules-*")
	if e != nil {
		return nil, e
	}
	tmp := temp.Name()
	defer os.Remove(tmp)
	if e = temp.Chmod(0600); e != nil {
		temp.Close()
		return nil, e
	}
	if _, e = temp.Write(data); e != nil {
		temp.Close()
		return nil, e
	}
	if e = temp.Sync(); e != nil {
		temp.Close()
		return nil, e
	}
	if e = temp.Close(); e != nil {
		return nil, e
	}
	// Refuse symlink targets; os.Rename is atomic within a directory on supported platforms.
	if fi, err := os.Lstat(existingPath); err == nil && !fi.Mode().IsRegular() {
		return nil, errors.New("rule cache destination is not a regular file")
	}
	if e = os.Rename(tmp, existingPath); e != nil {
		return nil, e
	}
	return bundle, nil
}
func LoadCached() (b *Bundle, err error) {
	key, e := InstalledPublic()
	if e != nil {
		return nil, fmt.Errorf("trusted key not configured: %w", e)
	}
	dir, e := ConfigDir()
	if e != nil {
		return nil, e
	}
	raw, e := readRegular(filepath.Join(dir, "signed-rules.json"), limit)
	if e != nil {
		return nil, e
	}
	return Verify(raw, key, time.Now().UTC())
}
func LoadSignedPath(path string, pub ed25519.PublicKey) (*Bundle, error) {
	data, err := readRegular(path, limit)
	if err != nil {
		return nil, err
	}
	return Verify(data, pub, time.Now().UTC())
}
