package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	binaryFullReadLimit int64 = 8 << 20  // read entire file when at or below this size
	binaryHeadWindow    int64 = 4 << 20  // first window for oversized binaries
	binaryTailWindow    int64 = 2 << 20  // trailing window for oversized binaries
	binaryMaxTotalRead  int64 = 10 << 20 // hard cap on bytes read per inspection
	binaryFingerprintN  int64 = 64 << 10 // prefix used for alias corroboration
)

var (
	embeddedPHPVersion = regexp.MustCompile(`(?i)PHP Version (\d+\.\d+\.\d+)`)
	embeddedPHPSlash   = regexp.MustCompile(`(?i)PHP/(\d+\.\d+\.\d+)`)
)

// BinaryInspectCoverage describes how much of a binary was inspected statically.
type BinaryInspectCoverage struct {
	FileSize  int64
	BytesRead int64
	Partial   bool
	Detail    string
}

// BinaryVersionResult is a passive version observation for one executable.
type BinaryVersionResult struct {
	Version    string
	Sources    []string
	Provenance string // verified_binary_metadata | path_inferred | unknown
	Confidence string // HIGH | MEDIUM | LOW | NONE
	Coverage   BinaryInspectCoverage
	Err        error
}

// VersionFromBinary inspects a PHP binary without executing it.
// Preference order: embedded build strings, PE FixedFileInfo (including directed
// .rsrc reads for large files), then clearly labelled install-path inference.
func VersionFromBinary(path string) BinaryVersionResult {
	var out BinaryVersionResult
	fi, err := os.Lstat(path)
	if err != nil {
		out.Err = err
		out.Provenance = "unknown"
		out.Confidence = "NONE"
		return out
	}
	if !fi.Mode().IsRegular() {
		out.Err = fmt.Errorf("not a regular file: %s", path)
		out.Provenance = "unknown"
		out.Confidence = "NONE"
		return out
	}
	out.Coverage.FileSize = fi.Size()
	f, err := os.Open(path)
	if err != nil {
		out.Err = err
		out.Provenance = "unknown"
		out.Confidence = "NONE"
		return out
	}
	defer f.Close()

	b, cov, err := readBinarySample(f, fi.Size())
	if err != nil {
		out.Err = err
		out.Coverage = cov
		out.Provenance = "unknown"
		out.Confidence = "NONE"
		return out
	}
	out.Coverage = cov

	version, sources, markerErr := versionMarkersFromBytes(b)
	out.Sources = append(out.Sources, sources...)

	// Directed PE .rsrc read recovers version info that head/tail windows miss.
	if peVer, peOK, peErr := peFileVersionFromFile(f, fi.Size()); peErr == nil && peOK {
		if version == "" {
			version = peVer
			out.Sources = append(out.Sources, "pe_fixed_file_info_rsrc_seek")
		} else if version != peVer {
			out.Sources = append(out.Sources, "pe_fixed_file_info_rsrc_seek_mismatch="+peVer)
		} else if !containsString(out.Sources, "pe_fixed_file_info") && !containsString(out.Sources, "pe_fixed_file_info_rsrc_seek") {
			out.Sources = append(out.Sources, "pe_fixed_file_info_rsrc_seek")
		}
	}

	if version != "" {
		out.Version = version
		out.Provenance = "verified_binary_metadata"
		out.Confidence = "HIGH"
		if cov.Partial {
			out.Sources = append(out.Sources, "partial_file_window_inspection")
			out.Confidence = "MEDIUM"
		}
		return out
	}

	if pathVer, pathSrc := VersionFromInstallPath(path); pathVer != "" {
		out.Version = pathVer
		out.Sources = append(out.Sources, pathSrc)
		out.Provenance = "path_inferred"
		out.Confidence = "MEDIUM"
		out.Err = nil
		if markerErr != nil {
			out.Sources = append(out.Sources, "binary_markers_absent")
		}
		return out
	}

	out.Provenance = "unknown"
	out.Confidence = "NONE"
	if markerErr != nil {
		out.Err = fmt.Errorf("%s: %w", path, markerErr)
	} else {
		out.Err = fmt.Errorf("%s: no version marker found", path)
	}
	return out
}

func readBinarySample(f *os.File, size int64) ([]byte, BinaryInspectCoverage, error) {
	cov := BinaryInspectCoverage{FileSize: size}
	if size <= binaryFullReadLimit {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, cov, err
		}
		b, err := io.ReadAll(io.LimitReader(f, size+1))
		if err != nil {
			return nil, cov, err
		}
		if int64(len(b)) > size {
			return nil, cov, fmt.Errorf("file grew during read")
		}
		cov.BytesRead = int64(len(b))
		cov.Partial = false
		cov.Detail = fmt.Sprintf("full_file_read bytes=%d", cov.BytesRead)
		return b, cov, nil
	}
	cov.Partial = true
	var buf bytes.Buffer
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, cov, err
	}
	head := make([]byte, int(binaryHeadWindow))
	n, err := io.ReadFull(io.LimitReader(f, binaryHeadWindow), head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, cov, err
	}
	headRead := int64(n)
	if headRead > 0 {
		buf.Write(head[:n])
		cov.BytesRead += headRead
	}
	tailRead := int64(0)
	if size > headRead {
		tailSize := binaryTailWindow
		if tailSize > size-headRead {
			tailSize = size - headRead
		}
		if tailSize > 0 {
			if _, err := f.Seek(size-tailSize, io.SeekStart); err != nil {
				return nil, cov, err
			}
			tail := make([]byte, int(tailSize))
			tn, err := io.ReadFull(io.LimitReader(f, tailSize), tail)
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				return nil, cov, err
			}
			if tn > 0 {
				buf.Write(tail[:tn])
				cov.BytesRead += int64(tn)
				tailRead = int64(tn)
			}
		}
	}
	if cov.BytesRead > binaryMaxTotalRead {
		return nil, cov, fmt.Errorf("binary inspection read cap exceeded")
	}
	cov.Detail = fmt.Sprintf("partial_window_read file_size=%d head=%d tail=%d bytes_read=%d pe_and_strings_may_be_incomplete", size, headRead, tailRead, cov.BytesRead)
	return buf.Bytes(), cov, nil
}

func versionMarkersFromBytes(b []byte) (version string, sources []string, err error) {
	phpRelated := bytesLikelyPHPBinary(b)
	if m := embeddedPHPVersion.FindSubmatch(b); len(m) == 2 {
		version = string(m[1])
		sources = append(sources, "embedded_build_string")
	} else if m := embeddedPHPSlash.FindSubmatch(b); len(m) == 2 {
		version = string(m[1])
		sources = append(sources, "embedded_php_slash_version")
	}
	if phpRelated {
		if peVer, peOK := peFileVersion(b); peOK {
			if version == "" {
				version = peVer
				sources = append(sources, "pe_fixed_file_info")
			} else if version != peVer {
				sources = append(sources, "pe_fixed_file_info_mismatch="+peVer)
			} else {
				sources = append(sources, "pe_fixed_file_info")
			}
		}
	}
	if version == "" {
		return "", sources, fmt.Errorf("no version marker found")
	}
	return version, sources, nil
}

func bytesLikelyPHPBinary(b []byte) bool {
	if embeddedPHPVersion.Match(b) || embeddedPHPSlash.Match(b) {
		return true
	}
	if len(b) < 64 {
		return false
	}
	// MZ PE header: allow PE resource parsing even when PHP strings are elsewhere.
	if b[0] == 'M' && b[1] == 'Z' {
		return true
	}
	scanLen := len(b)
	if scanLen > 2<<20 {
		scanLen = 2 << 20
	}
	lower := bytes.ToLower(b[:scanLen])
	return bytes.Contains(lower, []byte("zend engine")) && bytes.Contains(lower, []byte("php"))
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// binaryFingerprint returns size and a SHA-256 of the first binaryFingerprintN bytes.
// Used only to corroborate whether two discovered paths likely refer to the same file
// content — never executes the binary.
func binaryFingerprint(path string) (size int64, sum string, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
		return 0, "", fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, binaryFingerprintN))
	if err != nil {
		return 0, "", err
	}
	return fi.Size(), hex.EncodeToString(h.Sum(nil)) + fmt.Sprintf(":prefix=%d", n), nil
}

// AddBinaryVersionEvidence records static binary inspection results without executing the file.
func AddBinaryVersionEvidence(r *Report, path, name, source string) {
	res := VersionFromBinary(path)
	if res.Version == "" {
		detail := "no version marker found"
		if res.Err != nil {
			detail = res.Err.Error()
		}
		r.AddEvidence(Evidence{
			Type: "binary_path", Name: name, Source: source, Location: path,
			Detail: detail, Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
		})
		return
	}
	detail := strings.Join(res.Sources, ",") + "; provenance=" + res.Provenance + "; confidence=" + res.Confidence + "; " + res.Coverage.Detail
	if res.Coverage.Partial {
		detail += "; inspect_coverage=partial"
		r.AddWarning(fmt.Sprintf("Partial static binary inspection for %s (%s); version markers outside sampled windows may be missed", path, res.Coverage.Detail))
	}
	switch res.Provenance {
	case "path_inferred":
		r.AddEvidence(Evidence{
			Type: "binary_path_inferred_version", Name: name, Version: res.Version, Source: source, Location: path,
			Detail: detail, Interpretation: "PATH_INFERRED_VERSION_NOT_BINARY_VERIFIED_NOT_RUNTIME_ATTESTATION",
		})
	default:
		r.AddEvidence(Evidence{
			Type: "binary_static_version", Name: name, Version: res.Version, Source: source, Location: path,
			Detail: detail, Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
		})
	}
}
