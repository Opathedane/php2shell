package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	binaryFullReadLimit = 8 << 20  // read entire file when at or below this size
	binaryHeadWindow    = 4 << 20  // first window for oversized binaries
	binaryTailWindow    = 2 << 20  // trailing window for oversized binaries
	binaryMaxTotalRead  = 10 << 20 // hard cap on bytes read per inspection
)

var embeddedPHPVersion = regexp.MustCompile(`(?i)PHP Version (\d+\.\d+\.\d+)`)

// BinaryInspectCoverage describes how much of a binary was inspected statically.
type BinaryInspectCoverage struct {
	FileSize  int64
	BytesRead int64
	Partial   bool
	Detail    string
}

// VersionFromBinary inspects a PHP binary without executing it.
// Sources may include embedded build strings and (on Windows) PE version metadata.
func VersionFromBinary(path string) (version string, sources []string, cov BinaryInspectCoverage, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", nil, cov, err
	}
	if !fi.Mode().IsRegular() {
		return "", nil, cov, fmt.Errorf("not a regular file: %s", path)
	}
	cov.FileSize = fi.Size()
	f, err := os.Open(path)
	if err != nil {
		return "", nil, cov, err
	}
	defer f.Close()
	b, cov, err := readBinarySample(f, fi.Size())
	if err != nil {
		return "", nil, cov, err
	}
	version, sources, err = versionMarkersFromBytes(b)
	if err != nil {
		return "", sources, cov, fmt.Errorf("%s: %w", path, err)
	}
	if cov.Partial {
		sources = append(sources, "partial_file_window_inspection")
	}
	return version, sources, cov, nil
}

func readBinarySample(f *os.File, size int64) ([]byte, BinaryInspectCoverage, error) {
	cov := BinaryInspectCoverage{FileSize: size}
	if size <= binaryFullReadLimit {
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
	head := make([]byte, binaryHeadWindow)
	n, err := io.ReadFull(io.LimitReader(f, binaryHeadWindow), head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, cov, err
	}
	if n > 0 {
		buf.Write(head[:n])
		cov.BytesRead += int64(n)
	}
	tailRead := int64(0)
	if size > int64(n) {
		tailSize := binaryTailWindow
		if tailSize > size-int64(n) {
			tailSize = size - int64(n)
		}
		if tailSize > 0 {
			if _, err := f.Seek(size-tailSize, io.SeekStart); err != nil {
				return nil, cov, err
			}
			tail := make([]byte, tailSize)
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
	cov.Detail = fmt.Sprintf("partial_window_read file_size=%d head=%d tail=%d bytes_read=%d pe_and_strings_may_be_incomplete", size, int64(n), tailRead, cov.BytesRead)
	return buf.Bytes(), cov, nil
}

func versionMarkersFromBytes(b []byte) (version string, sources []string, err error) {
	phpRelated := bytesLikelyPHPBinary(b)
	if m := embeddedPHPVersion.FindSubmatch(b); len(m) == 2 {
		version = string(m[1])
		sources = append(sources, "embedded_build_string")
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
	if embeddedPHPVersion.Match(b) {
		return true
	}
	if len(b) < 512 {
		return false
	}
	scanLen := len(b)
	if scanLen > 2<<20 {
		scanLen = 2 << 20
	}
	lower := bytes.ToLower(b[:scanLen])
	return bytes.Contains(lower, []byte("zend engine")) && bytes.Contains(lower, []byte("php"))
}

// AddBinaryVersionEvidence records static binary inspection results without executing the file.
func AddBinaryVersionEvidence(r *Report, path, name, source string) {
	ver, src, cov, err := VersionFromBinary(path)
	if err != nil {
		r.AddEvidence(Evidence{
			Type: "binary_path", Name: name, Source: source, Location: path,
			Detail: err.Error(), Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
		})
		return
	}
	detail := strings.Join(src, ",") + "; " + cov.Detail
	if cov.Partial {
		detail += "; inspect_coverage=partial"
		r.AddWarning(fmt.Sprintf("Partial static binary inspection for %s (%s); version markers outside sampled windows may be missed", path, cov.Detail))
	}
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: name, Version: ver, Source: source, Location: path,
		Detail: detail, Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
}
