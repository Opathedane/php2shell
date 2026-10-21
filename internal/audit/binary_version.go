package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const binaryVersionReadLimit = 8 << 20

var embeddedPHPVersion = regexp.MustCompile(`(?i)PHP Version (\d+\.\d+\.\d+)`)

// VersionFromBinary inspects a PHP binary without executing it.
// Sources may include embedded build strings and (on Windows) PE version metadata.
func VersionFromBinary(path string) (version string, sources []string, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return "", nil, fmt.Errorf("not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, binaryVersionReadLimit+1))
	if err != nil {
		return "", nil, err
	}
	if int64(len(b)) > binaryVersionReadLimit {
		return "", nil, fmt.Errorf("binary exceeds read limit")
	}
	version, sources, err = versionMarkersFromBytes(b)
	if err != nil {
		return "", sources, fmt.Errorf("%s: %w", path, err)
	}
	return version, sources, nil
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
	ver, src, err := VersionFromBinary(path)
	if err != nil {
		r.AddEvidence(Evidence{
			Type: "binary_path", Name: name, Source: source, Location: path,
			Detail: err.Error(), Interpretation: "PRESENT_VERSION_UNKNOWN_NOT_RUNTIME_VERIFIED",
		})
		return
	}
	r.AddEvidence(Evidence{
		Type: "binary_static_version", Name: name, Version: ver, Source: source, Location: path,
		Detail: strings.Join(src, ","), Interpretation: "STATIC_BINARY_VERSION_NOT_ACTIVE_RUNTIME_ATTESTATION",
	})
}
