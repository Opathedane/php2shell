//go:build !windows

package audit

func peFileVersion(_ []byte) (string, bool) { return "", false }
