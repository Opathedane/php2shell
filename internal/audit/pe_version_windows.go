//go:build windows

package audit

import (
	"encoding/binary"
	"fmt"
)

// peFileVersion reads VS_FIXEDFILEINFO from a PE image already loaded in memory.
func peFileVersion(data []byte) (string, bool) {
	if len(data) < 64 {
		return "", false
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return "", false
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if eLfanew < 0 || eLfanew+24 > len(data) {
		return "", false
	}
	if string(data[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return "", false
	}
	coff := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	opt := coff + 20
	if opt+2 > len(data) {
		return "", false
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	var ddOffset int
	switch magic {
	case 0x10b:
		ddOffset = opt + 96
	case 0x20b:
		ddOffset = opt + 112
	default:
		return "", false
	}
	if ddOffset+8*8 > len(data) {
		return "", false
	}
	rsrcRVA := binary.LittleEndian.Uint32(data[ddOffset+2*8:])
	rsrcSize := binary.LittleEndian.Uint32(data[ddOffset+2*8+4:])
	if rsrcRVA == 0 || rsrcSize == 0 {
		return "", false
	}
	sectStart := opt + optSize
	for i := 0; i < numSections; i++ {
		off := sectStart + i*40
		if off+40 > len(data) {
			return "", false
		}
		name := string(data[off : off+8])
		if len(name) < 6 || name[:6] != ".rsrc" {
			continue
		}
		vaddr := binary.LittleEndian.Uint32(data[off+12:])
		raw := binary.LittleEndian.Uint32(data[off+20:])
		rawSize := binary.LittleEndian.Uint32(data[off+16:])
		if rsrcRVA < vaddr || rsrcRVA-vaddr >= rawSize {
			continue
		}
		base := int(raw + (rsrcRVA - vaddr))
		if base < 0 || base+int(rawSize) > len(data) {
			return "", false
		}
		if ver := findFixedFileInfo(data[base : base+int(rawSize)]); ver != "" {
			return ver, true
		}
	}
	return "", false
}

func findFixedFileInfo(section []byte) string {
	for idx := 0; idx+52 <= len(section) && idx <= 65536; idx++ {
		if binary.LittleEndian.Uint32(section[idx:]) != 0xfeef04bd {
			continue
		}
		ms := binary.LittleEndian.Uint32(section[idx+8:])
		ls := binary.LittleEndian.Uint32(section[idx+12:])
		return fmt.Sprintf("%d.%d.%d", ms>>16, ms&0xffff, ls>>16)
	}
	return ""
}
