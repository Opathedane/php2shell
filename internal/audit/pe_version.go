package audit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const peRsrcReadCap = 2 << 20 // max bytes to read from a .rsrc section

// peFileVersion reads VS_FIXEDFILEINFO from a PE image already loaded in memory.
func peFileVersion(data []byte) (string, bool) {
	section, ok := peResourceSection(data)
	if !ok {
		return "", false
	}
	if ver := findFixedFileInfo(section); ver != "" && peResourceSectionLooksLikePHP(section) {
		return ver, true
	}
	return "", false
}

// peFileVersionFromFile locates the PE .rsrc section via headers and reads only that
// slice. This recovers version metadata for large php.exe builds where head/tail
// string windows miss the resource directory.
func peFileVersionFromFile(f *os.File, size int64) (string, bool, error) {
	if size < 64 {
		return "", false, nil
	}
	hdrSize := int64(4096)
	if size < hdrSize {
		hdrSize = size
	}
	hdr := make([]byte, int(hdrSize))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", false, err
	}
	n, err := io.ReadFull(f, hdr)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", false, err
	}
	hdr = hdr[:n]
	rawOff, rawSize, ok := peResourceRawRange(hdr)
	if !ok {
		return "", false, nil
	}
	if int64(rawOff) >= size || rawSize == 0 {
		return "", false, nil
	}
	readSize := rawSize
	if readSize > peRsrcReadCap {
		readSize = peRsrcReadCap
	}
	if int64(rawOff)+int64(readSize) > size {
		readSize = int(size - int64(rawOff))
	}
	if readSize <= 0 {
		return "", false, nil
	}
	buf := make([]byte, readSize)
	if _, err := f.Seek(int64(rawOff), io.SeekStart); err != nil {
		return "", false, err
	}
	if _, err := io.ReadFull(f, buf); err != nil && err != io.ErrUnexpectedEOF {
		return "", false, err
	}
	if ver := findFixedFileInfo(buf); ver != "" && peResourceSectionLooksLikePHP(buf) {
		return ver, true, nil
	}
	return "", false, nil
}

func peResourceSection(data []byte) ([]byte, bool) {
	rawOff, rawSize, ok := peResourceRawRange(data)
	if !ok {
		return nil, false
	}
	if rawOff < 0 || rawSize <= 0 || rawOff+rawSize > len(data) {
		return nil, false
	}
	return data[rawOff : rawOff+rawSize], true
}

func peResourceRawRange(data []byte) (rawOff, rawSize int, ok bool) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return 0, 0, false
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if eLfanew < 0 || eLfanew+24 > len(data) {
		return 0, 0, false
	}
	if string(data[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return 0, 0, false
	}
	coff := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	opt := coff + 20
	if opt+2 > len(data) {
		return 0, 0, false
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	var ddOffset int
	switch magic {
	case 0x10b:
		ddOffset = opt + 96
	case 0x20b:
		ddOffset = opt + 112
	default:
		return 0, 0, false
	}
	if ddOffset+8*8 > len(data) {
		return 0, 0, false
	}
	rsrcRVA := binary.LittleEndian.Uint32(data[ddOffset+2*8:])
	rsrcSize := binary.LittleEndian.Uint32(data[ddOffset+2*8+4:])
	if rsrcRVA == 0 || rsrcSize == 0 {
		return 0, 0, false
	}
	sectStart := opt + optSize
	for i := 0; i < numSections; i++ {
		off := sectStart + i*40
		if off+40 > len(data) {
			return 0, 0, false
		}
		name := string(data[off : off+8])
		if len(name) < 6 || name[:6] != ".rsrc" {
			continue
		}
		vaddr := binary.LittleEndian.Uint32(data[off+12:])
		raw := binary.LittleEndian.Uint32(data[off+20:])
		secRawSize := binary.LittleEndian.Uint32(data[off+16:])
		if rsrcRVA < vaddr || rsrcRVA-vaddr >= secRawSize {
			continue
		}
		base := int(raw + (rsrcRVA - vaddr))
		size := int(secRawSize - (rsrcRVA - vaddr))
		if size > int(rsrcSize) {
			size = int(rsrcSize)
		}
		if base < 0 || size <= 0 {
			continue
		}
		return base, size, true
	}
	return 0, 0, false
}

func peResourceSectionLooksLikePHP(section []byte) bool {
	if bytes.Contains(section, []byte("PHP")) {
		return true
	}
	if bytes.Contains(section, []byte{'P', 0, 'H', 0, 'P', 0}) {
		return true
	}
	lower := bytes.ToLower(section)
	return bytes.Contains(lower, []byte("php.exe")) || bytes.Contains(lower, []byte("productname"))
}

func findFixedFileInfo(section []byte) string {
	limit := len(section)
	if limit > 65536 {
		limit = 65536
	}
	for idx := 0; idx+52 <= limit; idx++ {
		if binary.LittleEndian.Uint32(section[idx:]) != 0xfeef04bd {
			continue
		}
		ms := binary.LittleEndian.Uint32(section[idx+8:])
		ls := binary.LittleEndian.Uint32(section[idx+12:])
		return fmt.Sprintf("%d.%d.%d", ms>>16, ms&0xffff, ls>>16)
	}
	return ""
}
