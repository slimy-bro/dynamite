package util

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
)

// ExeVersion is a file version from PE version resource, 1.0.15.3
type ExeVersion [4]uint16

func (v ExeVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
}

// VS_FIXEDFILEINFO dwSignature (0xFEEF04BD) and dwStrucVersion (0x00010000)
var fixedFileInfoHeader = []byte{0xbd, 0x04, 0xef, 0xfe, 0x00, 0x00, 0x01, 0x00}

const fixedFileInfoSize = 52

func GetExeVersion(path string) (ExeVersion, error) {
	var v ExeVersion

	f, err := pe.Open(path)
	if err != nil {
		return v, err
	}
	defer f.Close()

	s := f.Section(".rsrc")
	if s == nil {
		return v, errors.New("no resource section")
	}

	data, err := s.Data()
	if err != nil {
		return v, fmt.Errorf("read resource section: %w", err)
	}

	i := bytes.Index(data, fixedFileInfoHeader)
	if i < 0 || i+fixedFileInfoSize > len(data) {
		return v, errors.New("no version info")
	}

	ms := binary.LittleEndian.Uint32(data[i+8:])
	ls := binary.LittleEndian.Uint32(data[i+12:])

	return ExeVersion{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}, nil
}
