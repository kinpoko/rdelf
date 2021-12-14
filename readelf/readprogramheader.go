package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type programHeader struct {
	P_type   uint32 /* Segment type */
	P_flags  uint32 /* Segment flags */
	P_offset uint64 /* Segment file offset */
	P_vaddr  uint64 /* Segment virtual address */
	P_paddr  uint64 /* Segment physical address */
	P_filesz uint64 /* Segment size in file */
	P_memsz  uint64 /* Segment size in memory */
	P_align  uint64 /* Segment alignment, file & memory */
}

type ProgramHeaderInfo struct {
	Type  string
	Flags string
}

type PHType uint32

const (
	Null    PHType = 0
	Load    PHType = 1
	Dynamic PHType = 2
	Interp  PHType = 3
	Note    PHType = 4
	Shlib   PHType = 5
	Phdr    PHType = 6
)

func setPHtype(info ProgramHeaderInfo, t PHType) ProgramHeaderInfo {
	switch t {
	case Null:
		info.Type = "NULL"
	case Load:
		info.Type = "LOAD"
	case Dynamic:
		info.Type = "DYNAMIC"
	case Interp:
		info.Type = "INTERP"
	case Note:
		info.Type = "NOTE"
	case Shlib:
		info.Type = "SHLIB"
	case Phdr:
		info.Type = "PHDR"
	}
	return info
}

type PHFlags uint32

const (
	X PHFlags = 1
	W PHFlags = 2
	R PHFlags = 4
)

func setPHFlags(info ProgramHeaderInfo, f PHFlags) ProgramHeaderInfo {
	switch f {
	case X:
		info.Flags = "Executable"
	case W:
		info.Flags = "Writable"
	case R:
		info.Flags = "Readable"
	}
	return info
}

func ReadProgramHeader(file []byte, phoff uint64, phnum uint16, phsize uint16) (ProgramHeaderInfo, error) {
	var info ProgramHeaderInfo
	eheader, err1 := ReadELFHeader(file)
	if err1 != nil {
		return info, err1
	}

	var order binary.ByteOrder
	if eheader.Data == "little endian" {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}

	var pheader programHeader
	phs := unsafe.Sizeof(pheader)
	ph := make([]byte, phs)
	copy(ph, file[int(phoff):])
	phr := bytes.NewReader(ph)
	err2 := binary.Read(phr, order, &pheader)
	if err2 != nil {
		return info, err2
	}
	info = setPHtype(info, PHType(pheader.P_type))
	info = setPHFlags(info, PHFlags(pheader.P_flags))
	return info, nil

}
