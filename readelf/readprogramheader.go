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
	Type   string
	Flags  string
	Offset uint64
	VAddr  uint64
	PAddr  uint64
	FSize  uint64
	MSize  uint64
}

type ProgramHeadersInfos []ProgramHeaderInfo

type PHType uint32

const (
	Null         PHType = 0
	Load         PHType = 1
	Dynamic      PHType = 2
	Interp       PHType = 3
	Note         PHType = 4
	Shlib        PHType = 5
	Phdr         PHType = 6
	Tls          PHType = 7
	PNum         PHType = 8
	Gnu_eh_frame PHType = 0x6474e550
	Gnu_stack    PHType = 0x6474e551
	Gnu_relro    PHType = 0x6474e552
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
	case Tls:
		info.Type = "TLS"
	case PNum:
		info.Type = "Num"
	case Gnu_eh_frame:
		info.Type = "GNU_EH_FRAME"
	case Gnu_stack:
		info.Type = "GNU_STACK"
	case Gnu_relro:
		info.Type = "GNU_RELRO"
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
	if R&f != 0 {
		info.Flags += "Readable"
	} else {
		info.Flags += " "
	}
	if W&f != 0 {
		info.Flags += " Writable"
	} else {
		info.Flags += " "
	}
	if X&f != 0 {
		info.Flags += " Excutable"
	} else {
		info.Flags += " "
	}
	return info
}

func ReadProgramHeader(file []byte, phoff uint64, phnum uint16, phsize uint16) (ProgramHeadersInfos, error) {
	var infos ProgramHeadersInfos
	eheader, err := ReadELFHeader(file)
	if err != nil {
		return infos, err
	}

	var order binary.ByteOrder
	if eheader.Data == "little endian" {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}

	for i := 0; i < int(phnum); i++ {
		var pheader programHeader
		var info ProgramHeaderInfo
		phs := unsafe.Sizeof(pheader)
		ph := make([]byte, phs)
		copy(ph, file[int(phoff)+int(phsize)*i:])
		phr := bytes.NewReader(ph)
		err = binary.Read(phr, order, &pheader)
		if err != nil {
			return infos, err
		}
		info = setPHtype(info, PHType(pheader.P_type))
		info = setPHFlags(info, PHFlags(pheader.P_flags))
		info.Offset = pheader.P_offset
		info.VAddr = pheader.P_vaddr
		info.PAddr = pheader.P_paddr
		info.FSize = pheader.P_filesz
		info.MSize = pheader.P_memsz
		infos = append(infos, info)
	}

	return infos, nil

}
