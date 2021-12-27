package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type ProgramHeader struct {
	P_type   Elf64_Word  /* Segment type */
	P_flags  Elf64_Word  /* Segment flags */
	P_offset Elf64_Off   /* Segment file offset */
	P_vaddr  Elf64_Addr  /* Segment virtual address */
	P_paddr  Elf64_Addr  /* Segment physical address */
	P_filesz Elf64_Xword /* Segment size in file */
	P_memsz  Elf64_Xword /* Segment size in memory */
	P_align  Elf64_Xword /* Segment alignment, file & memory */
}

type ProgramHeaderInfo struct {
	Type   string
	Flags  string
	Offset Elf64_Off
	VAddr  Elf64_Addr
	PAddr  Elf64_Addr
	FSize  Elf64_Xword
	MSize  Elf64_Xword
}

type ProgramHeaderInfos []ProgramHeaderInfo

type PType uint32

const (
	PT_NULL         PType = 0
	PT_LOAD         PType = 1
	PT_DYNAMIC      PType = 2
	PT_INTERP       PType = 3
	PT_NOTE         PType = 4
	PT_SHLIB        PType = 5
	PT_PHDR         PType = 6
	PT_TLS          PType = 7
	PT_NUM          PType = 8
	PT_GNU_EH_FRAME PType = 0x6474e550
	PT_GNU_STACK    PType = 0x6474e551
	PT_GNU_RELRO    PType = 0x6474e552
)

func setPType(info ProgramHeaderInfo, t PType) ProgramHeaderInfo {
	switch t {
	case PT_NULL:
		info.Type = "NULL"
	case PT_LOAD:
		info.Type = "LOAD"
	case PT_DYNAMIC:
		info.Type = "DYNAMIC"
	case PT_INTERP:
		info.Type = "INTERP"
	case PT_NOTE:
		info.Type = "NOTE"
	case PT_SHLIB:
		info.Type = "SHLIB"
	case PT_PHDR:
		info.Type = "PHDR"
	case PT_TLS:
		info.Type = "TLS"
	case PT_NUM:
		info.Type = "Num"
	case PT_GNU_EH_FRAME:
		info.Type = "GNU_EH_FRAME"
	case PT_GNU_STACK:
		info.Type = "GNU_STACK"
	case PT_GNU_RELRO:
		info.Type = "GNU_RELRO"
	default:
		info.Type = "Unknown"
	}
	return info
}

type PFlags uint32

const (
	PF_X PFlags = 1
	PF_W PFlags = 2
	PF_R PFlags = 4
)

func setPFlags(info ProgramHeaderInfo, f PFlags) ProgramHeaderInfo {
	if PF_R&f != 0 {
		info.Flags += "Readable"
	} else {
		info.Flags += " "
	}
	if PF_W&f != 0 {
		info.Flags += " Writable"
	} else {
		info.Flags += " "
	}
	if PF_X&f != 0 {
		info.Flags += " Excutable"
	} else {
		info.Flags += " "
	}
	return info
}

func ReadProgramHeaders(file []byte, phoff Elf64_Off, phnum Elf64_Half, phsize Elf64_Half) (ProgramHeaderInfos, error) {
	var infos ProgramHeaderInfos
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
		var pheader ProgramHeader
		var info ProgramHeaderInfo
		phs := unsafe.Sizeof(pheader)
		ph := make([]byte, phs)
		copy(ph, file[int(phoff)+int(phsize)*i:])
		phr := bytes.NewReader(ph)
		err = binary.Read(phr, order, &pheader)
		if err != nil {
			return infos, err
		}
		info = setPType(info, PType(pheader.P_type))
		info = setPFlags(info, PFlags(pheader.P_flags))
		info.Offset = pheader.P_offset
		info.VAddr = pheader.P_vaddr
		info.PAddr = pheader.P_paddr
		info.FSize = pheader.P_filesz
		info.MSize = pheader.P_memsz
		infos = append(infos, info)
	}

	return infos, nil

}
