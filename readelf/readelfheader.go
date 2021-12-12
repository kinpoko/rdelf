package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type elfHeader struct {
	e_dent      [16]uint8 /* Magic number and other info */
	e_type      uint16    /* Object file type */
	e_machine   uint16    /* Architecture */
	e_version   uint32    /* Object file version */
	e_entry     uint64    /* Entry point virtual address */
	e_phoff     uint64    /* Program header table file offset */
	e_shoff     uint64    /* Section header table file offset */
	e_flags     uint32    /* Processor-specific flags */
	e_ehsize    uint16    /* ELF header size in bytes */
	e_phentsize uint16    /* Program header table entry size */
	e_phnum     uint16    /* Program header table entry count */
	e_shentsize uint16    /* Section header table entry size */
	e_shnum     uint16    /* Section header table entry count */
	e_shstrndx  uint16    /* Section header string table index */
}

type ElfClass int

const (
	None ElfClass = iota
	ELF32
	ELF64
	Num
)

type ElfData int

const (
	Littleendian ElfData = 1
	Bigendian    ElfData = 2
)

type ElfHeaderInfo struct {
	Magic   [16]uint8
	Class   string
	Data    string
	Version uint8
	Type    string
}

type ElfType int

const (
	Nonetype ElfType = iota
	Rel
	Exec
	Dyn
	Core
)

func setClass(info ElfHeaderInfo, c ElfClass) ElfHeaderInfo {
	switch c {
	case None:
		info.Class = "None"
	case ELF32:
		info.Class = "ELF32"
	case ELF64:
		info.Class = "ELF64"
	case Num:
		info.Class = "Num"
	}
	return info
}

func setData(info ElfHeaderInfo, d ElfData) ElfHeaderInfo {
	switch d {
	case Littleendian:
		info.Data = "little endian"
	case Bigendian:
		info.Data = "big endian"
	}
	return info

}

func setType(info ElfHeaderInfo, o ElfType) ElfHeaderInfo {
	switch o {
	case Nonetype:
		info.Type = "An unknown type"
	case Rel:
		info.Type = "A relocatable file"
	case Exec:
		info.Type = "An executable file"
	case Dyn:
		info.Type = "A shared object"

	case Core:
		info.Type = "A core file"
	}
	return info
}

func ReadHeader(file []byte) (ElfHeaderInfo, error) {

	var header elfHeader
	var info ElfHeaderInfo

	s := unsafe.Sizeof(header)
	h := make([]byte, s)
	copy(h, file[:s])

	buf := bytes.NewReader(h)

	err1 := binary.Read(buf, binary.BigEndian, &header.e_dent)
	if err1 != nil {
		return info, err1
	}
	copy(info.Magic[:], header.e_dent[:])
	info = setClass(info, ElfClass(header.e_dent[4]))
	info = setData(info, ElfData(header.e_dent[5]))
	info.Version = header.e_dent[6]

	var order binary.ByteOrder
	if header.e_dent[5] == 1 {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}

	err2 := binary.Read(buf, order, &header.e_type)
	if err2 != nil {
		return info, err2
	}
	info = setType(info, ElfType(header.e_type))

	return info, nil
}
