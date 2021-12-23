package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type elfHeaderMagic struct {
	E_dent [16]uint8 /* Magic number and other info */
}

type elfHeader struct {
	E_type      uint16 /* Object file type */
	E_machine   uint16 /* Architecture */
	E_version   uint32 /* Object file version */
	E_entry     uint64 /* Entry point virtual address */
	E_phoff     uint64 /* Program header table file offset */
	E_shoff     uint64 /* Section header table file offset */
	E_flags     uint32 /* Processor-specific flags */
	E_ehsize    uint16 /* ELF header size in bytes */
	E_phentsize uint16 /* Program header table entry size */
	E_phnum     uint16 /* Program header table entry count */
	E_shentsize uint16 /* Section header table entry size */
	E_shnum     uint16 /* Section header table entry count */
	E_shstrndx  uint16 /* Section header string table index */
}

type ElfHeaderInfo struct {
	Magic          [16]uint8
	Class          string
	Data           string
	Version        uint8
	Type           string
	Machine        string
	EntryPoint     uint64
	StartOfPHeader uint64
	StartOfSHeader uint64
	SizeOfPHeader  uint16
	NumOfPHeader   uint16
	SizeOfSHeader  uint16
	NumOfSHeader   uint16
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

type ElfType int

const (
	Nonetype ElfType = iota
	Rel
	Exec
	Dyn
	Core
)

type ElfMachine int

const (
	Nonemachine ElfMachine = 0
	Sparc       ElfMachine = 2
	I386        ElfMachine = 3
	Sparc32plus ElfMachine = 18
	Sparcv9     ElfMachine = 43
	X8684       ElfMachine = 62
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
	default:
		info.Class = "Unknown"
	}
	return info
}

func setData(info ElfHeaderInfo, d ElfData) ElfHeaderInfo {
	switch d {
	case Littleendian:
		info.Data = "little endian"
	case Bigendian:
		info.Data = "big endian"
	default:
		info.Data = "unknown"
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
	default:
		info.Type = "Unknown"
	}
	return info
}

func setMachine(info ElfHeaderInfo, m ElfMachine) ElfHeaderInfo {
	switch m {
	case Nonemachine:
		info.Machine = "An unkown machine"
	case Sparc:
		info.Machine = "Sun Microsystems SPARC"
	case I386:
		info.Machine = "Intel 80386"
	case Sparc32plus:
		info.Machine = "SPARC with enhanced instruction set"
	case Sparcv9:
		info.Machine = "SPARC v9 64-bit"
	case X8684:
		info.Machine = "AMD x86-64"
	default:
		info.Machine = "Unknown"
	}
	return info
}

func ReadELFHeader(file []byte) (ElfHeaderInfo, error) {
	var magicnum elfHeaderMagic
	var info ElfHeaderInfo

	ms := unsafe.Sizeof(magicnum)
	m := make([]byte, ms)
	copy(m, file[:ms])
	mr := bytes.NewReader(m)
	err := binary.Read(mr, binary.BigEndian, &magicnum)
	if err != nil {
		return info, err
	}
	copy(info.Magic[:], magicnum.E_dent[:])
	info = setClass(info, ElfClass(magicnum.E_dent[4]))
	info = setData(info, ElfData(magicnum.E_dent[5]))

	var order binary.ByteOrder
	if magicnum.E_dent[5] == 1 {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}
	info.Version = magicnum.E_dent[6]

	var header elfHeader

	sh := unsafe.Sizeof(header)
	h := make([]byte, sh)
	copy(h, file[ms:])

	hr := bytes.NewReader(h)

	err = binary.Read(hr, order, &header)
	if err != nil {
		return info, err
	}

	info = setType(info, ElfType(header.E_type))
	info = setMachine(info, ElfMachine(header.E_machine))
	info.EntryPoint = header.E_entry
	info.StartOfPHeader = header.E_phoff
	info.StartOfSHeader = header.E_shoff
	info.SizeOfPHeader = header.E_phentsize
	info.NumOfPHeader = header.E_phnum
	info.SizeOfSHeader = header.E_shentsize
	info.NumOfSHeader = header.E_shnum
	return info, nil

}
