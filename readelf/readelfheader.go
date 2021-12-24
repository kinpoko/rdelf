package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type Elf64_Half uint16
type Elf64_Word uint32
type Elf64_Sword int32
type Elf64_Xword uint64
type Elf64_Sxword int64
type Elf64_Addr uint64
type Elf64_Off uint64
type Elf64_Section uint16
type Elf64_Versym Elf64_Half

type ElfHeaderMagic struct {
	E_dent [16]uint8 /* Magic number and other info */
}

type ElfHeader struct {
	E_type      Elf64_Half /* Object file type */
	E_machine   Elf64_Half /* Architecture */
	E_version   Elf64_Word /* Object file version */
	E_entry     Elf64_Addr /* Entry point virtual address */
	E_phoff     Elf64_Off  /* Program header table file offset */
	E_shoff     Elf64_Off  /* Section header table file offset */
	E_flags     Elf64_Word /* Processor-specific flags */
	E_ehsize    Elf64_Half /* ELF header size in bytes */
	E_phentsize Elf64_Half /* Program header table entry size */
	E_phnum     Elf64_Half /* Program header table entry count */
	E_shentsize Elf64_Half /* Section header table entry size */
	E_shnum     Elf64_Half /* Section header table entry count */
	E_shstrndx  Elf64_Half /* Section header string table index */
}

type ElfHeaderInfo struct {
	Magic          [16]uint8
	Class          string
	Data           string
	Version        uint8
	Type           string
	Machine        string
	EntryPoint     Elf64_Addr
	StartOfPHeader Elf64_Off
	StartOfSHeader Elf64_Off
	SizeOfPHeader  Elf64_Half
	NumOfPHeader   Elf64_Half
	SizeOfSHeader  Elf64_Half
	NumOfSHeader   Elf64_Half
}

type ElfClass int

const (
	ELFCLASSNONE ElfClass = iota
	ELFCLASS32
	ELFCLASS64
	ELFCLASSNUM
)

type ElfData int

const (
	ELFDATA2LSB ElfData = 1 /* little endian */
	ELFDATA2MSB ElfData = 2 /* big endian */
)

type ElfType int

const (
	ET_NONE ElfType = iota
	ET_REL
	ET_EXEC
	ET_DYN
	ET_CORE
)

type ElfMachine int

const (
	EM_NONE        ElfMachine = 0
	EM_SPARC       ElfMachine = 2
	EM_386         ElfMachine = 3
	EM_SPARC32PLUS ElfMachine = 18
	EM_SPARCV9     ElfMachine = 43
	EM_X86_64      ElfMachine = 62
)

func setClass(info ElfHeaderInfo, c ElfClass) ElfHeaderInfo {
	switch c {
	case ELFCLASSNONE:
		info.Class = "None"
	case ELFCLASS32:
		info.Class = "ELF32"
	case ELFCLASS64:
		info.Class = "ELF64"
	case ELFCLASSNUM:
		info.Class = "Num"
	default:
		info.Class = "Unknown"
	}
	return info
}

func setData(info ElfHeaderInfo, d ElfData) ElfHeaderInfo {
	switch d {
	case ELFDATA2LSB:
		info.Data = "little endian"
	case ELFDATA2MSB:
		info.Data = "big endian"
	default:
		info.Data = "unknown"
	}
	return info

}

func setType(info ElfHeaderInfo, o ElfType) ElfHeaderInfo {
	switch o {
	case ET_NONE:
		info.Type = "An unknown type"
	case ET_REL:
		info.Type = "A relocatable file"
	case ET_EXEC:
		info.Type = "An executable file"
	case ET_DYN:
		info.Type = "A shared object"
	case ET_CORE:
		info.Type = "A core file"
	default:
		info.Type = "Unknown"
	}
	return info
}

func setMachine(info ElfHeaderInfo, m ElfMachine) ElfHeaderInfo {
	switch m {
	case EM_NONE:
		info.Machine = "An unkown machine"
	case EM_SPARC:
		info.Machine = "Sun Microsystems SPARC"
	case EM_386:
		info.Machine = "Intel 80386"
	case EM_SPARC32PLUS:
		info.Machine = "SPARC with enhanced instruction set"
	case EM_SPARCV9:
		info.Machine = "SPARC v9 64-bit"
	case EM_X86_64:
		info.Machine = "AMD x86-64"
	default:
		info.Machine = "Unknown"
	}
	return info
}

func ReadELFHeader(file []byte) (ElfHeaderInfo, error) {
	var magicnum ElfHeaderMagic
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

	var header ElfHeader

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
