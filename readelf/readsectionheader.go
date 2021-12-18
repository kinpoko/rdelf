package readelf

import (
	"bytes"
	"encoding/binary"

	"unsafe"
)

type sectionHeader struct {
	Sh_name      uint32 /* Section name (string tbl index) */
	Sh_type      uint32 /* Section type */
	Sh_flags     uint64 /* Section flags */
	Sh_addr      uint64 /* Section virtual addr at execution */
	Sh_offset    uint64 /* Section file offset */
	Sh_size      uint64 /* Section size in bytes */
	Sh_link      uint32 /* Link to another section */
	Sh_info      uint32 /* Additional section information */
	Sh_addralign uint64 /* Section alignment */
	Sh_entsize   uint64 /* Entry size if section holds table */
}

type SectionHeaderInfo struct {
	Name      string
	Type      string
	Size      uint64
	EntrySize uint64
}

type SectionHeaderInfos []SectionHeaderInfo

type SHType uint32

const (
	SNull        SHType = 0
	Progbits     SHType = 1
	Symtab       SHType = 2
	Strtab       SHType = 3
	Rela         SHType = 4
	Hash         SHType = 5
	SDynamic     SHType = 6
	SNote        SHType = 7
	Nobits       SHType = 8
	SRel         SHType = 9
	SShlib       SHType = 10
	Dynsym       SHType = 11
	Initarray    SHType = 14
	Finiarray    SHType = 15
	Preinitarray SHType = 16
	Group        SHType = 17
	Symtabshndx  SHType = 18
	SNum         SHType = 19
	Gnu_hash     SHType = 0x6ffffff6
	Gnu_verneed  SHType = 0x6ffffffe
	Gnu_versym   SHType = 0x6fffffff
)

func setSHtype(info SectionHeaderInfo, t SHType) SectionHeaderInfo {
	switch t {
	case SNull:
		info.Type = "Null"
	case Progbits:
		info.Type = "Progbit"
	case Symtab:
		info.Type = "Symtab"
	case Strtab:
		info.Type = "Strtab"
	case Rela:
		info.Type = "Rela"
	case Hash:
		info.Type = "Hash"
	case SDynamic:
		info.Type = "Dynamic"
	case SNote:
		info.Type = "Note"
	case Nobits:
		info.Type = "Nobits"
	case SRel:
		info.Type = "Rel"
	case SShlib:
		info.Type = "Shlib"
	case Dynsym:
		info.Type = "Dynsym"
	case Initarray:
		info.Type = "Initarray"
	case Finiarray:
		info.Type = "Finiarray"
	case Preinitarray:
		info.Type = "Preinitarray"
	case Group:
		info.Type = "Group"
	case Symtabshndx:
		info.Type = "Symtabshndx"
	case SNum:
		info.Type = "Num"
	case Gnu_hash:
		info.Type = "GNU_hash"
	case Gnu_verneed:
		info.Type = "GNU_verneed"
	case Gnu_versym:
		info.Type = "GNU_versym"
	default:
		info.Type = "Unknown"
	}
	return info
}

func ReadSectionHeaders(file []byte, shoff uint64, shnum uint16, shsize uint16) (SectionHeaderInfos, error) {
	var infos SectionHeaderInfos
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

	for i := 0; i < int(shnum); i++ {
		var sheader sectionHeader
		var info SectionHeaderInfo
		shs := unsafe.Sizeof(sheader)
		sh := make([]byte, shs)
		copy(sh, file[int(shoff)+int(shsize)*i:])
		shr := bytes.NewReader(sh)
		err = binary.Read(shr, order, &sheader)
		if err != nil {
			return infos, err
		}
		info = setSHtype(info, SHType(sheader.Sh_type))

		infos = append(infos, info)
	}
	return infos, nil
}
