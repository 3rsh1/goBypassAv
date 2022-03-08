package winApi

type IMAGE_DOS_HEADER struct {
	Magic    uint16     // USHORT Magic number
	Cblp     uint16     // USHORT Bytes on last page of file
	Cp       uint16     // USHORT Pages in file
	Crlc     uint16     // USHORT Relocations
	Cparhdr  uint16     // USHORT Size of header in paragraphs
	MinAlloc uint16     // USHORT Minimum extra paragraphs needed
	MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
	SS       uint16     // USHORT Initial (relative) SS value
	SP       uint16     // USHORT Initial SP value
	CSum     uint16     // USHORT Checksum
	IP       uint16     // USHORT Initial IP value
	CS       uint16     // USHORT Initial (relative) CS value
	LfaRlc   uint16     // USHORT File address of relocation table
	Ovno     uint16     // USHORT Overlay number
	Res      [4]uint16  // USHORT Reserved words
	OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
	OEMInfo  uint16     // USHORT OEM information; e_oemid specific
	Res2     [10]uint16 // USHORT Reserved words
	LfaNew   int32      // LONG File address of bypass exe header
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}
