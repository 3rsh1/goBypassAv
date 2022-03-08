package winApi

import (
	"github.com/JamesHovious/w32"
	"syscall"
)

var (
	kernel32                   = syscall.MustLoadDLL("kernel32.dll")
	SetFileInformationByHandle = kernel32.MustFindProc("SetFileInformationByHandle")
	OpenProcess                = kernel32.MustFindProc("OpenProcess")
	VirtualProtectEx           = kernel32.MustFindProc("VirtualProtectEx")
	ConvertThreadToFiber       = kernel32.MustFindProc("ConvertThreadToFiber")
	CreateFiber                = kernel32.MustFindProc("CreateFiber")
	SwitchToFiber              = kernel32.MustFindProc("SwitchToFiber")
)

var (
	ntdll                        = syscall.MustLoadDLL("ntdll.dll")
	NtCreateProcessEx            = ntdll.MustFindProc("NtCreateProcessEx")
	NtCreateSection              = ntdll.MustFindProc("NtCreateSection")
	NtClose                      = ntdll.MustFindProc("NtClose")
	NtReadVirtualMemory          = ntdll.MustFindProc("NtReadVirtualMemory")
	NtCreateThreadEx             = ntdll.MustFindProc("NtCreateThreadEx")
	RtlCreateProcessParametersEx = ntdll.MustFindProc("RtlCreateProcessParametersEx")
	NtQueryInformationProcess    = ntdll.MustFindProc("NtQueryInformationProcess")
	RtlInitUnicodeStringEx       = ntdll.MustFindProc("RtlInitUnicodeStringEx")
	RtlCopyMemory                = ntdll.MustFindProc("RtlCopyMemory")
	RtlMoveMemory                = ntdll.MustFindProc("RtlMoveMemory")
)

var (
	psapi                = syscall.MustLoadDLL("psapi.dll")
	EnumProcessModules   = psapi.MustFindProc("EnumProcessModules")
	GetModuleFileNameExW = psapi.MustFindProc("GetModuleFileNameExW")
)

const MAX_PATH = 255

const (
	FileBasicInfo                  = 0
	FileStandardInfo               = 1
	FileNameInfo                   = 2
	FileRenameInfo                 = 3
	FileDispositionInfo            = 4
	FileAllocationInfo             = 5
	FileEndOfFileInfo              = 6
	FileStreamInfo                 = 7
	FileCompressionInfo            = 8
	FileAttributeTagInfo           = 9
	FileIdBothDirectoryInfo        = 10 // 0xA
	FileIdBothDirectoryRestartInfo = 11 // 0xB
	FileIoPriorityHintInfo         = 12 // 0xC
	FileRemoteProtocolInfo         = 13 // 0xD
	FileFullDirectoryInfo          = 14 // 0xE
	FileFullDirectoryRestartInfo   = 15 // 0xF
	FileStorageInfo                = 16 // 0x10
	FileAlignmentInfo              = 17 // 0x11
	FileIdInfo                     = 18 // 0x12
	FileIdExtdDirectoryInfo        = 19 // 0x13
	FileIdExtdDirectoryRestartInfo = 20 // 0x14
)

type FileInformationClass int
type ACCESS_MASK uint32

type FILE_DISPOSITION_INFO struct {
	DeleteFile bool
}

type OBJECT_ATTRIBUTES struct {
	length                   uint32
	RootDirectory            w32.HANDLE
	ObjectName               *w32.UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       w32.PVOID
	SecurityQualityOfService w32.PVOID
}

type RTL_USER_PROCESS_PARAMETERS struct {
	reserve1      [16]byte
	reserve2      [10]uintptr
	ImagePathName w32.UNICODE_STRING
	CommandLine   w32.UNICODE_STRING
}

type PROCESS_BASE_INFORMATION struct {
	ExitStatus                   uint
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}
