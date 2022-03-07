package winApi

import (
	"github.com/JamesHovious/w32"
	"unsafe"
)

func ProcSetFileInformationByHandle(fileHandle w32.HANDLE, FileInformationClass1 FileInformationClass, fileInformation *FILE_DISPOSITION_INFO, bufferSize w32.DWORD) bool {
	isSuc, _, _ := SetFileInformationByHandle.Call(uintptr(fileHandle), uintptr(FileInformationClass1), uintptr(unsafe.Pointer(fileInformation)), uintptr(bufferSize))
	if isSuc == 1 {
		return true
	} else {
		return false
	}
}

func ProcNtCreateSection(pHandle *w32.HANDLE, DesiredAccess ACCESS_MASK, ObjectAttributes *OBJECT_ATTRIBUTES, MaximumSize *uint64, SectionPageProtection uint32, AllocationAttributes uint32, FileHandle w32.HANDLE) uint32 {
	res, _, _ := NtCreateSection.Call(uintptr(unsafe.Pointer(pHandle)), uintptr(DesiredAccess), uintptr(unsafe.Pointer(ObjectAttributes)), uintptr(unsafe.Pointer(MaximumSize)), uintptr(SectionPageProtection), uintptr(AllocationAttributes), uintptr(FileHandle))
	return uint32(res)
}

func ProcNtCreateProcess(pHandle *w32.HANDLE, DesiredAccess ACCESS_MASK, ObjectAttributes *OBJECT_ATTRIBUTES, parentProcess w32.HANDLE, InheritObjectTable uint, sectionHandle w32.HANDLE, DebugPort w32.HANDLE, ExceptionPort w32.HANDLE, Injob uint8) uint32 {

	res, _, _ := NtCreateProcessEx.Call(uintptr(unsafe.Pointer(pHandle)), uintptr(DesiredAccess), uintptr(unsafe.Pointer(ObjectAttributes)), uintptr(parentProcess), uintptr(InheritObjectTable), uintptr(sectionHandle), uintptr(DebugPort), uintptr(ExceptionPort), uintptr(Injob))
	return uint32(res)

}

func ProcRtlCreateProcessParametersEx(pProcessParameters *uintptr, ImagePathName *w32.UNICODE_STRING, DllPath *w32.UNICODE_STRING, CurrentDirectory *w32.UNICODE_STRING, CommandLine *w32.UNICODE_STRING, Environment w32.PVOID, WindowTitle *w32.UNICODE_STRING, DesktopInfo *w32.UNICODE_STRING, ShellInfo *w32.UNICODE_STRING, RuntimeData *w32.UNICODE_STRING, flag uint) uint32 {
	res, _, _ := RtlCreateProcessParametersEx.Call(uintptr(unsafe.Pointer(pProcessParameters)), uintptr(unsafe.Pointer(ImagePathName)), uintptr(unsafe.Pointer(DllPath)), uintptr(unsafe.Pointer(CurrentDirectory)), uintptr(unsafe.Pointer(CommandLine)), uintptr(Environment), uintptr(unsafe.Pointer(WindowTitle)), uintptr(unsafe.Pointer(DesktopInfo)), uintptr(unsafe.Pointer(ShellInfo)), uintptr(unsafe.Pointer(RuntimeData)), uintptr(flag))
	return uint32(res)
}

func ProcNtQueryInformationProcess(hProcess w32.HANDLE, ProcessInfoClass int, ProcessInformation *PROCESS_BASE_INFORMATION, ProcessInformationLength uint32, ReturnLength w32.ULONG_PTR) uint32 {
	res, _, _ := NtQueryInformationProcess.Call(uintptr(hProcess), uintptr(ProcessInfoClass), uintptr(unsafe.Pointer(ProcessInformation)), uintptr(ProcessInformationLength), uintptr(ReturnLength))
	return uint32(res)
}

func ProcVirtualProtectEx(hProcess w32.HANDLE, lpAddress w32.PVOID, dwSize w32.SIZE_T, flNewProtect w32.DWORD, lpflOldProtect *w32.DWORD) uint32 {
	res, _, _ := VirtualProtectEx.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	return uint32(res)
}

func ProcNtReadVirtualMemory(processHandle w32.HANDLE, BaseAddress w32.PVOID, Buffer w32.PVOID, NumberOfBytesToRead uint32, NumberOfBytesReaded *uint32) uint32 {
	res, _, _ := NtReadVirtualMemory.Call(uintptr(processHandle), uintptr(BaseAddress), uintptr(Buffer), uintptr(NumberOfBytesToRead), uintptr(unsafe.Pointer(NumberOfBytesReaded)))
	return uint32(res)
}

func ProcRtlInitUnicodeStringEx(target *w32.UNICODE_STRING, source *string) uint32 {

	res, _, _ := RtlInitUnicodeStringEx.Call(uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(source)))
	return uint32(res)

}

func ProcNtCreateThreadEx(hThread *w32.HANDLE, DesiredAccess ACCESS_MASK, ObjectAttributes *w32.OBJECT_ATTRIBUTES, ProcessHandle w32.HANDLE, lpStartAddress unsafe.Pointer, lpParameter unsafe.Pointer, CreateSuspended int, StackZeroBits uint32, SizeOfStackCommit uint32, SizeOfStackReserve uint32, lpBytesBuffer unsafe.Pointer) uint32 {
	res, _, _ := NtCreateThreadEx.Call(uintptr(unsafe.Pointer(hThread)), uintptr(DesiredAccess), uintptr(unsafe.Pointer(ObjectAttributes)), uintptr(ProcessHandle), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(CreateSuspended), uintptr(StackZeroBits), uintptr(SizeOfStackCommit), uintptr(SizeOfStackReserve), uintptr(lpBytesBuffer))
	return uint32(res)
}

func ProcOpenProcess(DesireAccess, InheritHandle, ProcessId uint) uintptr {
	processHandle, _, _ := OpenProcess.Call(uintptr(DesireAccess), uintptr(InheritHandle), uintptr(ProcessId))
	return processHandle
}

func ProcEnumProcessModules(hProcess w32.HANDLE, hmodule *w32.HMODULE, cb w32.DWORD, lpcbNeeded *w32.DWORD) bool {
	isSuccess, _, _ := EnumProcessModules.Call(uintptr(hProcess), uintptr(unsafe.Pointer(hmodule)), uintptr(cb), uintptr(unsafe.Pointer(lpcbNeeded)))
	if isSuccess == 0 {
		return false
	} else {
		return true
	}
}

func ProcGetModuleFileNameExW(hProcess w32.HANDLE, hModule w32.HMODULE, lpFileName *[MAX_PATH]uint16, size w32.DWORD) uint32 {
	isSuccessGetModule, _, _ := GetModuleFileNameExW.Call(uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(lpFileName)), uintptr(size))
	return uint32(isSuccessGetModule)
}

func ProcConvertThreadToFiber() uintptr {
	fiberAddress, _, _ := ConvertThreadToFiber.Call()
	if fiberAddress != 0 {
		return fiberAddress
	} else {
		return 0
	}
}

func ProcRtlCopyMemory(Destination w32.PVOID, Source w32.PVOID, Length uintptr) {
	_, _, _ = RtlCopyMemory.Call(uintptr(Destination), uintptr(Source), Length)
}

//https://docs.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-switchtofiber
func ProcSwitchToFiber(lpFiber w32.PVOID) {
	SwitchToFiber.Call(uintptr(lpFiber))
}

//https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber
func ProcCreateFiber(dwStackSize w32.SIZE_T, lpStartAddress w32.PVOID, lpParameter w32.PVOID) uintptr {
	isSucc, _, _ := CreateFiber.Call(uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter))
	return isSucc
}
