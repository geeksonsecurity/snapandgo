package ptrace

import (
	"log"
	"syscall"
)

// Read bytes from given PID
func Read(pid int, addr uintptr, count uint64) []byte {
	dword := make([]byte, count)
	_, err := syscall.PtracePeekText(pid, addr, dword)
	if err != nil {
		log.Printf("Failed to read to pid %d", pid)
		log.Fatal(err)
	}
	//log.Printf("Read %d bytes", readcount)
	return dword
}

// Write bytes to given PID address
func Write(pid int, addr uintptr, bytes []byte) uint {
	res, err := syscall.PtracePokeText(pid, addr, bytes)
	if err != nil {
		log.Printf("Failed to write to pid %d", pid)
		log.Fatal(err)
	}
	return uint(res)
}

// GetEIP Return EIP
func GetEIP(pid int) uint64 {
	var regs syscall.PtraceRegs
	syscall.PtraceGetRegs(pid, &regs)
	return regs.PC()
}

// SetEIP set EIP
func SetEIP(pid int, newEIP uint64) uint64 {
	var regs syscall.PtraceRegs
	syscall.PtraceGetRegs(pid, &regs)
	regs.SetPC(newEIP)
	syscall.PtraceSetRegs(pid, &regs)
	return regs.PC()
}

// SaveRegisters save registers (-_-)
func SaveRegisters(pid int, regs *syscall.PtraceRegs) {
	err := syscall.PtraceGetRegs(pid, regs)
	if err != nil {
		log.Printf("Failed to save registers for pid %d", pid)
		log.Fatal(err)
	}
}

// RestoreRegisters restore registers (-_-)
func RestoreRegisters(pid int, regs *syscall.PtraceRegs) {
	err := syscall.PtraceSetRegs(pid, regs)
	if err != nil {
		log.Printf("Failed to restore registers for pid %d", pid)
		log.Fatal(err)
	}
}
