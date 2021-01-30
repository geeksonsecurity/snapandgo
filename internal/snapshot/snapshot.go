package snapshot

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"snapandgo/internal/ptrace"
)

// Permission representation
type Permission struct {
	perms string
}

// Readable is readable?
func (p Permission) Readable() bool {
	return strings.Contains(p.perms, "r")
}

// Writable is writable?
func (p Permission) Writable() bool {
	return strings.Contains(p.perms, "w")
}

// Executable is executable?
func (p Permission) Executable() bool {
	return strings.Contains(p.perms, "x")
}

func (p Permission) String() string {
	return p.perms
}

// MemorySection holds memory section informations
type MemorySection struct {
	From    uint64
	To      uint64
	Module  string
	Content []byte
	Perms   Permission
	Size    uint64
}

// Manager self explaining
type Manager struct {
	Pid int

	writableSections []*MemorySection
	sections         []*MemorySection
	registers        syscall.PtraceRegs
}

// TakeSnapshot takes a memory snapshot of all writable memory region for given pid
func (p *Manager) TakeSnapshot() {
	log.Printf("Taking snapshot of PID %d | EIP: 0x%x", p.Pid, ptrace.GetEIP(p.Pid))
	mapsfile, err := os.Open(fmt.Sprintf("/proc/%d/maps", p.Pid))
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(mapsfile)
	for scanner.Scan() {
		line := scanner.Text()
		// split columns (one or more whitespace)
		lineTokens := regexp.MustCompile("[ ]{1,}").Split(line, -1)
		addresses := strings.Split(lineTokens[0], "-")
		section := MemorySection{}
		section.From, _ = strconv.ParseUint(addresses[0], 16, 0)
		section.To, _ = strconv.ParseUint(addresses[1], 16, 0)
		section.Perms = Permission{lineTokens[1]}
		section.Module = lineTokens[5]
		section.Size = section.To - section.From
		p.sections = append(p.sections, &section)
		if section.Perms.Writable() {
			p.writableSections = append(p.writableSections, &section)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for _, s := range p.writableSections {
		log.Printf("Reading 0x%x-0x%x [%d bytes] - %s - %s", s.From, s.To, s.Size, s.Perms, s.Module)
		// TODO: is this the right way to update the object correctly?
		// Doing s.Content will result in the array not being persisted
		s.Content = ptrace.Read(p.Pid, uintptr(s.From), s.Size)
		if uint64(len(s.Content)) != s.Size {
			log.Panic("Failed to read bytes from target process!")
		}
	}

	ptrace.SaveRegisters(p.Pid, &p.registers)
	log.Printf("Registers saved! EIP: 0x%x", p.registers.PC())
}

// RestoreSnapshot restore writable pages in the target process
func (p *Manager) RestoreSnapshot() {
	//TODO: we should use process_vm_writev here (ProcessVMWritev)
	//log.Printf("Restoring snapshot for PID %d", p.Pid)
	for _, s := range p.writableSections {
		//log.Printf("Restoring 0x%x-0x%x [%d bytes] - %s - %s", s.From, s.To, s.Size, s.Perms, s.Module)
		written := ptrace.Write(p.Pid, uintptr(s.From), s.Content)
		if uint64(written) != s.Size {
			log.Panicf("Failed to write all %d bytes to target process, wrote %d only!", s.Size, written)
		}
	}
	ptrace.RestoreRegisters(p.Pid, &p.registers)
	//log.Printf("Registers restored! EIP: 0x%x", p.registers.PC())
}

// RewindEIP rewind EIP by one
func (p *Manager) RewindEIP() {
	// rewin RIP
	var regs syscall.PtraceRegs
	syscall.PtraceGetRegs(p.Pid, &regs)
	regs.SetPC(regs.PC() - 1)
	err := syscall.PtraceSetRegs(p.Pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
}

// Locate locate payload in RW sections
func (p *Manager) Locate(payload []byte) uint64 {
	for _, s := range p.writableSections {
		log.Printf("Searching in 0x%x-0x%x [%d bytes]", s.From, s.To, len(s.Content))
		idx := bytes.Index(s.Content, payload)
		if idx > -1 {
			return s.From + uint64(idx)
		}
	}
	return 0
}
