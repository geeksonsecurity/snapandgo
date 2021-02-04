package snapshot

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"snapandgo/internal/ptrace"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
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
	Offset  uint64
	Module  string
	Content []byte
	Perms   Permission
	Size    uint64
}

// Manager self explaining
type Manager struct {
	Pid    int
	Target string

	writableSections []*MemorySection
	sections         []*MemorySection
	registers        syscall.PtraceRegs
}

// GetXSections return executable sections
func (m *Manager) GetXSections() []*MemorySection {
	var xmems []*MemorySection
	for _, s := range m.sections {
		if s.Perms.Executable() {
			xmems = append(xmems, s)
		}
	}
	return xmems
}

// ConvertRelativeAddress Convert RVA to absolute memory address
func (m *Manager) ConvertRelativeAddress(addr uint64) uint64 {
	mainSection, _ := m.GetMainSection()
	return addr - mainSection.Offset + mainSection.From
}

// ConvertRelativeAddressWoOffset Convert RVA to absolute memory address (without adding section offset)
func (m *Manager) ConvertRelativeAddressWoOffset(addr uint64) uint64 {
	mainSection, _ := m.GetMainSection()
	return addr + mainSection.From
}

// ResolveAddress return the function offset
func (m *Manager) ResolveAddress(funcName string) uint64 {
	addrRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep %s | awk '{print $1}'", m.Target, funcName)).Output()
	addr, _ := strconv.ParseUint(strings.TrimSpace(string(addrRaw)), 16, 64)
	return m.ConvertRelativeAddress(addr)
}

// GetEntrypoint return main entrypoint
func (m *Manager) GetEntrypoint() uint64 {
	startRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep -sw _start | awk '{print $1}'", m.Target)).Output()
	start, _ := strconv.ParseUint(strings.TrimSpace(string(startRaw)), 16, 64)
	return m.ConvertRelativeAddress(start)
}

// GetMainSection return target main executable section
func (m *Manager) GetMainSection() (*MemorySection, error) {
	if m.sections == nil {
		m.LoadMemoryMap()
	}
	for _, s := range m.GetXSections() {
		//log.Printf(">> %s", s.Module)
		// remove dots to avoid relative paths not matching
		if strings.Contains(s.Module, strings.ReplaceAll(m.Target, ".", "")) {
			//log.Printf("Found main executable module 0x%x-0x%x [offset 0x%x]", s.From, s.To, s.Offset)
			return s, nil
		}
	}
	return nil, errors.New("Unable to locate main section")
}

// LoadMemoryMap load /proc/id/maps
func (m *Manager) LoadMemoryMap() {
	m.sections = nil
	m.writableSections = nil
	mapsfile, err := os.Open(fmt.Sprintf("/proc/%d/maps", m.Pid))
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
		section.Offset, _ = strconv.ParseUint(lineTokens[2], 16, 0)
		section.Module = lineTokens[5]
		section.Size = section.To - section.From
		m.sections = append(m.sections, &section)
		if section.Perms.Writable() {
			m.writableSections = append(m.writableSections, &section)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}

// TakeSnapshot takes a memory snapshot of all writable memory region for given Pid
func (m *Manager) TakeSnapshot() {
	log.Printf("Taking snapshot of PID %d | EIP: 0x%x", m.Pid, ptrace.GetEIP(m.Pid))

	for _, s := range m.writableSections {
		log.Printf("Reading 0x%x-0x%x [%d bytes] - %s - %s", s.From, s.To, s.Size, s.Perms, s.Module)
		// TODO: is this the right way to update the object correctly?
		// Doing s.Content will result in the array not being persisted
		s.Content = ptrace.Read(m.Pid, uintptr(s.From), s.Size)
		if uint64(len(s.Content)) != s.Size {
			log.Panic("Failed to read bytes from Target process!")
		}
	}

	ptrace.SaveRegisters(m.Pid, &m.registers)
	log.Printf("Registers saved! EIP: 0x%x", m.registers.PC())
}

// RestoreSnapshot restore writable pages in the Target process
func (m *Manager) RestoreSnapshot() {
	//TODO: we should use process_vm_writev here (ProcessVMWritev)
	//log.Printf("Restoring snapshot for PID %d", m.Pid)
	for _, s := range m.writableSections {

		//data := []byte{0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1}
		//log.Printf("Restoring 0x%x-0x%x [%d bytes | backing %p] - %s - %s", s.From, s.To, len(s.Content), &s.Content[0], s.Perms, s.Module)

		localIovec := unix.Iovec{Base: &s.Content[0], Len: uint64(len(s.Content))}
		remoteIovec := unix.RemoteIovec{Base: uintptr(s.From), Len: len(s.Content)}

		var localIovecs []unix.Iovec
		var remoteIovecs []unix.RemoteIovec
		localIovecs = append(localIovecs, localIovec)
		remoteIovecs = append(remoteIovecs, remoteIovec)

		//log.Printf("Almost ready to restore process %d", m.Pid)
		//bufio.NewReader(os.Stdin).ReadBytes('\n')

		written, err := unix.ProcessVMWritev(m.Pid, localIovecs, remoteIovecs, 0)
		if err != nil {
			log.Fatal(err)
		}

		//log.Printf("Restoring 0x%x-0x%x [%d bytes] - %s - %s", s.From, s.To, s.Size, s.Perms, s.Module)
		//written := ptrace.Write(m.Pid, uintptr(s.From), s.Content)
		if uint64(written) != s.Size {
			log.Panicf("Failed to write all %d bytes to Target process, wrote %d only!", s.Size, written)
		}
	}
	ptrace.RestoreRegisters(m.Pid, &m.registers)
	//log.Printf("Registers restored! EIP: 0x%x", m.registers.PC())
}

// RewindEIP rewind EIP by one
func (m *Manager) RewindEIP() {
	// rewin RIP
	var regs syscall.PtraceRegs
	syscall.PtraceGetRegs(m.Pid, &regs)
	regs.SetPC(regs.PC() - 1)
	err := syscall.PtraceSetRegs(m.Pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
}

// Locate locate payload in RW sections
func (m *Manager) Locate(payload []byte) uint64 {
	for _, s := range m.writableSections {
		log.Printf("Searching in 0x%x-0x%x [%d bytes]", s.From, s.To, len(s.Content))
		idx := bytes.Index(s.Content, payload)
		if idx > -1 {
			return s.From + uint64(idx)
		}
	}
	return 0
}
