package fuzzing

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"snapandgo/internal/ptrace"
	"snapandgo/internal/snapshot"
	"snapandgo/internal/utils"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Fuzzer handle the fuzzing stuff
type Fuzzer struct {
	Base uint64

	snapshot       *snapshot.Manager
	mainSection    *snapshot.MemorySection
	start          uint64
	end            uint64
	target         string
	targetPid      int
	initialPayload string
	breakpoints    map[uint64]byte
	payloadPtr     uint64
	startTime      time.Time
	iterationCount uint64
}

func (p *Fuzzer) resolveStartEndAddress(startFuncName string, endFuncName string) (uint64, uint64) {
	startRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep %s | awk '{print $1}'", p.target, startFuncName)).Output()
	endRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep %s | awk '{print $1}'", p.target, endFuncName)).Output()
	start, _ := strconv.ParseUint(strings.TrimSpace(string(startRaw)), 16, 64)
	end, _ := strconv.ParseUint(strings.TrimSpace(string(endRaw)), 16, 64)
	return start, end
}

func (p *Fuzzer) loadInitialState() {

	p.breakpoints = make(map[uint64]byte)
	p.mainSection = nil

	p.snapshot.LoadMemoryMap()

	for _, s := range p.snapshot.GetXSections() {
		log.Printf(">> %s", s.Module)
		// remove dots to avoid relative paths not matching
		if strings.Contains(s.Module, strings.ReplaceAll(p.target, ".", "")) {
			log.Printf("Found main executable module 0x%x-0x%x [offset 0x%x]", s.From, s.To, s.Offset)
			p.mainSection = s
			break
		}
	}

	if p.mainSection == nil {
		log.Fatalf("Unable to locate main memory region for target '%s'", p.target)
	}

	p.start, p.end = p.resolveStartEndAddress("startf", "endf")
	p.start = p.start - p.mainSection.Offset + p.mainSection.From
	p.end = p.end - p.mainSection.Offset + p.mainSection.From
	log.Printf("Located start @ 0x%x and end @ 0x%x", p.start, p.end)

	outputRaw, err := exec.Command("objdump", "-d", "-j", ".text", p.target).Output()

	if err != nil {
		log.Fatal(err)
	}

	output := string(outputRaw)

	output = output[strings.Index(output, ".text:")+8:]
	output = strings.ReplaceAll(output, "\n\n", "\n")
	outscanner := bufio.NewScanner(strings.NewReader(output))

	for outscanner.Scan() {
		line := outscanner.Text()
		if line == "" {
			continue
		}
		if line[len(line)-1:] == ":" {
			continue
		}
		r, _ := regexp.Compile("^\\s*([0-9a-f]+)")
		match := r.FindString(line)
		addr, _ := strconv.ParseUint(strings.TrimSpace(match), 16, 64)
		addr = addr - p.mainSection.Offset + p.mainSection.From
		p.breakpoints[addr] = ptrace.Read(p.targetPid, uintptr(addr), 1)[0]
		//log.Printf("Loaded breakpoint @ %x", addr)
	}
	log.Printf("Loaded %d breakpoints!", len(p.breakpoints))
	return
}

func (p *Fuzzer) setDynamicBreakpoints() {
	for addr := range p.breakpoints {
		ptrace.Write(p.targetPid, uintptr(addr), []byte{0xCC})
	}
}

func (p *Fuzzer) restoreDynamicBreakpoint(addr uint64) {
	log.Printf("Restoring breakpoint @ 0x%x", addr)
	ptrace.Write(p.targetPid, uintptr(addr), []byte{p.breakpoints[addr]})
}

func (p *Fuzzer) mutateInput() {
	// override input param
	ptrace.Write(p.targetPid, uintptr(p.payloadPtr), []byte{0x41, 0x42, 0x43, 0x44, 0x0})
}

func (p *Fuzzer) printStats() {
	elapsed := time.Since(p.startTime)
	log.Printf("[%10.4f] cases %.10d | fcps %8.4f", elapsed.Seconds(), p.iterationCount, float64(p.iterationCount)/elapsed.Seconds())
}

// Init the Fuzzer instance
func (p *Fuzzer) Init(target string, breakpointsPath string) {

	p.target = target
	devNull := os.NewFile(0, os.DevNull)
	//FIXME: why child keeps sending output to stdout?
	procAttr := syscall.ProcAttr{
		Dir:   "",
		Files: []uintptr{devNull.Fd(), devNull.Fd(), devNull.Fd()},
		Env:   []string{},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	}

	p.initialPayload = "deadbeef"

	var err error
	runtime.LockOSThread()
	p.targetPid, err = syscall.ForkExec(target, []string{"target", p.initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d, Parent is %d", p.targetPid, os.Getpid())
	p.snapshot = &snapshot.Manager{
		Pid: p.targetPid,
	}
}

// Fuzz Start fuzzing task
func (p *Fuzzer) Fuzz() {
	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	log.Printf("Trapped at beginning of traced process @ 0x%x", ptrace.GetEIP(p.targetPid))

	p.loadInitialState()

	originalMainByte := ptrace.Read(p.targetPid, uintptr(p.start), 1)

	// Replace main/exit with software breakpoint 0xCC
	ptrace.Write(p.targetPid, uintptr(p.start), []byte{0xCC})
	syscall.PtraceCont(p.targetPid, 0)

	log.Println("Waiting to reach main() breakpoint..")
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	if wstat.StopSignal() == 5 {
		eip := ptrace.GetEIP(p.targetPid)
		if eip-1 != p.start {
			log.Fatalf("We didnt stop in main but at 0x%x", eip-1)
		}
		// revert main breakpoint
		ptrace.Write(p.targetPid, uintptr(p.start), originalMainByte)
		// rewind EIP
		p.snapshot.RewindEIP()
		//p.setDynamicBreakpoints()
		// set exit breakpoint
		ptrace.Write(p.targetPid, uintptr(p.end), []byte{0xCC})
		// Snapshot!
		p.snapshot.TakeSnapshot()
		// locate payload
		p.payloadPtr = p.snapshot.Locate([]byte(p.initialPayload))
		if p.payloadPtr <= 0 {
			log.Fatalf("Unable to locate payload '%s' in RW sections!", p.initialPayload)
		} else {
			log.Printf("Initial payload '%s' located at 0x%x", p.initialPayload, p.payloadPtr)
		}
	} else {
		log.Fatalf("We expected main to be found: %s", utils.ExplainWaitStatus(wstat))
	}

	p.iterationCount = 0
	p.startTime = time.Now()
	log.Printf("Entering main fuzzing loop...")
	for {
		if p.iterationCount%50 == 0 {
			p.printStats()
		}
		syscall.PtraceCont(p.targetPid, 0)
		syscall.Wait4(p.targetPid, &wstat, 0, nil)

		// Breakpoint hit!
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(p.targetPid) - 1
			// Is exit breakpoint? Rewind!
			if uintptr(eip) == uintptr(p.end) {
				//log.Printf("Exit BP hit, restoring p.snapshot!")
				p.snapshot.RestoreSnapshot()
				//p.mutateInput()
				p.iterationCount++
			} else {
				log.Printf("BP, EIP 0x%x", eip)
				//p.restoreDynamicBreakpoint(eip)
			}
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
	}
	runtime.UnlockOSThread()
}
