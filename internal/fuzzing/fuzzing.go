package fuzzing

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"snapandgo/internal/ptrace"
	"snapandgo/internal/snapshot"
	"snapandgo/internal/utils"
	"strconv"
	"strings"
	"syscall"
)

// Fuzzer handle the fuzzing stuff
type Fuzzer struct {
	Base uint64

	snapshot       *snapshot.Manager
	targetPid      int
	initialPayload string
	breakpoints    []uint64
	mainAddr       uintptr
	exitAddr       uintptr
	payloadPtr     uint64
}

func (p *Fuzzer) loadBreakpoints(bpFile string) {
	inFile, err := os.Open(bpFile)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)

	for scanner.Scan() {
		val, _ := strconv.ParseUint(strings.Replace(scanner.Text(), "0x", "", -1), 16, 64)
		p.breakpoints = append(p.breakpoints, val)
		//log.Printf("0x%x / %s", val, scanner.Text())
	}

	log.Printf("Loaded %d breakpoints", len(p.breakpoints))
}

func (p *Fuzzer) mutateInput() {
	// override input param
	ptrace.Write(p.targetPid, uintptr(p.payloadPtr), []byte{0x41, 0x42, 0x43, 0x44, 0x0})
}

// Init the Fuzzer instance
func (p *Fuzzer) Init(target string, breakpointsPath string) {
	procAttr := syscall.ProcAttr{
		Dir:   "",
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Env:   []string{},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	}

	p.initialPayload = "deadbeef"

	var err error
	p.targetPid, err = syscall.ForkExec(target, []string{"target", p.initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d", p.targetPid)
	p.snapshot = &snapshot.Manager{
		Pid: p.targetPid,
	}
	p.loadBreakpoints(breakpointsPath)

}

// Fuzz Start fuzzing task
func (p *Fuzzer) Fuzz() {

	p.mainAddr = uintptr(p.Base + 0x304)
	p.exitAddr = uintptr(p.Base + 0x36a)

	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	fmt.Printf("Status: %s (%d)\n", utils.ExplainWaitStatus(wstat), wstat)

	originalMainByte := ptrace.Read(p.targetPid, p.mainAddr, 1)

	// Replace main/exit with software breakpoint 0xCC
	ptrace.Write(p.targetPid, p.mainAddr, []byte{0xCC})
	ptrace.Write(p.targetPid, p.exitAddr, []byte{0xCC})
	syscall.PtraceCont(p.targetPid, 0)

	fmt.Println("Waiting to reach main() breakpoint..")
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	if wstat.StopSignal() == 5 {
		// revert main breakpoint
		ptrace.Write(p.targetPid, p.mainAddr, originalMainByte)
		// rewind EIP
		p.snapshot.RewindEIP()
		// Snapshot!
		p.snapshot.TakeSnapshot()
		// locate payload
		p.payloadPtr = p.snapshot.Locate([]byte(p.initialPayload))
		if p.payloadPtr <= 0 {
			log.Fatalf("Unable to locate payload '%s' in RW sections!", p.initialPayload)
		} else {
			log.Printf("Initial payload '%s' located at 0x%x", p.initialPayload, p.payloadPtr)
		}
		// continue
		syscall.PtraceCont(p.targetPid, 0)
	} else {
		log.Fatalf("We expected main to be found: %s", utils.ExplainWaitStatus(wstat))
	}

	loopCount := 0
	log.Printf("Entering main fuzzing loop...")
	for {
		syscall.Wait4(p.targetPid, &wstat, 0, nil)
		log.Printf("[+] %d loop - EIP 0x%x", loopCount, ptrace.GetEIP(p.targetPid))
		// exit bp hit
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(p.targetPid)
			log.Printf("BP, EIP 0x%x", eip)
			if uintptr(eip-1) == p.exitAddr {
				log.Printf("Exit BP hit, restoring p.snapshot!")
				p.snapshot.RestoreSnapshot()
				p.mutateInput()
				loopCount++
			} else {
				log.Printf("Unknown breakpoint!")
				break
			}
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
		syscall.PtraceCont(p.targetPid, 0)
	}
}
