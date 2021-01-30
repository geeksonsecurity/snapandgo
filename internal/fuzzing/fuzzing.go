package fuzzing

import (
	"bufio"
	"log"
	"os"
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
	targetPid      int
	initialPayload string
	breakpoints    []uint64
	mainAddr       uintptr
	exitAddr       uintptr
	payloadPtr     uint64
	startTime      time.Time
	iterationCount uint64
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

func (p *Fuzzer) printStats() {
	elapsed := time.Since(p.startTime)
	log.Printf("[%10.4f] cases %.10d | fcps %8.4f", elapsed.Seconds(), p.iterationCount, float64(p.iterationCount)/elapsed.Seconds())
}

// Init the Fuzzer instance
func (p *Fuzzer) Init(target string, breakpointsPath string) {

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
	p.targetPid, err = syscall.ForkExec(target, []string{"target", p.initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d, Parent is %d", p.targetPid, os.Getpid())
	p.snapshot = &snapshot.Manager{
		Pid: p.targetPid,
	}
	p.loadBreakpoints(breakpointsPath)

}

// Fuzz Start fuzzing task
func (p *Fuzzer) Fuzz() {
	p.mainAddr = uintptr(p.Base + 0x2f4)
	p.exitAddr = uintptr(p.Base + 0x39c)

	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	syscall.Wait4(p.targetPid, &wstat, 0, nil)

	originalMainByte := ptrace.Read(p.targetPid, p.mainAddr, 1)

	// Replace main/exit with software breakpoint 0xCC
	ptrace.Write(p.targetPid, p.mainAddr, []byte{0xCC})
	ptrace.Write(p.targetPid, p.exitAddr, []byte{0xCC})
	syscall.PtraceCont(p.targetPid, 0)

	log.Println("Waiting to reach main() breakpoint..")
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

	p.iterationCount = 0
	p.startTime = time.Now()
	log.Printf("Entering main fuzzing loop...")
	for {
		if p.iterationCount%50 == 0 {
			p.printStats()
		}
		syscall.Wait4(p.targetPid, &wstat, 0, nil)
		//log.Printf("[+] %d loop - EIP 0x%x", p.iterationCount, ptrace.GetEIP(p.targetPid))
		// exit bp hit
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(p.targetPid)
			//log.Printf("BP, EIP 0x%x", eip)
			if uintptr(eip-1) == p.exitAddr {
				//log.Printf("Exit BP hit, restoring p.snapshot!")
				p.snapshot.RestoreSnapshot()
				p.mutateInput()
				p.iterationCount++
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
