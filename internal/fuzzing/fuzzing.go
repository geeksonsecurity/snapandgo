package fuzzing

import (
	"bufio"
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
	mutationEngine *Mutation

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

func (f *Fuzzer) loadInitialState() {

	f.breakpoints = make(map[uint64]byte)
	f.start = f.snapshot.ResolveAddress("startf")
	f.end = f.snapshot.ResolveAddress("endf")
	log.Printf("Located start @ 0x%x and end @ 0x%x", f.start, f.end)
	outputRaw, err := exec.Command("objdump", "-d", "-j", ".text", f.target).Output()

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
		addr = f.snapshot.ConvertRVA(addr)
		f.breakpoints[addr] = ptrace.Read(f.targetPid, uintptr(addr), 1)[0]
		//log.Printf("Loaded breakpoint @ %x", addr)
	}
	log.Printf("Loaded %d breakpoints!", len(f.breakpoints))
	return
}

func (f *Fuzzer) setDynamicBreakpoints() {
	for addr := range f.breakpoints {
		ptrace.Write(f.targetPid, uintptr(addr), []byte{0xCC})
		//log.Printf("Set bp 0x%x", addr)
	}
}

func (f *Fuzzer) restoreDynamicBreakpoint(addr uint64) {
	res := ptrace.Write(f.targetPid, uintptr(addr), []byte{f.breakpoints[addr]})
	if res != 1 {
		log.Fatalf("Failed to revert bp @ 0x%x with value 0x%x", addr, f.breakpoints[addr])
	}
	ptrace.SetEIP(f.targetPid, addr)
	//log.Printf("Reverting bp @ 0x%x with value 0x%x", addr, f.breakpoints[addr])
}
func (f *Fuzzer) mutateInput() []byte {
	// override input param
	newPayload := f.mutationEngine.Mutate()
	// add null terminator
	ptrace.Write(f.targetPid, uintptr(f.payloadPtr), append(newPayload, 0x0))
	return newPayload
}

func (f *Fuzzer) printStats() {
	elapsed := time.Since(f.startTime)
	found := 0
	for _, v := range f.breakpoints {
		if v == 0 {
			found++
		}
	}

	log.Printf("[%10.4f] cases %10d | fcps %8.4f | cov %2.1f%% (hit: %3d, tot: %3d) | corpus: %d", elapsed.Seconds(), f.iterationCount, float64(f.iterationCount)/elapsed.Seconds(), float64(found)/float64(len(f.breakpoints))*100.0, found, len(f.breakpoints), len(f.mutationEngine.corpus))
}

// Init the Fuzzer instance
func (f *Fuzzer) Init(target string, breakpointsPath string) {

	f.target = target
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

	f.initialPayload = "deadbeef"

	var err error
	runtime.LockOSThread()
	f.targetPid, err = syscall.ForkExec(target, []string{"target", f.initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d, Parent is %d", f.targetPid, os.Getpid())
	f.snapshot = &snapshot.Manager{
		Pid:    f.targetPid,
		Target: f.target,
	}

	f.mutationEngine = &Mutation{}
	f.mutationEngine.Init()
}

func (f *Fuzzer) waitForBreakpoint(addr uint64) {
	var wstat syscall.WaitStatus
	orig := ptrace.Read(f.targetPid, uintptr(addr), 1)
	ptrace.Write(f.targetPid, uintptr(addr), []byte{0xCC})
	syscall.PtraceCont(f.targetPid, 0)

	// We hit the breakpoint
	syscall.Wait4(f.targetPid, &wstat, 0, nil)
	eip := ptrace.GetEIP(f.targetPid) - 1
	if wstat.StopSignal() != 5 {
		log.Fatal("Unable to hit _start!")
	} else if eip != addr {
		log.Fatalf("We expected to stop at 0x%x, but we landed @ 0x%x", addr, eip)
	} else {
		log.Printf("We landed at 0x%x", addr)
	}
	ptrace.Write(f.targetPid, uintptr(addr), []byte{orig[0]})
	ptrace.SetEIP(f.targetPid, addr)
}

// Fuzz Start fuzzing task
func (f *Fuzzer) Fuzz() {
	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	syscall.Wait4(f.targetPid, &wstat, 0, nil)
	log.Printf("Trapped at beginning of traced process @ 0x%x", ptrace.GetEIP(f.targetPid))

	//Apparently with ptrace we land before the loader finishes its job (_start@ld-linux )
	//This causes the memory map to change till the real binary entrypoint is hit (_start@target symbol)
	//To correctly read the memory segments we therefore need to postpone initial loading until the target entrypoint!
	entrypoint := f.snapshot.GetEntrypoint()
	log.Printf("Breaking on main binary entrypoint _start 0x%x", entrypoint)
	f.waitForBreakpoint(entrypoint)
	f.snapshot.LoadMemoryMap()
	f.loadInitialState()

	log.Printf("Waiting to reach startf() @ 0x%x breakpoint..", f.start)
	f.waitForBreakpoint(f.start)
	// set all breakpoints
	f.setDynamicBreakpoints()
	// Snapshot!
	f.snapshot.TakeSnapshot()
	// locate payload
	f.payloadPtr = f.snapshot.Locate([]byte(f.initialPayload))
	if f.payloadPtr <= 0 {
		log.Fatalf("Unable to locate payload '%s' in RW sections!", f.initialPayload)
	} else {
		log.Printf("Initial payload '%s' located at 0x%x", f.initialPayload, f.payloadPtr)
	}

	f.iterationCount = 0
	f.startTime = time.Now()
	currentPayload := f.mutateInput()
	log.Printf("Entering main fuzzing loop...")
	for {
		if f.iterationCount%30000 == 0 {
			f.printStats()
		}
		syscall.PtraceCont(f.targetPid, 0)
		syscall.Wait4(f.targetPid, &wstat, 0, nil)

		// Breakpoint hit!
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(f.targetPid) - 1
			// Is exit breakpoint? Rewind!
			if uintptr(eip) == uintptr(f.end) {
				//log.Printf("Exit @ 0x%x BP hit, restoring snapshot!", eip)
				f.snapshot.RestoreSnapshot()
				currentPayload = f.mutateInput()
				f.iterationCount++
			} else {
				//log.Printf("BP, EIP 0x%x", eip)
				f.restoreDynamicBreakpoint(eip)
				f.breakpoints[eip] = 0
				f.mutationEngine.storeCorpus(currentPayload)
			}
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
	}
	runtime.UnlockOSThread()
}
