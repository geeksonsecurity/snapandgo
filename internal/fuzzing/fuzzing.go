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
)

// Fuzzer handle the fuzzing stuff
type Fuzzer struct {
	Target           string
	BreakpointSource string
	snapshot         *snapshot.Manager
	mutationEngine   *Mutation
	stats            *Stats

	start          uint64
	end            uint64
	targetPid      int
	initialPayload string
	breakpoints    map[uint64]byte
	payloadPtr     uint64
	currentInput   []byte
	crashes        []uint64
}

func (f *Fuzzer) loadBreakpointsFromPath(bpFile string) {
	f.breakpoints = make(map[uint64]byte)
	inFile, err := os.Open(bpFile)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)

	for scanner.Scan() {
		val, _ := strconv.ParseUint(strings.Replace(scanner.Text(), "0x", "", -1), 16, 64)
		addr := f.snapshot.ConvertRelativeAddressWoOffset(val)
		f.breakpoints[addr] = ptrace.Read(f.targetPid, uintptr(addr), 1)[0]
		//log.Printf("Loaded breakpoint @ 0x%x", addr)
	}

	log.Printf("Loaded %d breakpoints", len(f.breakpoints))
}

func (f *Fuzzer) loadBreakpointsFromObjdump() {
	outputRaw, err := exec.Command("objdump", "-d", "-j", ".text", f.Target).Output()

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
		addr = f.snapshot.ConvertRelativeAddress(addr)
		f.breakpoints[addr] = ptrace.Read(f.targetPid, uintptr(addr), 1)[0]
		//log.Printf("Loaded breakpoint @ 0x%x", addr)
	}
	log.Printf("Loaded %d breakpoints!", len(f.breakpoints))
}

func (f *Fuzzer) loadInitialState() {

	f.stats = &Stats{
		IterationCount: 0,
	}
	f.breakpoints = make(map[uint64]byte)
	f.start = f.snapshot.ResolveAddress("startf")
	f.end = f.snapshot.ResolveAddress("endf")
	log.Printf("Located start @ 0x%x and end @ 0x%x", f.start, f.end)

	if f.BreakpointSource != "" {
		log.Printf("Loading breakpoints from file %s", f.BreakpointSource)
		f.loadBreakpointsFromPath(f.BreakpointSource)
	} else {
		log.Printf("Computing breakpoints with objdump")
		f.loadBreakpointsFromObjdump()
	}

	f.stats.TotalBreakpoints = len(f.breakpoints)
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
func (f *Fuzzer) mutateInput() {
	// override input param
	f.currentInput = f.mutationEngine.Mutate()
	// add null terminator
	ptrace.Write(f.targetPid, uintptr(f.payloadPtr), append(f.currentInput, 0x0))
}

// Init the Fuzzer instance
func (f *Fuzzer) init() {
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
	f.targetPid, err = syscall.ForkExec(f.Target, []string{"Target", f.initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started Target process with PID %d, Parent is %d", f.targetPid, os.Getpid())
	f.snapshot = &snapshot.Manager{
		Pid:    f.targetPid,
		Target: f.Target,
	}

	f.mutationEngine = &Mutation{}
	f.mutationEngine.Init()
}

func (f *Fuzzer) countFoundBreakpoints() int {
	found := 0
	for _, v := range f.breakpoints {
		if v == 0 {
			found++
		}
	}
	return found
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

func (f *Fuzzer) isNewCrash(eip uint64) bool {
	for _, v := range f.crashes {
		if v == eip {
			return false
		}
	}
	return true
}

func (f *Fuzzer) restore() {
	f.snapshot.RestoreSnapshot()
	f.mutateInput()
	f.stats.IterationCount++
}

// Fuzz Start fuzzing task
func (f *Fuzzer) Fuzz() {
	f.init()
	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	syscall.Wait4(f.targetPid, &wstat, 0, nil)
	log.Printf("Trapped at beginning of traced process @ 0x%x", ptrace.GetEIP(f.targetPid))

	//Apparently with ptrace we land before the loader finishes its job (_start@ld-linux )
	//This causes the memory map to change till the real binary entrypoint is hit (_start@Target symbol)
	//To correctly read the memory segments we therefore need to force a reload when we are at the main Target entrypoint!
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

	f.mutateInput()
	go f.stats.StatsMonitor()

	log.Printf("Entering main fuzzing loop...")
	for {
		syscall.PtraceCont(f.targetPid, 0)
		syscall.Wait4(f.targetPid, &wstat, 0, nil)

		// Breakpoint hit!
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(f.targetPid) - 1
			// Is exit breakpoint? Rewind!
			if uintptr(eip) == uintptr(f.end) {
				//log.Printf("Exit @ 0x%x BP hit, restoring snapshot!", eip)
				f.restore()
			} else {
				//log.Printf("BP, EIP 0x%x", eip)
				f.restoreDynamicBreakpoint(eip)
				f.breakpoints[eip] = 0
				added := f.mutationEngine.storeCorpus(f.currentInput)
				if added {
					f.stats.CorpusLength = len(f.mutationEngine.corpus)
					f.stats.FoundBreakpoints = f.countFoundBreakpoints()
				}
			}
		} else if wstat.StopSignal() == 11 {
			eip := ptrace.GetEIP(f.targetPid)
			if f.isNewCrash(eip) {
				f.crashes = append(f.crashes, eip)
				f.stats.Crashes++
			}
			f.restore()
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
	}
	runtime.UnlockOSThread()
}
