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
	"math/rand"
	"bytes"
)

//dumb mutation stuff
type Mutation struct {
        corpus map[uint64][]byte
	testcase []byte
}

func (p *Mutation) genBytes(n uint64) ([]byte, error) {
	src := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(src)

        buf := make([]byte, n)
        _, err := rnd.Read(buf)

        if err != nil {
                return nil, err
        }
        return buf, nil
}

func (p *Mutation) storeCorpus(c []byte) {
	for _, x := range p.corpus {
		if bytes.Compare(x, c) == 0 {
			return
		}
	}
	p.corpus[uint64(len(p.corpus) + 1)] = c
}

func (p *Mutation) pickCorpus() ([]byte) {
	return p.corpus[uint64(rand.Int63n(int64(len(p.corpus))))]
}

func (p *Mutation) Init() {
	p.corpus   = make(map[uint64][]byte)
        buf, err := p.genBytes(1)
        if err != nil {
                p.corpus[0] = []byte{0x41}
        } else {
                p.corpus[0] = buf
        }
        return
}

func (p *Mutation) Mutate() ([]byte) {
        // get a corpus and mutate it
        tc := p.pickCorpus()
	if len(tc) == 0 {
		tc, _ = p.genBytes(1)
	}
        // mutate
    	t := rand.Intn(4)
    	switch t {
    		case 0: // append 1 random byte
			//fmt.Println("Mutation type: append")
			rb := rand.Intn(256)
			tc = append(tc, byte(rb))
     		case 1: // flip bytes
			//fmt.Println("Mutation type: flip")
			tc = bytes.Replace(tc, []byte{tc[rand.Intn(len(tc))]}, []byte{tc[rand.Intn(len(tc))]}, 1)
    		case 2: // remove 1 byte
			//fmt.Println("Mutation type: remove")
			tc = bytes.TrimPrefix(tc, []byte{tc[rand.Intn(len(tc))]})
    		case 3: // random
			tc, _ = p.genBytes(uint64(rand.Intn(16)))
    	}

	p.testcase = tc
        return tc
}

// Fuzzer handle the fuzzing stuff
type Fuzzer struct {
	Base uint64

	snapshot       *snapshot.Manager
	mainSection    *snapshot.MemorySection
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

func (p *Fuzzer) resolveStartEndAddress(startFuncName string, endFuncName string) (uint64, uint64) {
	startRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep %s | awk '{print $1}'", p.target, startFuncName)).Output()
	endRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep %s | awk '{print $1}'", p.target, endFuncName)).Output()
	start, _ := strconv.ParseUint(strings.TrimSpace(string(startRaw)), 16, 64)
	end, _ := strconv.ParseUint(strings.TrimSpace(string(endRaw)), 16, 64)
	return start, end
}

func (p *Fuzzer) getEntrypoint() uint64 {
	startRaw, _ := exec.Command("bash", "-c", fmt.Sprintf("nm %s | grep -sw _start | awk '{print $1}'", p.target)).Output()
	start, _ := strconv.ParseUint(strings.TrimSpace(string(startRaw)), 16, 64)
	return start
}

func (p *Fuzzer) loadInitialState() {

	p.breakpoints = make(map[uint64]byte)
	p.mainSection = nil

	p.snapshot.LoadMemoryMap()

	for _, s := range p.snapshot.GetXSections() {
		//log.Printf(">> %s", s.Module)
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
		//log.Printf("Set bp 0x%x", addr)
	}
}

func (p *Fuzzer) restoreDynamicBreakpoint(addr uint64) {
	res := ptrace.Write(p.targetPid, uintptr(addr), []byte{p.breakpoints[addr]})
	if res != 1 {
		log.Fatalf("Failed to revert bp @ 0x%x with value 0x%x", addr, p.breakpoints[addr])
	}
	ptrace.SetEIP(p.targetPid, addr)
	//log.Printf("Reverting bp @ 0x%x with value 0x%x", addr, p.breakpoints[addr])
}

func (p *Fuzzer) mutateInput() {
	// override input param
	newPayload := p.mutationEngine.Mutate()
/*
	for _, n := range(newPayload) {
        	fmt.Printf("% 08b", n)
    	}
	fmt.Println()
	fmt.Println(newPayload)
*/
	//ptrace.Write(p.targetPid, uintptr(p.payloadPtr), []byte{0x41, 0x42, 0x43, 0x44, 0x0})
	// add null terminator
	ptrace.Write(p.targetPid, uintptr(p.payloadPtr), append(newPayload, 0x0))
}

func (p *Fuzzer) printStats() {
	elapsed := time.Since(p.startTime)
	found := 0
	for _, v := range p.breakpoints {
		if v == 0 {
			found++
		}
	}

	log.Printf("[%10.4f] cases %10d | fcps %8.4f | cov %2.1f%% (hit: %3d, tot: %3d) | corpus: %d", elapsed.Seconds(), p.iterationCount, float64(p.iterationCount)/elapsed.Seconds(), float64(found)/float64(len(p.breakpoints))*100.0, found, len(p.breakpoints), len(p.mutationEngine.corpus))
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

	p.mutationEngine = &Mutation{}
	p.mutationEngine.Init()
}

// Fuzz Start fuzzing task
func (p *Fuzzer) Fuzz() {
	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	var eip uint64
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	log.Printf("Trapped at beginning of traced process @ 0x%x", ptrace.GetEIP(p.targetPid))

	//TODO: Cleanup the next section
	//Apparently with ptrace we land before the loader finishes its job (_start@ld-linux )
	//This causes the memory map to change till the real binary entrypoint is hit (_start@target symbol)
	//To correctly read the memory segments we therefore need to postpone initial loading until the target entrypoint!
	// The offsets are hardcoded since those were calculated in loadInitialState, need refactoring!
	entrypoint := p.getEntrypoint() - 0x1000 + 0x0000555555555000
	orig := ptrace.Read(p.targetPid, uintptr(entrypoint), 1)
	log.Printf("Breaking on binary entrypoint _start @ 0x%x", entrypoint)
	ptrace.Write(p.targetPid, uintptr(entrypoint), []byte{0xCC})
	syscall.PtraceCont(p.targetPid, 0)

	// We hit the breakpoint
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	eip = ptrace.GetEIP(p.targetPid) - 1
	if wstat.StopSignal() != 5 {
		log.Fatal("Unable to hit _start!")
	} else if eip != entrypoint {
		log.Fatalf("We couldnt stop at _start, but we landed @ 0x%x", eip)
	} else {
		log.Printf("We landed at _start")
	}

	ptrace.Write(p.targetPid, uintptr(entrypoint), []byte{orig[0]})
	ptrace.SetEIP(p.targetPid, entrypoint)

	p.loadInitialState()
	//TODO-END

	// Replace main/exit with software breakpoint 0xCC
	ptrace.Write(p.targetPid, uintptr(p.start), []byte{0xCC})
	syscall.PtraceCont(p.targetPid, 0)

	log.Printf("Waiting to reach startf() @ 0x%x breakpoint..", p.start)
	syscall.Wait4(p.targetPid, &wstat, 0, nil)
	if wstat.StopSignal() == 5 {

		eip = ptrace.GetEIP(p.targetPid) - 1
		if eip != p.start {
			log.Fatalf("We didnt stop in main but at 0x%x", eip)
		}

		// revert main breakpoint
		p.restoreDynamicBreakpoint(p.start)
		// set all breakpoints
		p.setDynamicBreakpoints()
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
		if p.iterationCount%30000 == 0 {
			p.printStats()
		}
		syscall.PtraceCont(p.targetPid, 0)
		syscall.Wait4(p.targetPid, &wstat, 0, nil)

		// Breakpoint hit!
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(p.targetPid) - 1
			// Is exit breakpoint? Rewind!
			if uintptr(eip) == uintptr(p.end) {
				//log.Printf("Exit @ 0x%x BP hit, restoring snapshot!", eip)
				p.snapshot.RestoreSnapshot()
				p.mutateInput()
				p.iterationCount++
			} else {
				//log.Printf("BP, EIP 0x%x", eip)
				p.restoreDynamicBreakpoint(eip)
				p.breakpoints[eip] = 0
				p.mutationEngine.storeCorpus(p.mutationEngine.testcase)
			}
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
	}
	runtime.UnlockOSThread()
}
