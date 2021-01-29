package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"snapandgo/internal/ptrace"
	"snapandgo/internal/snapshot"
	"snapandgo/internal/utils"
)

// TODO: Autocompute those values
const base = 0x555555555000
const mainAddr = base + 0x304
const exitAddr = base + 0x36a

//ADDR_NO_RANDOMIZE disable randomization of VA space
const ADDR_NO_RANDOMIZE = 0x0040000

func main() {
	var err error

	procAttr := syscall.ProcAttr{
		Dir:   "",
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Env:   []string{},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	}

	r1, _, errno := syscall.Syscall(syscall.SYS_PERSONALITY, ADDR_NO_RANDOMIZE, uintptr(0), uintptr(0))

	if errno != 0 {
		log.Printf("Failed to disable ASLR: %s", errno.Error())
	}
	log.Printf("Result %d", r1)

	initialPayload := "deadbeef"
	targetPid, err := syscall.ForkExec("./tools/demo/target", []string{"target", initialPayload}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d", targetPid)
	snapshot := snapshot.Manager{
		Pid:  targetPid,
		Base: base,
	}

	snapshot.LoadBreakpoints("./tools/demo/breakpoints.txt")

	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	_, err = syscall.Wait4(targetPid, &wstat, 0, nil)
	fmt.Printf("Status: %s (%d)\n", utils.ExplainWaitStatus(wstat), wstat)

	originalMainByte := ptrace.Read(targetPid, mainAddr, 1)

	// Replace main/exit with software breakpoint 0xCC
	ptrace.Write(targetPid, mainAddr, []byte{0xCC})
	ptrace.Write(targetPid, exitAddr, []byte{0xCC})
	syscall.PtraceCont(targetPid, 0)

	fmt.Println("Waiting to reach main() breakpoint..")
	syscall.Wait4(targetPid, &wstat, 0, nil)
	var payloadPtr uint64
	if wstat.StopSignal() == 5 {
		// revert main breakpoint
		ptrace.Write(targetPid, mainAddr, originalMainByte)
		// rewind EIP
		snapshot.RewindEIP()
		// Snapshot!
		snapshot.TakeSnapshot()
		// locate payload
		payloadPtr = snapshot.Locate([]byte(initialPayload))
		if payloadPtr <= 0 {
			log.Fatalf("Unable to locate payload '%s' in RW sections!", initialPayload)
		} else {
			log.Printf("Initial payload '%s' located at 0x%x", initialPayload, payloadPtr)
		}
		// continue
		syscall.PtraceCont(targetPid, 0)
	} else {
		log.Fatalf("We expected main to be found: %s", utils.ExplainWaitStatus(wstat))
	}

	loopCount := 0
	log.Printf("Entering main fuzzing loop...")
	for {
		syscall.Wait4(targetPid, &wstat, 0, nil)
		log.Printf("[+] %d loop - EIP 0x%x", loopCount, ptrace.GetEIP(targetPid))
		// exit bp hit
		if wstat.StopSignal() == 5 {
			eip := ptrace.GetEIP(targetPid)
			log.Printf("BP, EIP 0x%x", eip)
			if eip-1 == exitAddr {
				log.Printf("Exit BP hit, restoring snapshot!")
				snapshot.RestoreSnapshot()
				// override input param
				ptrace.Write(targetPid, uintptr(payloadPtr), []byte{0x41, 0x42, 0x43, 0x44, 0x0})
				loopCount++
			} else {
				log.Printf("Unknown breakpoint!")
				break
			}
		} else {
			log.Printf("INTERRUPTED! Reason: %s", utils.ExplainWaitStatus(wstat))
			break
		}
		syscall.PtraceCont(targetPid, 0)
	}
}
