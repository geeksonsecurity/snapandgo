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

const base = 0x555555555000
const mainAddr = base + 0x304

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
		Pid: targetPid,
	}

	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	_, err = syscall.Wait4(targetPid, &wstat, 0, nil)
	fmt.Printf("Status: %s (%d)\n", utils.ExplainWaitStatus(wstat), wstat)

	originalMainByte := ptrace.Read(targetPid, mainAddr, 1)

	// Replace it with software breakpoint 0xCC
	ptrace.Write(targetPid, mainAddr, []byte{0xCC})
	syscall.PtraceCont(targetPid, 0)

	fmt.Println("Waiting to reach main..")
	syscall.Wait4(targetPid, &wstat, 0, nil)
	if wstat.StopSignal() == 5 {
		// main
		snapshot.TakeSnapshot()
		// revert main breakpoint
		ptrace.Write(targetPid, mainAddr, originalMainByte)
		// rewind EIP
		snapshot.RewindEIP()
		// locate payload
		ptr := snapshot.Locate([]byte(initialPayload))
		if ptr <= 0 {
			log.Fatalf("Unable to locate payload '%s' in RW sections!", initialPayload)
		} else {
			log.Printf("Initial payload '%s' located at 0x%x", initialPayload, ptr)
		}
		// continue
		syscall.PtraceCont(targetPid, 0)
	} else {
		log.Fatalf("We expected main to be found: %s", utils.ExplainWaitStatus(wstat))
	}

	log.Printf("Entering main fuzzing loop...")
	for {
		syscall.Wait4(targetPid, &wstat, 0, nil)

		// exit bp hit
		if wstat.StopSignal() == 5 {
			log.Printf("BP, EIP 0x%x", ptrace.GetEIP(targetPid))
			snapshot.RestoreSnapshot()
		} else {
			log.Printf("%s", utils.ExplainWaitStatus(wstat))
			break
		}
		syscall.PtraceCont(targetPid, 0)

		//log.Printf("Read %s", hex.Dump(read(targetPid, mainAddr, 1)))
		//fmt.Printf("syscall: %d\n", regs.Orig_rax)
		//syscall.PtraceSyscall(targetPid, 0)
	}
}
