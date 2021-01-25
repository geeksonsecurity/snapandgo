package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"syscall"

	"snapandgo/internal/ptrace"
	"snapandgo/internal/snapshot"
	"snapandgo/internal/utils"
)

const mainAddr = 0x555555555303

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

	targetPid, err := syscall.ForkExec("./tools/demo/target", []string{}, &procAttr)
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

	// set breakpoint at main and let continue
	// First byte in main
	log.Printf("Read %s", hex.Dump(ptrace.Read(targetPid, mainAddr, 1)))

	// Replace it with software breakpoint 0xCC
	ptrace.Write(targetPid, mainAddr, []byte{0xCC})
	syscall.PtraceCont(targetPid, 0)

	for {
		fmt.Println("Waiting..")
		_, err := syscall.Wait4(targetPid, &wstat, 0, nil)
		fmt.Printf("Status: %s (%d)\n", utils.ExplainWaitStatus(wstat), wstat)

		if err != nil {
			fmt.Println(err)
			break
		}

		if wstat.StopSignal() == 5 {
			// main
			snapshot.TakeSnapshot()
			break
		}

		//log.Printf("Read %s", hex.Dump(read(targetPid, mainAddr, 1)))
		syscall.PtraceCont(targetPid, 0)
		//fmt.Printf("syscall: %d\n", regs.Orig_rax)
		//syscall.PtraceSyscall(targetPid, 0)
	}
	snapshot.RestoreSnapshot()
}
