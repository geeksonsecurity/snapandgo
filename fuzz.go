package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

func debug() {
	log.Printf("Debugging child!")
}

func explainWaitStatus(ws syscall.WaitStatus) string {
	switch {
	case ws.Exited():
		es := ws.ExitStatus()
		return fmt.Sprintf("Exit %d", es)
	case ws.Signaled():
		msg := fmt.Sprintf("signaled %v", ws.Signal())
		if ws.CoreDump() {
			msg += " (core dumped)"
		}
		return fmt.Sprintf("Signaled %s", msg)
	case ws.Stopped():
		msg := fmt.Sprintf("stopped %v", ws.StopSignal())
		trap := ws.TrapCause()
		if trap != -1 {
			msg += fmt.Sprintf(" (trapped %v)", trap)
		}
		return fmt.Sprintf("Stopped %s\n", msg)
	case ws.Continued():
		return fmt.Sprint("continued")
	default:
		return fmt.Sprintf("unknown status %d", ws)
	}
}

func main() {
	procAttr := syscall.ProcAttr{
		Dir:   "",
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Env:   []string{},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	}

	targetPid, err := syscall.ForkExec("./demo/target", []string{}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d", targetPid)

	var wstat syscall.WaitStatus
	//var regs syscall.PtraceRegs

	for {
		fmt.Println("Waiting..")
		_, err := syscall.Wait4(targetPid, &wstat, 0, nil)
		fmt.Printf("Status: %s (%d)\n", explainWaitStatus(wstat), wstat)

		if err != nil {
			fmt.Println(err)
			break
		}
		syscall.PtraceCont(targetPid, 0)
		//syscall.PtraceGetRegs(targetPid, &regs)
		//fmt.Printf("syscall: %d\n", regs.Orig_rax)

		//syscall.PtraceSyscall(targetPid, 0)
	}
}
