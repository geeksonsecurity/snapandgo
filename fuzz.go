package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"syscall"
)

const mainAddr = 0x555555555303

//ADDR_NO_RANDOMIZE disable randomization of VA space
const ADDR_NO_RANDOMIZE = 0x0040000

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

func read(pid int, addr uintptr, count int) []byte {
	dword := make([]byte, count)
	count, err := syscall.PtracePeekText(pid, addr, dword)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read %d bytes", count)
	return dword
}

func write(pid int, addr uintptr, bytes []byte) int {
	count, err := syscall.PtracePokeText(pid, addr, bytes)
	if err != nil {
		log.Fatal(err)
	}
	return count
}

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

	targetPid, err := syscall.ForkExec("./demo/target", []string{}, &procAttr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started target process with PID %d", targetPid)

	// waiting stop at entrypoint
	var wstat syscall.WaitStatus
	_, err = syscall.Wait4(targetPid, &wstat, 0, nil)
	fmt.Printf("Status: %s (%d)\n", explainWaitStatus(wstat), wstat)

	// set breakpoint at main and let continue
	// First byte in main
	log.Printf("Read %s", hex.Dump(read(targetPid, mainAddr, 1)))

	// Replace it with software breakpoint 0xCC
	write(targetPid, mainAddr, []byte{0xCC})
	syscall.PtraceCont(targetPid, 0)

	for {
		fmt.Println("Waiting..")
		_, err := syscall.Wait4(targetPid, &wstat, 0, nil)
		fmt.Printf("Status: %s (%d)\n", explainWaitStatus(wstat), wstat)

		if err != nil {
			fmt.Println(err)
			break
		}

		if wstat.StopSignal() == 5 {
			break
		}

		//log.Printf("Read %s", hex.Dump(read(targetPid, mainAddr, 1)))
		syscall.PtraceCont(targetPid, 0)
		//syscall.PtraceGetRegs(targetPid, &regs)
		//fmt.Printf("syscall: %d\n", regs.Orig_rax)
		//syscall.PtraceSyscall(targetPid, 0)
	}
}
