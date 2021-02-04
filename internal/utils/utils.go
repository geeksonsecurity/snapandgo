package utils

import (
	"fmt"
	"log"
	"syscall"
)

// ExplainWaitStatus humanize the waitstatus
func ExplainWaitStatus(ws syscall.WaitStatus) string {
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

// DisableASLR disable randomization of VA space via SYS_PERSONALITY
func DisableASLR() {
	//ADDR_NO_RANDOMIZE disable randomization of VA space
	_, _, errno := syscall.Syscall(syscall.SYS_PERSONALITY, 0x0040000, uintptr(0), uintptr(0))

	if errno != 0 {
		log.Fatalf("Failed to disable ASLR: %s", errno.Error())
	}
}
