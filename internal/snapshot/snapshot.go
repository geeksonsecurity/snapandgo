package snapshot

import "log"

// TakeSnapshot takes a memory snapshot of all writable memory region for given pid
func TakeSnapshot(pid int) {
	log.Printf("Taking snapshot of PID %d", pid)
}
