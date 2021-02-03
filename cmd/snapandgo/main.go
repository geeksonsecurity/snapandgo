package main

import (
	"log"
	"syscall"

	"snapandgo/internal/fuzzing"
)

//ADDR_NO_RANDOMIZE disable randomization of VA space
const ADDR_NO_RANDOMIZE = 0x0040000

func main() {
	_, _, errno := syscall.Syscall(syscall.SYS_PERSONALITY, ADDR_NO_RANDOMIZE, uintptr(0), uintptr(0))

	if errno != 0 {
		log.Printf("Failed to disable ASLR: %s", errno.Error())
	}

	fuzzer := fuzzing.Fuzzer{
		Base: 0x555555555000,
	}

	fuzzer.Init("./tools/demo/target", "./tools/demo/breakpoints.txt")
	fuzzer.Fuzz()
}
