# Snapandgo

Snapandgo is a {golang, ptrace, snapshot}-based fuzzer inspired by the great work of [h0mbre](https://github.com/h0mbre/Fuzzing/tree/master/Caveman4) and [defparam](https://github.com/defparam/Coldsnap).  
Its written in Golang and does not use any external dependency.

> This is still in development, so don't expect anything to work rn

## Build

To build the demo program:
```
cd tools/demo
make
```

To run the fuzzer just:
```
$ go run cmd/snapandgo/main.go

2021/01/25 21:23:55 Result 0
2021/01/25 21:23:55 Started target process with PID 29591
Status: Stopped stopped trace/breakpoint trap (trapped 0)
 (1407)
Waiting to reach main..
Processing deadbeef
2021/01/25 21:23:55 Taking snapshot of PID 29591
2021/01/25 21:23:55 Reading 0x555555558000-0x555555559000 [4096 bytes] - rw-p - /home/user/Documents/snapandgo/tools/demo/target
2021/01/25 21:23:55 Reading 0x555555559000-0x55555557a000 [135168 bytes] - rw-p - [heap]
2021/01/25 21:23:55 Reading 0x7ffff7fae000-0x7ffff7fb0000 [8192 bytes] - rw-p - /usr/lib/x86_64-linux-gnu/libc-2.28.so
2021/01/25 21:23:55 Reading 0x7ffff7fb0000-0x7ffff7fb6000 [24576 bytes] - rw-p - 
2021/01/25 21:23:55 Reading 0x7ffff7ffd000-0x7ffff7ffe000 [4096 bytes] - rw-p - /usr/lib/x86_64-linux-gnu/ld-2.28.so
2021/01/25 21:23:55 Reading 0x7ffff7ffe000-0x7ffff7fff000 [4096 bytes] - rw-p - 
2021/01/25 21:23:55 Reading 0x7ffffffde000-0x7ffffffff000 [135168 bytes] - rw-p - [stack]
2021/01/25 21:23:55 Registers saved! EIP: 0x555555555304
2021/01/25 21:23:55 Searching in 0x555555558000-0x555555559000 [4096 bytes]
2021/01/25 21:23:55 Searching in 0x555555559000-0x55555557a000 [135168 bytes]
2021/01/25 21:23:55 Initial payload 'deadbeef' located at 0x55555555926b
2021/01/25 21:23:55 Entering main fuzzing loop...
2021/01/25 21:23:55 Exit 0
```

