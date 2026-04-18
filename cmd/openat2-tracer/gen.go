package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" openat2Tracer ../../bpf/openat2-tracer.bpf.c
