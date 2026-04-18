package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	AT_FDCWD  = -100
	O_CREAT   = 0100
	O_TMPFILE = 020200000
)

// RESOLVE_* flags for openat2's resolve field
const (
	RESOLVE_NO_XDEV       = 0x01
	RESOLVE_NO_MAGICLINKS = 0x02
	RESOLVE_NO_SYMLINKS   = 0x04
	RESOLVE_BENEATH       = 0x08
	RESOLVE_IN_ROOT       = 0x10
	RESOLVE_CACHED        = 0x20
)

type Openat2Event struct {
	Pid          uint32
	Comm         [16]byte
	Dirfd        int32
	Filename     [256]byte
	Flags        uint64
	Mode         uint64
	Resolve      uint64
	HowAvail     bool
	DirPath      [256]byte
	DirPathAvail bool
	Pad0         [6]byte // trailing padding to align struct size to 8 bytes (rather than 4 due to u64 members)
}

var resolveFlags = []struct {
	flag uint64
	name string
}{
	{RESOLVE_NO_XDEV, "RESOLVE_NO_XDEV"},
	{RESOLVE_NO_MAGICLINKS, "RESOLVE_NO_MAGICLINKS"},
	{RESOLVE_NO_SYMLINKS, "RESOLVE_NO_SYMLINKS"},
	{RESOLVE_BENEATH, "RESOLVE_BENEATH"},
	{RESOLVE_IN_ROOT, "RESOLVE_IN_ROOT"},
	{RESOLVE_CACHED, "RESOLVE_CACHED"},
}

func formatResolve(resolve uint64) string {
	if resolve == 0 {
		return "0"
	}
	var parts []string
	for _, rf := range resolveFlags {
		if resolve&rf.flag != 0 {
			parts = append(parts, rf.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", resolve)
	}
	return strings.Join(parts, "|")
}

func main() {
	// allow eBPF to lock memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load compiled eBPF objects
	objs := openat2TracerObjects{}
	if err := loadOpenat2TracerObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1 << 26, // 64MB log buffer to capture full verifier output
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
		} else {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	defer objs.Close()

	// attach to sys_enter_openat2
	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_openat2",
		objs.HandleOpenat2,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	// open ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	fmt.Println("Listening for openat2 events... (Ctrl+C to stop)")

	// handle Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop
		fmt.Println("\nStopping...")
		rd.Close()
	}()

	// read events
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var e Openat2Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("parse error:", err)
			continue
		}

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		fmt.Printf("\nPID: %d | COMM: %s\n", e.Pid, comm)

		if e.Dirfd == AT_FDCWD {
			fmt.Printf("DIRFD: AT_FDCWD")
		} else {
			fmt.Printf("DIRFD: %d", e.Dirfd)
		}
		if e.DirPathAvail {
			dirPath := string(bytes.TrimRight(e.DirPath[:], "\x00"))
			fmt.Printf(" (%s)\n", dirPath)
		} else {
			fmt.Printf("\n")
		}

		fmt.Printf("OPENAT2: %s\n", filename)

		if e.HowAvail {
			fmt.Printf("FLAGS: %d\n", e.Flags)

			if e.Flags&(O_CREAT|O_TMPFILE) != 0 {
				fmt.Printf("MODE: %d\n", e.Mode)
			}

			if e.Resolve != 0 {
				fmt.Printf("RESOLVE: %s\n", formatResolve(e.Resolve))
			}
		} else {
			fmt.Printf("FLAGS: (unavailable)\n")
		}
	}
}
