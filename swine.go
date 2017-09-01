package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	asm "github.com/as/x86/x86asm"
	"strings"
)
import (
	"github.com/as/mute"
)

const Prefix = "swine: "

var args struct {
	h, q bool
	r    bool
	k    string
}

var f *flag.FlagSet
var emu *Emu

func init() {
	f = flag.NewFlagSet("main", flag.ContinueOnError)
	f.BoolVar(&args.h, "h", false, "")
	f.BoolVar(&args.q, "?", false, "")
	f.StringVar(&args.k, "k", "", "")
	f.BoolVar(&args.r, "r", false, "")
	err := mute.Parse(f, os.Args[1:])
	if err != nil {
		printerr(err)
		os.Exit(1)
	}
}

func main() {
	a := f.Args()
	if len(a) < 2 {
		printerr("usage: swine exe dstdir")
		os.Exit(1)
	}
	exe := a[0]
	dir := a[1]

	if !args.r {
		exe2fs(dir, exe)
	}
	exe2fs(dir, exe)
	fs2exe(exe, dir)

	os.Exit(0)
}

func disasm(sec string, data []byte, wordsize int, baseaddr int) []byte {
	buf := new(bytes.Buffer)
	for i := uint64(baseaddr); len(data) > 0; {
		inst, err := asm.Decode(data, wordsize)
		if err != nil {
			//printerr(err)
		}
		fmt.Fprintf(buf, "%08x %s\n", i, asm.Plan9Syntax(inst, i, symname))
		i += uint64(inst.Len)
		if sec == ".text" {
			//Execute(data[:inst.Len])
		}
		data = data[inst.Len:]
	}
	return buf.Bytes()
}

func sections(file string) (section []string) {
	data, err := ioutil.ReadFile(clean(file + "/section/ORDER"))
	if err != nil {
		return nil
	}
	for _, v := range strings.Split(string(data), " ") {
		if v != "" {
			section = append(section, v)
		}
	}
	return section
}

func symname(addr uint64) (s string, n uint64) {
	var err error
	if emu == nil {
		emu, err = Boot(f.Args()[1])
		printerr(err)
	}
	return emu.Symbol(addr)
}
