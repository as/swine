package main

import (
	"bytes"
	"fmt"
	jit "github.com/nelhage/gojit"
	asm "rsc.io/x86/x86asm"
)

type Emu struct {
	Base     uint64
	Ram      []byte
	Sections []Section
	Dir      string
	Bits     int
}

type Section struct {
	Name       string
	Addr, Size uint64
	Data       []byte
}

func (e *Emu) findsection(addr uint64) *Section {
	if e == nil {
		return nil
	}
	for _, v := range e.Sections {
		if v.Has(addr) {
			return &v
		}
	}
	return nil
}

func (e *Emu) String() (s string) {
	s = fmt.Sprintln("base", e.Base)
	s += fmt.Sprintln("Dir", e.Dir)
	for _, v := range e.Sections {
		s += fmt.Sprint(v)
	}
	return s
}
func (e *Emu) Symbol(addr uint64) (string, uint64) {
	if e == nil {
		return "", 0
	}
	var end = []byte{0x0, 0x0}
	sect := e.findsection(addr)
	var sp uint64
	if sect == nil {
		if sect = e.findsection(addr - e.Base); sect == nil {
			return "", 0
		}
		sp = addr - sect.Addr - e.Base
	} else {
		sp = addr - sect.Addr
	}
	printerr(e)
	printerr("addr (%d) = ", addr)
	printerr(sect)
	printerr(fmt.Sprintf("sp (%d) = addr (%d) - virt (%d)", sp, addr, sect.Addr))
	printerr(fmt.Sprintf("sect.Data[%d:] %d", sp, len(sect.Data)))
	//	printerr(fmt.Sprintf("data %#x",sect.Data))
	ep := bytes.Index(sect.Data[sp:], end)
	if ep < 0 {
		return "", 0
	}
	printerr(fmt.Sprintf("sect.Data[%d:][:%d]", sp, ep))

	name := string(sect.Data[sp:][:ep])
	return name, sect.Addr
}

func (s Section) String() string {
	return fmt.Sprintf("section=%s addr=%d size=%d\n", s.Name, s.Addr, s.Size)
}
func (s Section) Has(addr uint64) bool {
	if s.Addr > addr {
		return false
	}
	if s.Addr+s.Size < addr {
		return false
	}
	return true
}

func Boot(dir string) (e *Emu, err error) {
	defer func() {
		if r := recover(); r != nil {
			printerr("Boot: recover:", r)
		}
	}()
	checkerr := func() {
		if err != nil {
			panic(err)
		}
	}
	// not always 32 bit
	base, err := read64(dir + "/opthdr32/addr/baseimage")
	if err != nil{
		base, err = read64(dir + "/opthdr64/addr/baseimage")
	}
	checkerr()
	emu = new(Emu)
	emu.Base = base

	var (
		addr, size uint64
		data       []byte
	)
	for _, v := range sections(dir) {
		subdir := dir + "/section/" + v
		addr, err = read64(subdir + "/offset")
		checkerr()
		size, err = read64(subdir + "/size")
		checkerr()
		data, err = read(subdir + "/data/raw")
		checkerr()
		sect := Section{v, addr, size, data}
		emu.Sections = append(emu.Sections, sect)
		emu.Ram = append(emu.Ram, sect.Data...)
		printerr("store memory[", addr+base, ":], data")
	}

	return emu, nil
}

// Execute emulates execution of the given instructions
func Execute(inst []byte) {
	//TODO
	bin, err := asm.Decode(inst, 64)
	if err != nil {
		return
	}
	printerr("execute:", inst, bin)
	jit.Build(inst)
}
