package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

func dos2fs(dir string, exe string) (err error) {
	fd, err := os.Open(clean(exe))
	if err != nil {
		return err
	}
	defer fd.Close()
	dos, real, err := ReadDOS(fd)
	if err != nil {
		return err
	}
	mkdir(dir)
	if err = dos.WriteASCII(dir); err != nil {
		return err
	}
	return writereal(dir+"/dos/real", real)
}

func exe2fs(dir string, exe string) {
	var (
		wordsize   int
		base       int
		codeoffset int
		dataoffset int
	)
	dataoffset = dataoffset
	codeoffset = codeoffset
	wordsize = wordsize
	base = base
	err := dos2fs(dir, exe)
	printerr(err)
	fd, err := pe.Open(clean(exe))
	mustnil(err)
	defer fd.Close()

	ascii := func(a ...interface{}) []byte {
		return []byte(fmt.Sprint(a...))
	}

	// Write the EXE to the filesystem
	pre := clean(dir + "/hdr")
	mkdir(pre)

	hdr := fd.FileHeader
	write(pre+"/machine", ascii(hdr.Machine))
	write(pre+"/nosections", ascii(hdr.NumberOfSections))
	write(pre+"/timestamp", ascii(hdr.TimeDateStamp))
	write(pre+"/symtabptr", ascii(hdr.PointerToSymbolTable))
	write(pre+"/nosymbols", ascii(hdr.NumberOfSymbols))
	write(pre+"/opthdrsize", ascii(hdr.SizeOfOptionalHeader))
	write(pre+"/character", ascii(hdr.Characteristics))

	switch t := fd.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		pre := clean(dir + "/opthdr32")
		mkdir(pre)
		base = int(t.ImageBase)
		codeoffset = int(t.BaseOfCode)
		dataoffset = int(t.BaseOfData)

		write(pre+"/magic", ascii(t.Magic))
		write(pre+"/version/linker/maj", ascii(t.MajorLinkerVersion))
		write(pre+"/version/linker/min", ascii(t.MinorLinkerVersion))
		write(pre+"/version/os/maj", ascii(t.MajorOperatingSystemVersion))
		write(pre+"/version/os/min", ascii(t.MinorOperatingSystemVersion))
		write(pre+"/version/image/maj", ascii(t.MajorImageVersion))
		write(pre+"/version/image/min", ascii(t.MinorImageVersion))
		write(pre+"/version/subsystem/maj", ascii(t.MajorSubsystemVersion))
		write(pre+"/version/subsystem/min", ascii(t.MinorSubsystemVersion))
		write(pre+"/version/win32", ascii(t.Win32VersionValue))
		write(pre+"/size/stackreserve", ascii(t.SizeOfStackReserve))
		write(pre+"/size/stackcommit", ascii(t.SizeOfStackCommit))
		write(pre+"/size/heapreserve", ascii(t.SizeOfHeapReserve))
		write(pre+"/size/heapcommit", ascii(t.SizeOfHeapCommit))
		write(pre+"/size/image", ascii(t.SizeOfImage))
		write(pre+"/size/headers", ascii(t.SizeOfHeaders))
		write(pre+"/size/code", ascii(t.SizeOfCode))
		write(pre+"/size/initdata", ascii(t.SizeOfInitializedData))
		write(pre+"/size/uninitdata", ascii(t.SizeOfUninitializedData))
		write(pre+"/addr/main", ascii(t.AddressOfEntryPoint))
		write(pre+"/addr/basecode", ascii(t.BaseOfCode))
		write(pre+"/addr/basedata", ascii(t.BaseOfData))
		write(pre+"/addr/baseimage", ascii(t.ImageBase))
		write(pre+"/align/section", ascii(t.SectionAlignment))
		write(pre+"/align/file", ascii(t.FileAlignment))
		write(pre+"/crc", ascii(t.CheckSum))
		write(pre+"/subsystem", ascii(t.Subsystem))
		write(pre+"/dllcharacter", ascii(t.DllCharacteristics))
		write(pre+"/loaderflags", ascii(t.LoaderFlags))
		write(pre+"/norvasizes", ascii(t.NumberOfRvaAndSizes))
		for i, t := range t.DataDirectory {
			name := fmt.Sprint(i)
			if i < len(Dirnames) {
				name = Dirnames[i]
			}
			dir := clean(pre + "/data/" + name)
			mkdir(dir)
			write(dir+"/offset", ascii(t.VirtualAddress))
			write(dir+"/size", ascii(t.Size))
		}
		wordsize = 32
	case *pe.OptionalHeader64:
		wordsize = 64
		base = int(t.ImageBase)
		codeoffset = int(t.BaseOfCode)
		pre := clean(dir + "/opthdr64")
		mkdir(pre)
		write(pre+"/magic", ascii(t.Magic))
		write(pre+"/version/linker/maj", ascii(t.MajorLinkerVersion))
		write(pre+"/version/linker/min", ascii(t.MinorLinkerVersion))
		write(pre+"/version/os/maj", ascii(t.MajorOperatingSystemVersion))
		write(pre+"/version/os/min", ascii(t.MinorOperatingSystemVersion))
		write(pre+"/version/image/maj", ascii(t.MajorImageVersion))
		write(pre+"/version/image/min", ascii(t.MinorImageVersion))
		write(pre+"/version/subsystem/maj", ascii(t.MajorSubsystemVersion))
		write(pre+"/version/subsystem/min", ascii(t.MinorSubsystemVersion))
		write(pre+"/version/win32", ascii(t.Win32VersionValue))
		write(pre+"/size/stackreserve", ascii(t.SizeOfStackReserve))
		write(pre+"/size/stackcommit", ascii(t.SizeOfStackCommit))
		write(pre+"/size/heapreserve", ascii(t.SizeOfHeapReserve))
		write(pre+"/size/heapcommit", ascii(t.SizeOfHeapCommit))
		write(pre+"/size/image", ascii(t.SizeOfImage))
		write(pre+"/size/headers", ascii(t.SizeOfHeaders))
		write(pre+"/size/code", ascii(t.SizeOfCode))
		write(pre+"/size/initdata", ascii(t.SizeOfInitializedData))
		write(pre+"/size/uninitdata", ascii(t.SizeOfUninitializedData))
		write(pre+"/addr/main", ascii(t.AddressOfEntryPoint))
		write(pre+"/addr/basecode", ascii(t.BaseOfCode))
		write(pre+"/addr/baseimage", ascii(t.ImageBase))
		write(pre+"/align/section", ascii(t.SectionAlignment))
		write(pre+"/align/file", ascii(t.FileAlignment))
		write(pre+"/crc", ascii(t.CheckSum))
		write(pre+"/subsystem", ascii(t.Subsystem))
		write(pre+"/dllcharacter", ascii(t.DllCharacteristics))
		write(pre+"/loaderflags", ascii(t.LoaderFlags))
		write(pre+"/norvasizes", ascii(t.NumberOfRvaAndSizes))
		for i, t := range t.DataDirectory {
			name := fmt.Sprint(i)
			if i < len(Dirnames) {
				name = Dirnames[i]
			}
			dir := clean(pre + "/data/" + name)
			mkdir(dir)
			write(dir+"/offset", ascii(t.VirtualAddress))
			write(dir+"/size", ascii(t.Size))
		}
	}

	mkdir(dir + "/section")
	order := ""
	for _, t := range fd.Sections {
		order += t.Name + " "
		pre := clean(dir + "/section/" + t.Name)
		mkdir(pre)
		write(pre+"/virtualsize", ascii(t.VirtualSize))
		write(pre+"/virtualaddr", ascii(t.VirtualAddress))
		write(pre+"/size", ascii(t.Size))
		write(pre+"/offset", ascii(t.Offset))
		write(pre+"/relocations", ascii(t.PointerToRelocations))
		write(pre+"/lines", ascii(t.PointerToLineNumbers))
		write(pre+"/norelocations", ascii(t.NumberOfRelocations))
		write(pre+"/nolines", ascii(t.NumberOfLineNumbers))
		write(pre+"/character", ascii(t.Characteristics))
		data, _ := t.Data()
		write(pre+"/data/raw", data)
		write(pre+"/data/dis", disasm(t.Name, data, wordsize, base+codeoffset))
		hwrite(pre+"/data/hex", data)
	}
	write(dir+"/section/ORDER", []byte(order))

	for _, t := range fd.Symbols {
		pre := dir + "/symbol/" + t.Name
		mkdir(pre)
		write(pre+"/value", ascii(t.Value))
		write(pre+"/section", ascii(t.SectionNumber))
		write(pre+"/type", ascii(t.Type))
		write(pre+"/storageclass", ascii(t.StorageClass))
	}
}
func fs2exe(exe string, dir string) {

	var (
		wordsize  int
		baseaddr  int
		filealign uint32
	)

	fd := &pe.File{FileHeader: pe.FileHeader{}}
	hdr := &fd.FileHeader
	pre := dir + "/hdr"
	sscan(pre+"/machine", &hdr.Machine)
	sscan(pre+"/nosections", &hdr.NumberOfSections)
	sscan(pre+"/timestamp", &hdr.TimeDateStamp)
	sscan(pre+"/symtabptr", &hdr.PointerToSymbolTable)
	sscan(pre+"/nosymbols", &hdr.NumberOfSymbols)
	sscan(pre+"/opthdrsize", &hdr.SizeOfOptionalHeader)
	sscan(pre+"/character", &hdr.Characteristics)

	if readable(dir + "/opthdr32") {
		wordsize = 32
		fd.OptionalHeader = &pe.OptionalHeader32{}
	} else if readable(dir + "/opthdr64") {
		wordsize = 64
		fd.OptionalHeader = &pe.OptionalHeader64{}
	} else {
		printerr("opthdr missing")
		return
	}

	switch t := fd.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		pre := dir + "/opthdr32"
		baseaddr = int(t.BaseOfCode)
		sscan(pre+"/magic", &t.Magic)
		sscan(pre+"/version/linker/maj", &t.MajorLinkerVersion)
		sscan(pre+"/version/linker/min", &t.MinorLinkerVersion)
		sscan(pre+"/version/os/maj", &t.MajorOperatingSystemVersion)
		sscan(pre+"/version/os/min", &t.MinorOperatingSystemVersion)
		sscan(pre+"/version/image/maj", &t.MajorImageVersion)
		sscan(pre+"/version/image/min", &t.MinorImageVersion)
		sscan(pre+"/version/subsystem/maj", &t.MajorSubsystemVersion)
		sscan(pre+"/version/subsystem/min", &t.MinorSubsystemVersion)
		sscan(pre+"/version/win32", &t.Win32VersionValue)
		sscan(pre+"/size/stackreserve", &t.SizeOfStackReserve)
		sscan(pre+"/size/stackcommit", &t.SizeOfStackCommit)
		sscan(pre+"/size/heapreserve", &t.SizeOfHeapReserve)
		sscan(pre+"/size/heapcommit", &t.SizeOfHeapCommit)
		sscan(pre+"/size/image", &t.SizeOfImage)
		sscan(pre+"/size/headers", &t.SizeOfHeaders)
		sscan(pre+"/size/code", &t.SizeOfCode)
		sscan(pre+"/size/initdata", &t.SizeOfInitializedData)
		sscan(pre+"/size/uninitdata", &t.SizeOfUninitializedData)
		sscan(pre+"/addr/main", &t.AddressOfEntryPoint)
		sscan(pre+"/addr/basecode", &t.BaseOfCode)
		sscan(pre+"/addr/basedata", &t.BaseOfData)
		sscan(pre+"/addr/baseimage", &t.ImageBase)
		sscan(pre+"/align/section", &t.SectionAlignment)
		sscan(pre+"/align/file", &t.FileAlignment)
		sscan(pre+"/crc", &t.CheckSum)
		sscan(pre+"/subsystem", &t.Subsystem)
		sscan(pre+"/dllcharacter", &t.DllCharacteristics)
		sscan(pre+"/loaderflags", &t.LoaderFlags)
		sscan(pre+"/norvasizes", &t.NumberOfRvaAndSizes)
		for i, _ := range t.DataDirectory {
			name := fmt.Sprint(i)
			if i < len(Dirnames) {
				name = Dirnames[i]
			}
			sscan(pre+"/data/"+name+"/offset", &t.DataDirectory[i].VirtualAddress)
			sscan(pre+"/data/"+name+"/size", &t.DataDirectory[i].Size)
		}
		wordsize = 32
		filealign = t.FileAlignment
		fd.OptionalHeader = t
	case *pe.OptionalHeader64:
		wordsize = 64
		filealign = t.FileAlignment
		baseaddr = int(t.BaseOfCode)
		pre := dir + "/opthdr64"
		sscan(pre+"/magic", &t.Magic)
		sscan(pre+"/version/linker/maj", &t.MajorLinkerVersion)
		sscan(pre+"/version/linker/min", &t.MinorLinkerVersion)
		sscan(pre+"/version/os/maj", &t.MajorOperatingSystemVersion)
		sscan(pre+"/version/os/min", &t.MinorOperatingSystemVersion)
		sscan(pre+"/version/image/maj", &t.MajorImageVersion)
		sscan(pre+"/version/image/min", &t.MinorImageVersion)
		sscan(pre+"/version/subsystem/maj", &t.MajorSubsystemVersion)
		sscan(pre+"/version/subsystem/min", &t.MinorSubsystemVersion)
		sscan(pre+"/version/win32", &t.Win32VersionValue)
		sscan(pre+"/size/stackreserve", &t.SizeOfStackReserve)
		sscan(pre+"/size/stackcommit", &t.SizeOfStackCommit)
		sscan(pre+"/size/heapreserve", &t.SizeOfHeapReserve)
		sscan(pre+"/size/heapcommit", &t.SizeOfHeapCommit)
		sscan(pre+"/size/image", &t.SizeOfImage)
		sscan(pre+"/size/headers", &t.SizeOfHeaders)
		sscan(pre+"/size/code", &t.SizeOfCode)
		sscan(pre+"/size/initdata", &t.SizeOfInitializedData)
		sscan(pre+"/size/uninitdata", &t.SizeOfUninitializedData)
		sscan(pre+"/addr/main", &t.AddressOfEntryPoint)
		sscan(pre+"/addr/basecode", &t.BaseOfCode)
		sscan(pre+"/addr/baseimage", &t.ImageBase)
		sscan(pre+"/align/section", &t.SectionAlignment)
		sscan(pre+"/align/file", &t.FileAlignment)
		sscan(pre+"/crc", &t.CheckSum)
		sscan(pre+"/subsystem", &t.Subsystem)
		sscan(pre+"/dllcharacter", &t.DllCharacteristics)
		sscan(pre+"/loaderflags", &t.LoaderFlags)
		sscan(pre+"/norvasizes", &t.NumberOfRvaAndSizes)
		for i, _ := range t.DataDirectory {
			name := fmt.Sprint(i)
			if i < len(Dirnames) {
				name = Dirnames[i]
			}
			sscan(pre+"/data/"+name+"/offset", &t.DataDirectory[i].VirtualAddress)
			sscan(pre+"/data/"+name+"/size", &t.DataDirectory[i].Size)
		}
		fd.OptionalHeader = t
	}

	ordered := sections(dir)
	for _, v := range ordered {
		if v == "" {
			continue
		}
		pre := dir + "/section/" + v
		t := pe.Section{}
		t.Name = v
		sscan(pre+"/virtualsize", &t.VirtualSize)
		sscan(pre+"/virtualaddr", &t.VirtualAddress)
		sscan(pre+"/size", &t.Size)
		sscan(pre+"/offset", &t.Offset)
		sscan(pre+"/relocations", &t.PointerToRelocations)
		sscan(pre+"/lines", &t.PointerToLineNumbers)
		sscan(pre+"/norelocations", &t.NumberOfRelocations)
		sscan(pre+"/nolines", &t.NumberOfLineNumbers)
		sscan(pre+"/character", &t.Characteristics)
		//		data, _ := t.Data()
		//		bsscan(pre+"/data/dis", disasm(data, wordsize, baseaddr)
		//		hsscan(pre+"/data/hex", data)
		data, err := ioutil.ReadFile(pre + "/data/raw")
		if err != nil {
			printerr(err)
		}
		t.ReaderAt = NewSectionReader(data)
		p := make([]byte, t.Size)
		t.ReadAt(p, 0)
		fmt.Println(p)
		fd.Sections = append(fd.Sections, &t)
	}
	fd.Symbols = make([]*pe.Symbol, hdr.NumberOfSymbols)
	for _, t := range fd.Symbols {
		pre := dir + "/symbol/" + t.Name
		sscan(pre+"/value", &t.Value)
		sscan(pre+"/section", &t.SectionNumber)
		sscan(pre+"/type", &t.Type)
	}

	//
	// Write the exe
	wordsize = wordsize
	baseaddr = baseaddr
	var n int64

	exefd, err := os.Create("test.exe")
	mustnil(err)
	defer exefd.Close()

	exewrite := func(i interface{}) {
		err := binary.Write(exefd, binary.LittleEndian, i)
		mustnil(err)
		n += int64(binary.Size(i))
	}

	//
	// Write DOS/Real program
	dos, err := ReadASCII(dir)
	mustnil(err)
	real, err := readreal(dir + "/dos")
	printerr(err)
	m, err := WriteDOS(exefd, dos, real)
	mustnil(err)
	n = int64(m)

	//
	// Write PE header & Optional header
	exewrite([]byte{'P', 'E', 0, 0})
	exewrite(fd.FileHeader)
	exewrite(fd.OptionalHeader)
	for _, v := range fd.Sections {
		hdr := v.SectionHeader
		var name [8]byte
		copy(name[:], hdr.Name)
		exewrite(name)
		exewrite(hdr.VirtualSize)
		exewrite(hdr.VirtualAddress)
		exewrite(hdr.Size)
		exewrite(hdr.Offset)
		exewrite(hdr.PointerToRelocations)
		exewrite(hdr.PointerToLineNumbers)
		exewrite(hdr.NumberOfRelocations)
		exewrite(hdr.NumberOfLineNumbers)
		exewrite(hdr.Characteristics)
	}
	//
	// Write Symbols
	for _, v := range fd.Symbols {
		hdr := v
		var name [8]byte
		copy(name[:], hdr.Name)
		exewrite(name)
		exewrite(hdr.Value)
		exewrite(hdr.SectionNumber)
		exewrite(hdr.Type)
		exewrite(hdr.StorageClass)
	}

	//
	// Align in file
	need := align(uint32(n), filealign)
	exewrite(bytes.Repeat(ZeroByte, int(need)))

	for _, v := range ordered {
		if v == "" {
			continue
		}
		pre := dir + "/section/" + v
		data, err := ioutil.ReadFile(pre + "/data/raw")
		mustnil(err)
		exewrite(data)
	}
}
