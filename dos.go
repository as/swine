package main

import (
	"fmt"
	"io"
	"encoding/binary"
)
type DOS struct {
	Magic    uint16
	CBLP     uint16
	CP       uint16
	CRLC     uint16
	CPartHdr uint16
	MinAlloc uint16
	MaxAlloc uint16
	SS       uint16
	SP       uint16
	CSum     uint16
	IP       uint16
	CS       uint16
	LFARLO   uint16
	OVNO     uint16
	Res      [4]uint16
	OEMID    uint16
	OEMInfo  uint16
	Res2     [10]uint16
	LFANew   uint32
}

func writereal(dir string, data []byte) (err error) {
	if err = write(dir+"/raw", data); err != nil {
		return
	}
	if err = write(dir+"/dis", disasm("r",data, 16, 0)); err != nil {
		return
	}
	return hwrite(dir+"/hex", data)
}
func readreal(dir string) (data []byte, err error) {
	return read(dir + "/real/raw")
}
func ReadDOS(fd io.Reader) (dos *DOS, real []byte, err error) {
	dos = new(DOS)
	err = binary.Read(fd, binary.LittleEndian, dos)
	if err != nil || dos == nil {
		return
	}
	if dos.LFANew <= 64 || dos.LFANew > 512 {
		return nil, nil, fmt.Errorf("odd program: pe header @ 0x%x", dos.LFANew)
	}
	need := int(dos.LFANew - 64)
	real = make([]byte, need)
	n, err := fd.Read(real)
	if err != nil {
		return
	}
	if n != need {
		return nil, nil, fmt.Errorf("short read")
	}
	return
}
func WriteDOS(fd io.Writer, dos *DOS, real []byte) (n int, err error) {
	err = binary.Write(fd, binary.LittleEndian, dos)
	if err != nil {
		return
	}
	if n, err = fd.Write(real); err != nil {
		return
	}
	return n + binary.Size(dos), nil

}

func (d DOS) WriteASCII(dir string) (err error) {
	sprint := func(i interface{}) []byte{
		return []byte(fmt.Sprint(i))
	}
	pre := dir + "/dos/"
	t := d
	write(pre+"/magic",    sprint(t.Magic))
	write(pre+"/cblp",     sprint(t.CBLP))
	write(pre+"/cp",       sprint(t.CP))
	write(pre+"/crlc",     sprint(t.CRLC))
	write(pre+"/cparthdr", sprint(t.CPartHdr))
	write(pre+"/minalloc", sprint(t.MinAlloc))
	write(pre+"/maxalloc", sprint(t.MaxAlloc))
	write(pre+"/ss",       sprint(t.SS))
	write(pre+"/sp",       sprint(t.SP))
	write(pre+"/csum",     sprint(t.CSum))
	write(pre+"/ip",       sprint(t.IP))
	write(pre+"/cs",       sprint(t.CS))
	write(pre+"/lfarlo",   sprint(t.LFARLO))
	write(pre+"/ovno",     sprint(t.OVNO))
	write(pre+"/res",      sprint(t.Res))
	write(pre+"/oemid",    sprint(t.OEMID))
	write(pre+"/oeminfo",  sprint(t.OEMInfo))
	write(pre+"/res2",     sprint(t.Res2))
	write(pre+"/lfanew",   sprint(t.LFANew))
	return
}

func ReadASCII(src string) (t *DOS, err error) {
	pre := src + "/dos"
	t = &DOS{}
	sscan(pre+"/magic", &t.Magic)
	sscan(pre+"/cblp", &t.CBLP)
	sscan(pre+"/cp", &t.CP)
	sscan(pre+"/crlc", &t.CRLC)
	sscan(pre+"/cparthdr", &t.CPartHdr)
	sscan(pre+"/minalloc", &t.MinAlloc)
	sscan(pre+"/maxalloc", &t.MaxAlloc)
	sscan(pre+"/ss", &t.SS)
	sscan(pre+"/sp", &t.SP)
	sscan(pre+"/csum", &t.CSum)
	sscan(pre+"/ip", &t.IP)
	sscan(pre+"/cs", &t.CS)
	sscan(pre+"/lfarlo", &t.LFARLO)
	sscan(pre+"/ovno", &t.OVNO)
	sscan(pre+"/res", &t.Res)
	sscan(pre+"/oemid", &t.OEMID)
	sscan(pre+"/oeminfo", &t.OEMInfo)
	sscan(pre+"/res2", &t.Res2)
	sscan(pre+"/lfanew", &t.LFANew)
	return
}
