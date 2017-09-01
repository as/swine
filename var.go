package main

import (
	"fmt"
	"io"
)

var ZeroByte = []byte{0}

var Dirnames = [...]string{
	".edata", ".idata", ".rsrc", ".pdata",
	".cert", ".reloc", ".debug", ".arch",
	".global", ".tls", ".loadtbl", ".bound",
	".import", ".delayimport", ".clr", ".reserved",
}

type SectionReader struct {
	data []byte
}

type ReaderAt interface {
	io.ReaderAt
}

func NewSectionReader(d []byte) *SectionReader {
	return &SectionReader{d}
}
func (s SectionReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(s.data)) {
		return 0, fmt.Errorf("offset >= data")
	}
	return copy(p, s.data[off:]), nil
}
