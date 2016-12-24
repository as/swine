package main
import (
	"fmt"
	"path/filepath"
	"os"
	"encoding/hex"
	"io/ioutil"
	"strconv"
)
func align(n, a uint32) uint32 {
	if a == 0 {
		printerr("warning: file alignment was zero")
		return 512
	}
	// TODO: This might be different
	return (a - n) % a
}
func clean(dir string) string {
	dir = filepath.ToSlash(dir)
	dir = filepath.FromSlash(dir)
	return filepath.Clean(dir)
}
func dirof(file string) string {
	file = clean(file)
	printerr("dirof:",file,"=",filepath.Dir(file))
	return filepath.Dir(file)
}
func fatal(v interface{}) {
	printerr(v)
	os.Exit(1)
}
func hwrite(name string, data []byte) error {
	s := hex.Dump(data)
	return write(name, []byte(s))
}
func mkdir(dir string) error {
	err := os.MkdirAll(clean(dir), 0777)
	if err != nil{
		printerr(err)
		os.Exit(1)
	}
	return nil
}
func read(name string) ([]byte, error) {
	return ioutil.ReadFile(clean(name))
}
func readable(file string) bool {
	fd, err := os.Open(clean(file))
	defer fd.Close()
	if err != nil {
		printerr(err) //TODO
	}
	return true
}
func mustnil(e error) {
	if e == nil {
		return
	}
	fatal(e)
}
func println(v ...interface{}) {
	fmt.Print(Prefix)
	fmt.Println(v...)
}

func printerr(v ...interface{}) {
	fmt.Fprint(os.Stderr, Prefix)
	fmt.Fprintln(os.Stderr, v...)
}

func read64(file string) (uint64, error) {
	data, err := read(clean(file))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(data), 10, 64)
}
func sscan(s string, a ...interface{}) (n int, err error) {
	data, err := read(clean(s))
	if err != nil {
		mustnil(err)
		return
	}
	return fmt.Sscan(string(data), a...)
}
func write(name string, data []byte) error {
	printerr("write: rq", name)
	name = clean(name)
	printerr("write: clean:", name)
	printerr("write: dirof:", dirof(name))
	mkdir(dirof(name))
	return ioutil.WriteFile(name, data, 0777)
}