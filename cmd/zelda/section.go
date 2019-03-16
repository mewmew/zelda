package main

import (
	"log"

	"github.com/mewmew/pe/enum"
)

// A Section represents a continuous section of memory.
type Section struct {
	// Section name.
	Name string
	// Contents of section.
	Data []byte
	// Size of section contents in number of bytes. If Size < len(Data) then the
	// remaining bytes of Data are padding. If Size > len(Data) then the missing
	// bytes are uninitialized.
	Size int64
	// Virtual address of section.
	Addr Address
	// Access permissions of section.
	Perm Perm
}

// fill fills the address range with the given byte if present in the section.
func (sect *Section) fill(a AddrRange, b byte) {
	start := sect.Addr
	end := start + Address(len(sect.Data))
	if a.Start > end {
		return
	}
	if a.End <= start {
		return
	}
	for addr := a.Start; addr < a.End; addr++ {
		if start <= addr && addr < end {
			pos := addr - sect.Addr
			log.Printf("fill address %s with 0x%02X", addr, b)
			sect.Data[pos] = b
		}
	}
}

// replace replaces the contents at the given address with the specified bytes buffer.
func (sect *Section) replace(addr Address, buf []byte) {
	sectStart := sect.Addr
	sectEnd := sectStart + Address(len(sect.Data))
	bufStart := addr
	bufEnd := addr + Address(len(buf))
	if bufStart > sectEnd {
		return
	}
	if bufEnd <= sectStart {
		return
	}
	offset := int64(bufStart - sectStart)
	for i, b := range buf {
		a := bufStart + Address(i)
		log.Printf("replace byte at address %s with 0x%02X", a, b)
		sect.Data[offset+int64(i)] = b
	}
}

// --- [ Access permissions ] --------------------------------------------------

// Perm specifies the access permissions of a segment or section in memory.
type Perm uint8

// Access permissions.
const (
	// PermR specifies that the memory is readable.
	PermR Perm = 0x4
	// PermW specifies that the memory is writeable.
	PermW Perm = 0x2
	// PermX specifies that the memory is executable.
	PermX Perm = 0x1
)

// parsePerm returns the memory access permissions represented by the given PE
// section flags.
func parsePerm(flags enum.SectionFlag) Perm {
	var perm Perm
	if flags&enum.SectionFlagMemRead != 0 {
		perm |= PermR
	}
	if flags&enum.SectionFlagMemWrite != 0 {
		perm |= PermW
	}
	if flags&enum.SectionFlagMemExecute != 0 {
		perm |= PermX
	}
	return perm
}
