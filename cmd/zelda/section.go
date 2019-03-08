package main

import "github.com/mewmew/pe/enum"

// A Section represents a continuous section of memory.
type Section struct {
	// Section name.
	Name string
	// Contents of section.
	Data []byte
	// Virtual address of section.
	Addr uint64
	// Access permissions of section.
	Perm Perm
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
