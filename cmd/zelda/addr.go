package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// --- [ Binary replacements ] -------------------------------------------------

// Replacements is a set of binary replacements.
type Replacements []Replacement

// Set sets the binary replacements based on the given string.
func (rs *Replacements) Set(s string) error {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		var r Replacement
		part = strings.TrimSpace(part)
		if err := r.Set(part); err != nil {
			return errors.WithStack(err)
		}
		*rs = append(*rs, r)
	}
	return nil
}

// String returns the string representation of the binary replacements.
func (rs Replacements) String() string {
	var ss []string
	for _, r := range rs {
		s := r.String()
		ss = append(ss, s)
	}
	return strings.Join(ss, ",")
}

// Replacement is a binary replacement specified by address.
type Replacement struct {
	// Start address of binary replacement.
	Addr Address
	// New content.
	Buf []byte
}

// Set sets the binary replacement based on the given string.
func (r *Replacement) Set(s string) error {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return errors.Errorf("invalid number of dash-separated parts in binary replacement; expected 2, got %d", len(parts))
	}
	if err := r.Addr.Set(parts[0]); err != nil {
		return errors.WithStack(err)
	}
	buf, err := hex.DecodeString(parts[1])
	if err != nil {
		return errors.WithStack(err)
	}
	r.Buf = buf
	return nil
}

// String returns the string representation of the binary replacement.
func (r Replacement) String() string {
	return fmt.Sprintf("%s:%X", r.Addr, r.Buf)
}

// --- [ Address ranges ] ------------------------------------------------------

// AddrRanges is a set of address ranges.
type AddrRanges []AddrRange

// Contains reports whether the address range contains the given address.
func (as AddrRanges) Contains(addr Address) bool {
	for _, a := range as {
		if a.Contains(addr) {
			return true
		}
	}
	return false
}

// Set sets the address ranges based on the given string.
func (as *AddrRanges) Set(s string) error {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		var a AddrRange
		part = strings.TrimSpace(part)
		if err := a.Set(part); err != nil {
			return errors.WithStack(err)
		}
		*as = append(*as, a)
	}
	return nil
}

// String returns the string representation of the address ranges.
func (as AddrRanges) String() string {
	var ss []string
	for _, a := range as {
		s := a.String()
		ss = append(ss, s)
	}
	return strings.Join(ss, ",")
}

// AddrRange defines the address range [start, end).
type AddrRange struct {
	// Start address, inclusive.
	Start Address
	// End address, exclusive.
	End Address
}

// Contains reports whether the address range contains the given address.
func (a AddrRange) Contains(addr Address) bool {
	return a.Start <= addr && addr < a.End
}

// Set sets the address range based on the given string.
func (a *AddrRange) Set(s string) error {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return errors.Errorf("invalid number of dash-separated parts in address range; expected 2, got %d", len(parts))
	}
	if err := a.Start.Set(parts[0]); err != nil {
		return errors.WithStack(err)
	}
	if err := a.End.Set(parts[1]); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// String returns the string representation of the address range.
func (a AddrRange) String() string {
	return fmt.Sprintf("%s-%s", a.Start, a.End)
}

// Address is a virtual address, which may be specified in hexadecimal notation.
// It implements the flag.Value, encoding.TextUnmarshaler and
// metadata.Unmarshaler interfaces.
type Address uint64

// Set sets the address based on the given string.
func (a *Address) Set(s string) error {
	x, err := parseHex(s)
	if err != nil {
		return errors.WithStack(err)
	}
	*a = Address(x)
	return nil
}

// String returns the string representation of the address.
func (a Address) String() string {
	return fmt.Sprintf("0x%X", uint64(a))
}

// UnmarshalText unmarshals the text into a.
func (a *Address) UnmarshalText(text []byte) error {
	return a.Set(string(text))
}

// MarshalText returns the textual representation of a.
func (a Address) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// ### [ Helper functions ] ####################################################

// parseHex parses the hexadecimal representation of an unsigned integer.
func parseHex(s string) (uint64, error) {
	s = strings.ToLower(s)
	const prefix = "0x"
	if !strings.HasPrefix(s, prefix) {
		return 0, errors.Errorf("invalid address %q; missing hexadecimal prefix %q", s, prefix)
	}
	s = s[len(prefix):]
	x, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return x, nil
}
