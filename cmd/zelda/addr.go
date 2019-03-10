package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// AddrRanges is a set of address ranges.
type AddrRanges []AddrRange

// Contains reports whether the address range contains the given address.
func (as AddrRanges) Contains(addr uint64) bool {
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
	Start uint64
	End   uint64
}

// Contains reports whether the address range contains the given address.
func (a AddrRange) Contains(addr uint64) bool {
	return a.Start <= addr && addr < a.End
}

// Set sets the address range based on the given string.
func (a *AddrRange) Set(s string) error {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return errors.Errorf("invalid number of dash-separated parts in address range; expected 2, got %d", len(parts))
	}
	startRaw := strings.ToLower(parts[0])
	endRaw := strings.ToLower(parts[1])
	start, err := parseHex(startRaw)
	if err != nil {
		return errors.WithStack(err)
	}
	end, err := parseHex(endRaw)
	if err != nil {
		return errors.WithStack(err)
	}
	a.Start = start
	a.End = end
	return nil
}

// parseHex parses the hexadecimal representation of an unsigned integer.
func parseHex(s string) (uint64, error) {
	s = strings.ToLower(s)
	const prefix = "0x"
	if !strings.HasPrefix(s, prefix) {
		return 0, errors.Errorf("invalid address %q; missing hexadecimal prefix", s)
	}
	s = s[len(prefix):]
	x, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return x, nil
}

// String returns the string representation of the address range.
func (a AddrRange) String() string {
	return fmt.Sprintf("0x%X-0x%X", a.Start, a.End)
}
