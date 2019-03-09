package main

import (
	"debug/elf"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"text/template"

	"github.com/mewkiz/pkg/goutil"
	"github.com/pkg/errors"
)

// --- [ File header ] ---------------------------------------------------------

// dumpFileHdr outputs the ELF file header in NASM syntax, writing to w.
func dumpFileHdr(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "ehdr.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, nil); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// --- [ Program headers ] -----------------------------------------------------

// ProgHeader is an ELF program header.
type ProgHeader struct {
	// Title comment.
	Title string
	// Program header type.
	Type string
	// Name of program header.
	Name string
	// Memory access flags of segment.
	Flags string
	// Alignment of segment.
	Align string
}

// dumpProgHdrs outputs the ELF program headers in NASM syntax based on the
// given sections, writing to w.
func dumpProgHdrs(w io.Writer, progHdrs []ProgHeader) error {
	funcs := template.FuncMap{
		"h2": h2,
	}
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "phdr.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).Funcs(funcs).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, progHdrs); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// === [ Sections ] ============================================================

// --- [ .interp section ] -----------------------------------------------------

// dumpInterpSect outputs the .interp section in NASM syntax, writing to w.
func dumpInterpSect(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "interp.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, nil); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// --- [ .dynamic section ] ----------------------------------------------------

// dumpDynamicSect outputs the .dynamic section in NASM syntax based on the
// given imported libraries, writing to w.
func dumpDynamicSect(w io.Writer, libs []Library) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "dynamic.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, libs); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpDynstrSect outputs the .dynstr section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpDynstrSect(w io.Writer, libs []Library) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "dynstr.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, libs); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// ### [ Helper functions ] ####################################################

// h2 returns a h2 heading as an 80-column NASM comment.
func h2(title string) string {
	// --- [ title ] ---
	const width = 80
	m := width - len("; --- [ ") - len(title) - len(" ] ")
	return fmt.Sprintf("; --- [ %s ] %s", title, strings.Repeat("-", m))
}

// nasmIdent returns a valid NASM identifier based on the given string.
func nasmIdent(s string) string {
	f := func(r rune) rune {
		const (
			lower   = "abcdefghijklmnopqrstuvwxyz"
			upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			digits  = "0123456789"
			charset = lower + upper + digits + "_"
		)
		if strings.ContainsRune(charset, r) {
			return r
		}
		return '_'
	}
	return strings.Map(f, s)
}

// elfProgFlag returns the program header flags based on the given memory access
// permissions.
func elfProgFlag(perm Perm) elf.ProgFlag {
	var flags elf.ProgFlag
	if perm&PermR != 0 {
		flags |= elf.PF_R
	}
	if perm&PermW != 0 {
		flags |= elf.PF_W
	}
	if perm&PermX != 0 {
		flags |= elf.PF_X
	}
	return flags
}

// ProgFlagString returns the string representation of the given program flags.
func ProgFlagString(flags elf.ProgFlag) string {
	return strings.ReplaceAll(flags.String(), "+", " | ")
}
