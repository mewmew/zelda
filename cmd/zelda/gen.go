package main

import (
	"bytes"
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

// dumpFileHdr outputs the ELF file header in NASM syntax based on the given
// entry point address, writing to w.
func dumpFileHdr(w io.Writer, entry Address, isSharedLib bool) error {
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
	data := map[string]interface{}{
		"Entry":       entry,
		"IsSharedLib": isSharedLib,
	}
	if err := t.Execute(tw, data); err != nil {
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

// === [ Segments ] ============================================================

// dumpRSegPre outputs the header of a read-only segment in NASM syntax based on
// the given base address, writing to w.
func dumpRSegPre(w io.Writer, base uint64) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "r_seg_pre.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	data := map[string]string{
		"Base": fmt.Sprintf("0x%08X", base),
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpRSegPost outputs the footer of a read-only segment in NASM syntax,
// writing to w.
func dumpRSegPost(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "r_seg_post.tmpl"
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

// dumpRWSegPre outputs the header of a read-write segment in NASM syntax,
// writing to w.
func dumpRWSegPre(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "rw_seg_pre.tmpl"
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

// dumpRWSegPost outputs the footer of a read-write segment in NASM syntax,
// writing to w.
func dumpRWSegPost(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "rw_seg_post.tmpl"
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

// dumpXSegPre outputs the header of an executable segment in NASM syntax,
// writing to w.
func dumpXSegPre(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "x_seg_pre.tmpl"
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

// dumpXSegPost outputs the footer of an executable segment in NASM syntax,
// writing to w.
func dumpXSegPost(w io.Writer) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "x_seg_post.tmpl"
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

// --- [ .hash section ] -------------------------------------------------------

// dumpHashSect outputs the .hash section in NASM syntax based on the given
// exported symbols, writing to w.
func dumpHashSect(w io.Writer, nglobals int) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "hash.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	symbolIndices := []int{
		0, // STN_UNDEF
	}
	for symIdx := 0; symIdx < nglobals; symIdx++ {
		symbolIndices = append(symbolIndices, symIdx)
	}
	data := map[string]interface{}{
		"SymbolIndices": symbolIndices,
	}
	if err := t.Execute(tw, data); err != nil {
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
func dumpDynamicSect(w io.Writer, libs []Library, exports []Export) error {
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
	data := map[string]interface{}{
		"Libs":    libs,
		"Exports": exports,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpDynstrSect outputs the .dynstr section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpDynstrSect(w io.Writer, libs []Library, exports []Export) error {
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
	data := map[string]interface{}{
		"Libs":    libs,
		"Exports": exports,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpDynsymSect outputs the .dynsym section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpDynsymSect(w io.Writer, libs []Library, exports []Export) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "dynsym.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	data := map[string]interface{}{
		"Libs":    libs,
		"Exports": exports,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpRelPltSect outputs the .rel.plt section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpRelPltSect(w io.Writer, libs []Library) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "rel_plt.tmpl"
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

// dumpGotPltSect outputs the .got.plt section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpGotPltSect(w io.Writer, libs []Library) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "got_plt.tmpl"
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

// dumpPltSect outputs the .plt section in NASM syntax based on the given
// imported libraries, writing to w.
func dumpPltSect(w io.Writer, libs []Library) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "plt.tmpl"
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

// genSectContent returns the contents of the given section in NASM syntax,
// using the formatting functions to pretty-print data.
func genSectContent(sect *Section, fs ...func(w io.Writer, addr Address, buf []byte) (int, error)) (string, error) {
	// Initialized data.
	out := &bytes.Buffer{}
	addr := sect.Addr
loop:
	// TODO: only print the first Size bytes of Data (when len(Data) > Size).
	// Mark the remaining bytes of Data as padding.
	for i := 0; i < len(sect.Data); {
		buf := sect.Data[i:]
		fmt.Fprintf(out, "; address: %s\n", addr)
		for _, f := range fs {
			n, err := f(out, addr, buf)
			if err != nil {
				return "", errors.WithStack(err)
			}
			if n != 0 {
				// f pretty-printed n bytes of section contents at the current
				// address.
				i += n
				addr += Address(n)
				continue loop
			}
		}
		// The current address was not pretty printed.
		b := sect.Data[i]
		c := byte('.')
		if isPrint(b) {
			c = b
		}
		fmt.Fprintf(out, "\tdb      0x%02X ; |%c|\n", b, c)
		i++
		addr++
	}
	// Uninitialized data.
	// TODO: use pretty-printer functions also for uninitialized data.
	if sect.Size > int64(len(sect.Data)) {
		n := sect.Size - int64(len(sect.Data))
		out.WriteString("; Uninitialized data.\n")
		fmt.Fprintf(out, "resb %d\n", n)
	}
	return out.String(), nil
}

// dumpSect outputs the given PE section in NASM syntax and PE library imports,
// writing to w.
func dumpSect(w io.Writer, sect *Section, prevSeg string, content string) error {
	funcs := template.FuncMap{
		"h0":    h0,
		"h0End": h0End,
		"h2":    h2,
		"h2End": h2End,
	}
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "sect.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).Funcs(funcs).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	pad := "db 0x00"
	if sect.Perm&PermX != 0 {
		pad = "int3"
	}
	data := map[string]interface{}{
		"Name":    sect.Name,
		"Ident":   nasmIdent(sect.Name),
		"PrevSeg": prevSeg,
		"Addr":    sect.Addr,
		"Content": content,
		"Pad":     pad,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpShstrtabSect outputs the .shstrtab section in NASM syntax based on the
// given sections, writing to w.
func dumpShstrtabSect(w io.Writer, prevSeg string, sects []*Section) error {
	funcs := template.FuncMap{
		"nasmIdent": nasmIdent,
	}
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "shstrtab.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).Funcs(funcs).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	data := map[string]interface{}{
		"PrevSeg": prevSeg,
		"Sects":   sects,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// dumpLibImps outputs a redirection from the given PE import entries to their
// corresponding ELF dynamic symbols in NASM syntax, writing to w.
func dumpLibImps(w io.Writer, lib Library) error {
	funcs := template.FuncMap{
		"h2":    h2,
		"h2End": h2End,
	}
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "lib_imps.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).Funcs(funcs).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	if err := t.Execute(tw, lib); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// --- [ Section headers ] -----------------------------------------------------

// dumpSectHdrs outputs the ELF section headers in NASM syntax based on the
// given sections, writing to w.
func dumpSectHdrs(w io.Writer, sects []*Section, hasGlobal bool) error {
	srcDir, err := goutil.SrcDir("github.com/mewmew/zelda/cmd/zelda")
	if err != nil {
		return errors.WithStack(err)
	}
	const tmplName = "shdr.tmpl"
	tmplPath := filepath.Join(srcDir, tmplName)
	t, err := template.New(tmplName).ParseFiles(tmplPath)
	if err != nil {
		return errors.WithStack(err)
	}
	// flags:
	//    SHF_ALLOC | SHF_EXECINSTR
	tw := tabwriter.NewWriter(w, 1, 3, 1, ' ', tabwriter.TabIndent)
	// Prepare data for template.
	type ELFSection struct {
		Name  string
		Flags string
	}
	var elfSects []ELFSection
	for _, sect := range sects {
		flags := elfSectionFlag(sect.Perm)
		elfSect := ELFSection{
			Name:  nasmIdent(sect.Name),
			Flags: SectionFlagString(flags),
		}
		elfSects = append(elfSects, elfSect)
	}
	data := map[string]interface{}{
		"Sects":     elfSects,
		"HasGlobal": hasGlobal,
	}
	if err := t.Execute(tw, data); err != nil {
		return errors.WithStack(err)
	}
	if err := tw.Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// ### [ Helper functions ] ####################################################

// hexdump outputs the given data as a hexdump in NASM format.
func hexdump(data []byte) string {
	buf := &bytes.Buffer{}
	for pos := 0; pos < len(data); {
		end := pos + 16
		if end > len(data) {
			end = len(data)
		}
		buf.WriteString("\tdb      ")
		line := data[pos:end]
		for i := 0; i < 16; i++ {
			if i < len(line) {
				if i != 0 {
					buf.WriteString(", ")
				}
				fmt.Fprintf(buf, "0x%02X", line[i])
			} else {
				buf.WriteString("      ")
			}
		}
		buf.WriteString(" ; |")
		for _, b := range line {
			if !isPrint(b) {
				buf.WriteString(".")
			} else {
				fmt.Fprintf(buf, "%c", b)
			}
		}
		buf.WriteString("|\n")
		pos = end
	}
	return buf.String()
}

// isPrint reports whether the given ASCII character is printable.
func isPrint(b byte) bool {
	//  For the standard ASCII character set (used by the "C" locale), printing
	//  characters are all with an ASCII code greater than 0x1f (US), except 0x7f
	//  (DEL).
	return ' ' <= b && b <= '~'
}

// h0 returns a h0 heading as an 80-column NASM comment.
func h0(title string) string {
	// ___ [ title ] ___
	const width = 80
	m := width - len("; ___ [ ") - len(title) - len(" ] ")
	return fmt.Sprintf("; ___ [ %s ] %s", title, strings.Repeat("_", m))
}

// h0End returns an end h0 heading as an 80-column NASM comment.
func h0End(title string) string {
	// ___ [/ title ] ___
	const width = 80
	m := width - len("; ___ [/ ") - len(title) - len(" ] ")
	return fmt.Sprintf("; ___ [/ %s ] %s", title, strings.Repeat("_", m))
}

// h2 returns a h2 heading as an 80-column NASM comment.
func h2(title string) string {
	// --- [ title ] ---
	const width = 80
	m := width - len("; --- [ ") - len(title) - len(" ] ")
	return fmt.Sprintf("; --- [ %s ] %s", title, strings.Repeat("-", m))
}

// h2End returns an end h2 heading as an 80-column NASM comment.
func h2End(title string) string {
	// --- [/ title ] ---
	const width = 80
	m := width - len("; --- [/ ") - len(title) - len(" ] ")
	return fmt.Sprintf("; --- [/ %s ] %s", title, strings.Repeat("-", m))
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

// elfSectionFlag returns the section header flags based on the given memory
// access permissions.
func elfSectionFlag(perm Perm) elf.SectionFlag {
	var flags elf.SectionFlag
	flags |= elf.SHF_ALLOC
	if perm&PermR != 0 {
		// ELF sections are always readable.
		// nothing to do.
	}
	if perm&PermW != 0 {
		flags |= elf.SHF_WRITE
	}
	if perm&PermX != 0 {
		flags |= elf.SHF_EXECINSTR
	}
	return flags
}

// ProgFlagString returns the string representation of the given program flags.
func ProgFlagString(flags elf.ProgFlag) string {
	return strings.ReplaceAll(flags.String(), "+", " | ")
}

// SectionFlagString returns the string representation of the given section
// flags.
func SectionFlagString(flags elf.SectionFlag) string {
	return strings.ReplaceAll(flags.String(), "+", " | ")
}
