// Zelda is Link's companion.
package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/mewkiz/pkg/pathutil"
	"github.com/mewmew/pe"
	"github.com/pkg/errors"
)

func main() {
	flag.Parse()
	for _, pePath := range flag.Args() {
		if err := relink(pePath); err != nil {
			log.Fatalf("%+v", err)
		}
	}
}

// relink relinks the given PE file into a corresponding ELF file.
func relink(pePath string) error {
	// Parse PE file.
	file, err := pe.ParseFile(pePath)
	if err != nil {
		return errors.WithStack(err)
	}
	// Parse sections.
	sects := parseSects(file)
	// Parse imported libraries.
	libs := parseImports(file)
	// TODO: add command line option to add extra import libraries.

	// ___ [ Read-only segment ] ___
	// Output header of read-only segment.
	out := &bytes.Buffer{}
	// TODO: make base address configurable from command line.
	const base = 0x80400000 // use 0x8XXXXXXX to prevent conflict with 0x0XXXXXXX
	if err := dumpRSegPre(out, base); err != nil {
		return errors.WithStack(err)
	}
	// Output ELF file header.
	entry := file.OptHdr.ImageBase + uint64(file.OptHdr.EntryRelAddr)
	if err := dumpFileHdr(out, entry); err != nil {
		return errors.WithStack(err)
	}
	// Get ELF program headers for the sections.
	progHdrs := elfProgHdrs(sects)
	// Output ELF program headers.
	if err := dumpProgHdrs(out, progHdrs); err != nil {
		return errors.WithStack(err)
	}
	// Output sections.
	// === [ Sections ] ===
	// Output sections header.
	const sectPre = "; === [ Sections ] =============================================================\n\n"
	if _, err := out.WriteString(sectPre); err != nil {
		return errors.WithStack(err)
	}
	// .interp
	if err := dumpInterpSect(out); err != nil {
		return errors.WithStack(err)
	}
	// .dynamic
	if err := dumpDynamicSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// .dynstr
	if err := dumpDynstrSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// .dynsym
	if err := dumpDynsymSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// .rel.plt
	if err := dumpRelPltSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// Output footer of read-only segment.
	if err := dumpRSegPost(out); err != nil {
		return errors.WithStack(err)
	}
	// ___ [/ Read-only segment ] ___

	// ___ [ Read-write segment ] ___
	// Output header of read-write segment.
	if err := dumpRWSegPre(out); err != nil {
		return errors.WithStack(err)
	}
	// .got.plt
	if err := dumpGotPltSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// Output footer of read-write segment.
	if err := dumpRWSegPost(out); err != nil {
		return errors.WithStack(err)
	}
	// ___ [/ Read-write segment ] ___

	// ___ [ Executable segment ] ___
	// Output header of executable segment.
	if err := dumpXSegPre(out); err != nil {
		return errors.WithStack(err)
	}
	// .plt
	if err := dumpPltSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
	// Output footer of executable segment.
	if err := dumpXSegPost(out); err != nil {
		return errors.WithStack(err)
	}
	// ___ [/ Executable segment ] ___

	// Output sections of PE file.
	prevSeg := "x_seg"
	for _, sect := range sects {
		if err := dumpSect(out, sect, prevSeg); err != nil {
			return errors.WithStack(err)
		}
		prevSeg = nasmIdent(sect.Name)
	}
	// Output sections footer.
	const sectPost = "; === [/ Sections ] ============================================================\n\n"
	if _, err := out.WriteString(sectPost); err != nil {
		return errors.WithStack(err)
	}
	// === [/ Sections ] ===

	fmt.Println(out.String())
	return nil
}

// parseSects parses the sections of the given PE file into a unified format.
func parseSects(file *pe.File) []*Section {
	var sects []*Section
	for _, sectHdr := range file.SectHdrs {
		start := sectHdr.DataOffset
		end := start + sectHdr.DataSize
		data := file.Content[start:end]
		addr := file.OptHdr.ImageBase + uint64(sectHdr.RelAddr)
		perm := parsePerm(sectHdr.Flags)
		sect := &Section{
			Name: sectHdr.Name,
			Data: data,
			Addr: addr,
			Perm: perm,
		}
		sects = append(sects, sect)
	}
	return sects
}

// elfProgHdrs returns the ELF program headers corresponding to the given
// sections. The interpreter and dynamic program headers are always included.
func elfProgHdrs(sects []*Section) []ProgHeader {
	var progHdrs []ProgHeader
	// Add interpreter program header.
	interpProgHdr := ProgHeader{
		Title: "Interpreter program header",
		Type:  elf.PT_INTERP.String(),
		Name:  "interp",
		Flags: elf.PF_R.String(),
		Align: fmt.Sprintf("0x%X", 1),
	}
	progHdrs = append(progHdrs, interpProgHdr)
	// Add dynamic program header.
	dynamicProgHdr := ProgHeader{
		Title: "Dynamic array program header",
		Type:  elf.PT_DYNAMIC.String(),
		Name:  "dynamic",
		Flags: elf.PF_R.String(),
		Align: "dynamic_align",
	}
	progHdrs = append(progHdrs, dynamicProgHdr)
	// Add read-only segment program header.
	rSegProgHdr := ProgHeader{
		Title: "Read-only segment program header",
		Type:  elf.PT_LOAD.String(),
		Name:  "r_seg",
		Flags: elf.PF_R.String(),
		Align: "PAGE",
	}
	progHdrs = append(progHdrs, rSegProgHdr)
	// Add read-write segment program header.
	rwSegProgHdr := ProgHeader{
		Title: "Read-write segment program header",
		Type:  elf.PT_LOAD.String(),
		Name:  "rw_seg",
		Flags: ProgFlagString(elf.PF_R | elf.PF_W),
		Align: "PAGE",
	}
	progHdrs = append(progHdrs, rwSegProgHdr)
	// Add executable segment program header.
	xSegProgHdr := ProgHeader{
		Title: "Executable segment program header",
		Type:  elf.PT_LOAD.String(),
		Name:  "x_seg",
		Flags: ProgFlagString(elf.PF_R | elf.PF_X),
		Align: "PAGE",
	}
	progHdrs = append(progHdrs, xSegProgHdr)
	// Add section program headers.
	for _, sect := range sects {
		title := fmt.Sprintf("%s segment program header", sect.Name)
		name := nasmIdent(sect.Name)
		flags := elfProgFlag(sect.Perm)
		progHdr := ProgHeader{
			Title: title,
			Type:  elf.PT_LOAD.String(),
			Name:  name,
			Flags: ProgFlagString(flags),
			Align: "PAGE",
		}
		progHdrs = append(progHdrs, progHdr)
	}
	return progHdrs
}

// parseImports parses the imported libraries of the given PE file into a
// unified format.
func parseImports(file *pe.File) []Library {
	var libs []Library
	for _, imp := range file.Imps {
		baseName := pathutil.TrimExt(strings.ToLower(imp.ImpDir.Name))
		filename := baseName + ".so"
		lib := Library{
			Name:     baseName,
			Filename: filename,
		}
		for _, iat := range imp.IATs {
			var funcName string
			if iat.IsOrdinal {
				funcName = fmt.Sprintf("%s_ordinal_%d", baseName, iat.Ordinal)
			} else {
				funcName = iat.NameEntry.Name
			}
			lib.Funcs = append(lib.Funcs, funcName)
		}
		libs = append(libs, lib)
	}
	return libs
}
