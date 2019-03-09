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
	// Output ELF file header.
	out := &bytes.Buffer{}
	if err := dumpFileHdr(out); err != nil {
		return errors.WithStack(err)
	}
	// Get ELF program headers for the sections.
	progHdrs := elfProgHdrs(sects)
	// Output ELF program headers.
	if err := dumpProgHdrs(out, progHdrs); err != nil {
		return errors.WithStack(err)
	}
	// Output sections.
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
	// .got.plt
	// TODO: ensure that the .got.plt section is located within a read-write area
	// of memory.
	if err := dumpGotPltSect(out, libs); err != nil {
		return errors.WithStack(err)
	}
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
		perm := parsePerm(sectHdr.Flags)
		sect := &Section{
			Name: sectHdr.Name,
			Data: data,
			Addr: uint64(sectHdr.RelAddr), // TODO: add IMAGE_BASE?
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
		Align: fmt.Sprintf("0x%X", 4),
	}
	progHdrs = append(progHdrs, dynamicProgHdr)
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
				funcName = fmt.Sprintf("ordinal_%d", iat.Ordinal)
			} else {
				funcName = iat.NameEntry.Name
			}
			lib.Funcs = append(lib.Funcs, funcName)
		}
		libs = append(libs, lib)
	}
	return libs
}
