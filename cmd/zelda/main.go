// Zelda is Link's companion.
package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/mewkiz/pkg/jsonutil"

	"github.com/mewkiz/pkg/pathutil"
	"github.com/mewmew/pe"
	"github.com/pkg/errors"
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: zelda [OPTION]... FILE.exe...")
	flag.PrintDefaults()
}

func main() {
	// Parse command line arguments.
	var (
		// nop address ranges.
		nops AddrRanges
		// Path to JSON file of statically linked libraries.
		staticLibsPath string
	)
	flag.Usage = usage
	flag.Var(&nops, "nop", `nop address ranges (e.g. "0x10-0x20,0x33-0x37")`)
	flag.StringVar(&staticLibsPath, "static_libs", "", "path to JSON file of statically linked libraries")
	flag.Parse()

	// Parse JSON file of statically linked functions.
	var staticLibs []StaticLib
	if len(staticLibsPath) > 0 {
		if err := jsonutil.ParseFile(staticLibsPath, &staticLibs); err != nil {
			log.Fatalf("%+v", err)
		}
	}
	for _, pePath := range flag.Args() {
		if err := relink(pePath, nops, staticLibs); err != nil {
			log.Fatalf("%+v", err)
		}
	}
}

// relink relinks the given PE file into a corresponding ELF file. If specified,
// the nop address ranges are nop'ed out, and the statically linked libraries
// are replaced with dynamic libraries.
func relink(pePath string, nops AddrRanges, staticLibs []StaticLib) error {
	// Parse PE file.
	file, err := pe.ParseFile(pePath)
	if err != nil {
		return errors.WithStack(err)
	}
	// Parse sections.
	sects := parseSects(file)
	// Parse imported libraries.
	libs := parseImports(file)
	// Add dynamic libraries of statically linked libraries.
	for _, staticLib := range staticLibs {
		lib := Library{
			Name:     libName(staticLib.Filename),
			Filename: staticLib.Filename,
		}
		for _, fn := range staticLib.Funcs {
			lib.Funcs = append(lib.Funcs, fn.Name)
		}
		libs = append(libs, lib)
	}
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
	var fs []func(w io.Writer, addr Address, buf []byte) (int, error)
	libImpsPrinter, err := getLibImpsPrinter(file)
	if err != nil {
		return errors.WithStack(err)
	}
	fs = append(fs, libImpsPrinter)
	staticLibsPrinter, err := getStaticLibsPrinter(staticLibs)
	if err != nil {
		return errors.WithStack(err)
	}
	fs = append(fs, staticLibsPrinter)
	for _, sect := range sects {
		nopSect(sect, nops)
		content, err := genSectContent(sect, fs...)
		if err != nil {
			return errors.WithStack(err)
		}
		if err := dumpSect(out, sect, prevSeg, content); err != nil {
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

// getStaticLibsPrinter returns a pretty-printed for statically linked library.
func getStaticLibsPrinter(staticLibs []StaticLib) (func(w io.Writer, addr Address, buf []byte) (int, error), error) {
	f := func(w io.Writer, addr Address, buf []byte) (int, error) {
		for _, staticLib := range staticLibs {
			for _, fn := range staticLib.Funcs {
				if fn.Addr == addr {
					if _, err := fmt.Fprintf(w, "\tjmp     plt.%s\n", fn.Name); err != nil {
						return 0, errors.WithStack(err)
					}
					// TODO: figure out how to calculate size of JMP instruction.
					return 5, nil
				}
			}
		}
		return 0, nil
	}
	return f, nil
}

// getLibImpsPrinter returns a pretty-printed for library imports.
func getLibImpsPrinter(file *pe.File) (func(w io.Writer, addr Address, buf []byte) (int, error), error) {
	// === [ Library imports ] ===
	libImpsBuf := &bytes.Buffer{}
	// Ensure that we only include libraries present in the original PE file, and
	// not any added libraries; as these will be pretty-printed to their original
	// offset in the .idata section of the PE.
	impLibs := parseImports(file)
	// Sort import libraries by their occurrence in the PE file.
	libRelAddr := make(map[string]uint32)
	for _, imp := range file.Imps {
		baseName := libName(imp.ImpDir.Name)
		libRelAddr[baseName] = imp.ImpDir.IATRelAddr
	}
	less := func(i, j int) bool {
		// Ensure that libraries present in the original PE file are sorted first, as their offset
		iv, ok1 := libRelAddr[impLibs[i].Name]
		if !ok1 {
			panic(fmt.Errorf("invalid relative import library %q, not present in original PE file", impLibs[i].Name))
		}
		jv, ok2 := libRelAddr[impLibs[j].Name]
		if !ok2 {
			panic(fmt.Errorf("invalid relative import library %q, not present in original PE file", impLibs[j].Name))
		}
		return iv < jv
	}
	sort.Slice(impLibs, less)
	for _, impLib := range impLibs {
		if err := dumpLibImps(libImpsBuf, impLib); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	// Relative address of first import entity.
	var minIATRelAddr Address
	for _, relAddr := range libRelAddr {
		iatRelAddr := Address(relAddr)
		if minIATRelAddr == 0 || iatRelAddr < minIATRelAddr {
			minIATRelAddr = iatRelAddr
		}
	}
	libImpsAddr := Address(file.OptHdr.ImageBase) + minIATRelAddr
	libImpsSize := 0
	for _, impLib := range impLibs {
		// 4 bytes per function and a terminating NULL import entry.
		libImpsSize += 4 * (len(impLib.Funcs) + 1)
	}
	// === [/ Library imports ] ===
	f := func(w io.Writer, addr Address, buf []byte) (int, error) {
		if addr == libImpsAddr {
			if _, err := libImpsBuf.WriteTo(w); err != nil {
				return 0, errors.WithStack(err)
			}
			return libImpsSize, nil
		}
		return 0, nil
	}
	return f, nil
}

// parseSects parses the sections of the given PE file into a unified format.
func parseSects(file *pe.File) []*Section {
	var sects []*Section
	for _, sectHdr := range file.SectHdrs {
		start := sectHdr.DataOffset
		end := start + sectHdr.DataSize
		data := file.Content[start:end]
		addr := Address(file.OptHdr.ImageBase) + Address(sectHdr.RelAddr)
		perm := parsePerm(sectHdr.Flags)
		sect := &Section{
			Name: sectHdr.Name,
			Data: data,
			Size: int64(sectHdr.VirtualSize),
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
		baseName := libName(imp.ImpDir.Name)
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

// nopSect nops the parts of the section contained within the given address
// ranges.
func nopSect(sect *Section, nops AddrRanges) {
	b := byte(0x00) // 0 byte.
	if sect.Perm&PermX != 0 {
		b = byte(0x90) // NOP instruction
	}
	for _, nop := range nops {
		sect.fill(nop, b)
	}
}

// libName returns the basename without extension of the given library file
// name.
func libName(filename string) string {
	filename = strings.ToLower(filename)
	// libc.so.6 -> libc
	for {
		// Trim multiple extensions, as used by symlinks.
		s := pathutil.TrimExt(filename)
		if s == filename {
			return s
		}
		filename = s
	}
}
