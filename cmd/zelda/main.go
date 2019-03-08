// Zelda is Link's companion.
package main

import (
	"flag"
	"log"

	"github.com/kr/pretty"
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
	for _, sect := range sects {
		sect.Data = nil
	}
	pretty.Println(sects)
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
