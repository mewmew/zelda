package main

// Library is a shared library.
type Library struct {
	// Library name.
	Name string
	// Library file name.
	Filename string
	// Imported functions.
	Funcs []string
}
