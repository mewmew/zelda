package main

// StaticLib is a statically linked library.
type StaticLib struct {
	// File name of statically linked library.
	Filename string
	// Statically linked functions.
	Funcs []StaticFunc
}

// StaticFunc is a statically linked function.
type StaticFunc struct {
	// Address of statically linked function in executable.
	Addr Address
	// Function name.
	Name string
}
