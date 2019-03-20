package main

// Export is an exported symbol.
type Export struct {
	// Symbol name.
	Name string `json:"name"`
	// Address of exported symbol.
	Addr Address `json:"addr"`
}
