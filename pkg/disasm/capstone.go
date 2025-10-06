package disasm

import (
	"fmt"
)

// Capstone integration stub
// TODO: Install Capstone library and uncomment the integration
// Instructions:
// 1. Install Capstone: https://www.capstone-engine.org/download.html
// 2. go get github.com/knightsc/gapstone
// 3. Uncomment the Capstone implementation in capstone_impl.go

// CapstoneDisassembler provides professional-grade disassembly using Capstone
// Currently stubbed - install Capstone to enable
type CapstoneDisassembler struct {
	arch string
}

// NewCapstoneDisassembler creates a new Capstone-based disassembler
func NewCapstoneDisassembler(arch string) (*CapstoneDisassembler, error) {
	return nil, fmt.Errorf("Capstone not available - install from https://www.capstone-engine.org")
}

// Close releases Capstone resources
func (cd *CapstoneDisassembler) Close() error {
	return nil
}

// Disassemble disassembles code bytes starting at the given address
func (cd *CapstoneDisassembler) Disassemble(code []byte, address uint64) ([]Instruction, error) {
	return nil, fmt.Errorf("Capstone not available")
}

// DisassembleSectionWithCapstone disassembles a section using Capstone
// Returns error if Capstone is not installed
func DisassembleSectionWithCapstone(section *Section, arch string) ([]Instruction, error) {
	return nil, fmt.Errorf("Capstone not installed - using fallback disassembler")
}
