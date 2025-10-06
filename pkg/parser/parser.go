package parser

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
)

// Binary represents a parsed executable
type Binary struct {
	Format      string // "PE", "ELF", "Mach-O"
	Arch        string // "x86", "x86_64", "arm", etc.
	EntryPoint  uint64
	Sections    []Section
	Symbols     []Symbol
	Imports     []string
	Exports     []string
	RawData     []byte
	FilePath    string
}

// Section represents a section in the binary
type Section struct {
	Name    string
	Address uint64
	Size    uint64
	Data    []byte
	Flags   uint32
}

// Symbol represents a symbol in the binary
type Symbol struct {
	Name    string
	Address uint64
	Size    uint64
	Type    string
}

// ParseExecutable detects and parses the executable format
func ParseExecutable(path string) (*Binary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Detect format by magic bytes
	if len(data) < 4 {
		return nil, fmt.Errorf("file too small to be a valid executable")
	}

	// Try PE format (Windows)
	if data[0] == 'M' && data[1] == 'Z' {
		return parsePE(path, data)
	}

	// Try ELF format (Linux)
	if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return parseELF(path, data)
	}

	// Try Mach-O format (macOS)
	if len(data) >= 4 {
		magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		if magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcefaedfe || magic == 0xcffaedfe {
			return parseMachO(path, data)
		}
	}

	return nil, fmt.Errorf("unknown executable format")
}

func parsePE(path string, data []byte) (*Binary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE: %w", err)
	}
	defer f.Close()

	binary := &Binary{
		Format:   "PE",
		RawData:  data,
		FilePath: path,
	}

	// Determine architecture
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		binary.Arch = "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		binary.Arch = "x86_64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		binary.Arch = "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		binary.Arch = "arm64"
	default:
		binary.Arch = fmt.Sprintf("unknown(0x%x)", f.Machine)
	}

	// Parse sections
	for _, sec := range f.Sections {
		data, _ := sec.Data()
		binary.Sections = append(binary.Sections, Section{
			Name:    sec.Name,
			Address: uint64(sec.VirtualAddress),
			Size:    uint64(sec.Size),
			Data:    data,
			Flags:   sec.Characteristics,
		})
	}

	// Parse symbols
	for _, sym := range f.Symbols {
		binary.Symbols = append(binary.Symbols, Symbol{
			Name:    sym.Name,
			Address: uint64(sym.Value),
			Type:    fmt.Sprintf("PE_SYM_%d", sym.Type),
		})
	}

	// Parse imports
	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			binary.Imports = append(binary.Imports, imp)
		}
	}

	return binary, nil
}

func parseELF(path string, data []byte) (*Binary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF: %w", err)
	}
	defer f.Close()

	binary := &Binary{
		Format:     "ELF",
		RawData:    data,
		FilePath:   path,
		EntryPoint: f.Entry,
	}

	// Determine architecture
	switch f.Machine {
	case elf.EM_386:
		binary.Arch = "x86"
	case elf.EM_X86_64:
		binary.Arch = "x86_64"
	case elf.EM_ARM:
		binary.Arch = "arm"
	case elf.EM_AARCH64:
		binary.Arch = "arm64"
	default:
		binary.Arch = fmt.Sprintf("unknown(0x%x)", f.Machine)
	}

	// Parse sections
	for _, sec := range f.Sections {
		data, _ := sec.Data()
		binary.Sections = append(binary.Sections, Section{
			Name:    sec.Name,
			Address: sec.Addr,
			Size:    sec.Size,
			Data:    data,
			Flags:   uint32(sec.Flags),
		})
	}

	// Parse symbols
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			binary.Symbols = append(binary.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    fmt.Sprintf("ELF_SYM_%d", sym.Info),
			})
		}
	}

	// Parse dynamic symbols
	dynSyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSyms {
			binary.Symbols = append(binary.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    fmt.Sprintf("DYN_SYM_%d", sym.Info),
			})
		}
	}

	// Parse imports
	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			binary.Imports = append(binary.Imports, imp.Name)
		}
	}

	return binary, nil
}

func parseMachO(path string, data []byte) (*Binary, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mach-O: %w", err)
	}
	defer f.Close()

	binary := &Binary{
		Format:   "Mach-O",
		RawData:  data,
		FilePath: path,
	}

	// Determine architecture
	switch f.Cpu {
	case macho.Cpu386:
		binary.Arch = "x86"
	case macho.CpuAmd64:
		binary.Arch = "x86_64"
	case macho.CpuArm:
		binary.Arch = "arm"
	case macho.CpuArm64:
		binary.Arch = "arm64"
	default:
		binary.Arch = fmt.Sprintf("unknown(0x%x)", f.Cpu)
	}

	// Parse sections
	for _, sec := range f.Sections {
		data, _ := sec.Data()
		binary.Sections = append(binary.Sections, Section{
			Name:    sec.Name,
			Address: sec.Addr,
			Size:    sec.Size,
			Data:    data,
			Flags:   sec.Flags,
		})
	}

	// Parse symbols
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			binary.Symbols = append(binary.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Type:    fmt.Sprintf("MACHO_SYM_%d", sym.Type),
			})
		}
	}

	return binary, nil
}
