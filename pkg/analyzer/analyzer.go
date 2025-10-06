package analyzer

import (
	"fmt"
	"strings"

	"expeer/pkg/disasm"
	"expeer/pkg/parser"
)

// Analysis contains the results of analyzing a binary
type Analysis struct {
	Binary           *parser.Binary
	DetectedLanguage string
	Confidence       float64
	Functions        []disasm.Function
	Strings          []string
	GoIndicators     []string
	CIndicators      []string
}

// Analyze performs comprehensive analysis on a binary
func Analyze(binary *parser.Binary, verbose bool) (*Analysis, error) {
	analysis := &Analysis{
		Binary: binary,
	}

	// Extract strings from all sections
	analysis.extractStrings()

	// Disassemble code sections and find functions
	err := analysis.disassembleCode(verbose)
	if err != nil && verbose {
		fmt.Printf("Warning: disassembly issues: %v\n", err)
	}

	// Detect language
	analysis.detectLanguage()

	return analysis, nil
}

// extractStrings extracts readable strings from the binary
func (a *Analysis) extractStrings() {
	for _, section := range a.Binary.Sections {
		// Look for sections that might contain strings
		if strings.Contains(strings.ToLower(section.Name), "data") ||
			strings.Contains(strings.ToLower(section.Name), "rodata") ||
			strings.Contains(strings.ToLower(section.Name), "rdata") {

			strings := extractReadableStrings(section.Data)
			a.Strings = append(a.Strings, strings...)
		}
	}
}

func extractReadableStrings(data []byte) []string {
	var result []string
	var current []byte

	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			current = append(current, b)
		} else if len(current) >= 4 { // Minimum string length
			result = append(result, string(current))
			current = nil
		} else {
			current = nil
		}
	}

	if len(current) >= 4 {
		result = append(result, string(current))
	}

	return result
}

// disassembleCode disassembles code sections
func (a *Analysis) disassembleCode(verbose bool) error {
	for _, section := range a.Binary.Sections {
		// Look for executable sections
		isCode := false
		sectionLower := strings.ToLower(section.Name)

		if strings.Contains(sectionLower, "text") ||
			strings.Contains(sectionLower, "code") {
			isCode = true
		}

		// Check flags for executable
		if section.Flags&0x20000000 != 0 || // IMAGE_SCN_MEM_EXECUTE (PE)
			section.Flags&0x4 != 0 { // SHF_EXECINSTR (ELF)
			isCode = true
		}

		if !isCode {
			continue
		}

		if verbose {
			fmt.Printf("[*] Disassembling section: %s (0x%x bytes)\n", section.Name, section.Size)
		}

		instructions, err := disasm.DisassembleSection(&section, a.Binary.Arch)
		if err != nil {
			return err
		}

		functions := disasm.FindFunctions(instructions, a.Binary.Symbols)
		a.Functions = append(a.Functions, functions...)

		if verbose {
			fmt.Printf("[*] Found %d functions in section %s\n", len(functions), section.Name)
		}
	}

	return nil
}

// detectLanguage attempts to detect if the binary was compiled from C or Go
func (a *Analysis) detectLanguage() {
	goScore := 0.0
	cScore := 0.0

	// Check symbols for Go runtime indicators
	for _, sym := range a.Binary.Symbols {
		name := strings.ToLower(sym.Name)

		// Strong Go indicators
		if strings.HasPrefix(name, "runtime.") ||
			strings.HasPrefix(name, "go.") ||
			strings.Contains(name, "golang") ||
			strings.HasPrefix(name, "type..") {
			goScore += 10.0
			a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("Symbol: %s", sym.Name))
		}

		// Go garbage collector
		if strings.Contains(name, "gc") && strings.Contains(name, "runtime") {
			goScore += 5.0
			a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("GC symbol: %s", sym.Name))
		}

		// Go scheduler
		if strings.Contains(name, "sched") || strings.Contains(name, "goroutine") {
			goScore += 5.0
			a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("Scheduler: %s", sym.Name))
		}
	}

	// Check imports for common patterns
	for _, imp := range a.Binary.Imports {
		impLower := strings.ToLower(imp)

		// C library indicators
		if strings.Contains(impLower, "libc") ||
			strings.Contains(impLower, "msvcrt") ||
			strings.Contains(impLower, "ucrtbase") ||
			impLower == "printf" || impLower == "malloc" || impLower == "free" {
			cScore += 5.0
			a.CIndicators = append(a.CIndicators, fmt.Sprintf("Import: %s", imp))
		}

		// Go typically doesn't import standard C libs directly
		if strings.Contains(impLower, "kernel32") ||
			strings.Contains(impLower, "user32") {
			// Could be either, slight preference for C
			cScore += 1.0
		}
	}

	// Check strings for language-specific patterns
	for _, str := range a.Strings {
		strLower := strings.ToLower(str)

		// Go runtime strings
		if strings.Contains(strLower, "runtime.") ||
			strings.Contains(strLower, "goroutine") ||
			strings.Contains(strLower, "go build") {
			goScore += 3.0
			a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("String: %s", str))
		}

		// Go panic/error messages
		if strings.Contains(strLower, "panic:") ||
			strings.Contains(strLower, "fatal error:") {
			goScore += 2.0
		}
	}

	// Check for Go-specific sections
	for _, section := range a.Binary.Sections {
		name := strings.ToLower(section.Name)

		if strings.Contains(name, "go.") ||
			strings.Contains(name, ".gopclntab") ||
			strings.Contains(name, ".go.buildinfo") {
			goScore += 15.0
			a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("Section: %s", section.Name))
		}

		// Typical C sections
		if name == ".bss" || name == ".data" {
			cScore += 1.0
		}
	}

	// Binary size heuristic - Go binaries are typically larger due to runtime
	if len(a.Binary.RawData) > 2*1024*1024 { // > 2MB
		goScore += 2.0
		a.GoIndicators = append(a.GoIndicators, fmt.Sprintf("Large binary size: %d MB", len(a.Binary.RawData)/(1024*1024)))
	}

	// Determine language and confidence
	total := goScore + cScore
	if total == 0 {
		a.DetectedLanguage = "c" // Default to C if no indicators
		a.Confidence = 0.3
	} else if goScore > cScore {
		a.DetectedLanguage = "go"
		a.Confidence = goScore / total
	} else {
		a.DetectedLanguage = "c"
		a.Confidence = cScore / total
	}

	// Clamp confidence
	if a.Confidence > 1.0 {
		a.Confidence = 1.0
	}
}
