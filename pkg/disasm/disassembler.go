package disasm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"expeer/pkg/parser"
)

// Function represents a detected function
type Function struct {
	Name         string
	StartAddr    uint64
	EndAddr      uint64
	Instructions []Instruction
	Calls        []uint64 // Addresses of called functions
}

// DisassembleSection disassembles a code section
// Prefers Capstone if available, falls back to simple decoder
func DisassembleSection(section *parser.Section, arch string) ([]Instruction, error) {
	// Convert parser.Section to disasm.Section
	disasmSection := &Section{
		Name:    section.Name,
		Address: section.Address,
		Size:    section.Size,
		Data:    section.Data,
		Flags:   section.Flags,
	}

	// Try Capstone first
	instructions, err := DisassembleSectionWithCapstone(disasmSection, arch)
	if err == nil && len(instructions) > 0 {
		return instructions, nil
	}

	// Fallback to simple decoder if Capstone fails
	if arch != "x86_64" && arch != "x86" {
		return nil, fmt.Errorf("unsupported architecture: %s (currently only x86/x86_64 supported)", arch)
	}

	var fallbackInstructions []Instruction
	data := section.Data
	baseAddr := section.Address
	offset := 0

	// Enhanced pattern-based disassembly (fallback)
	for offset < len(data) {
		// Try enhanced decoder first
		inst, size := EnhancedDecodeInstruction(data[offset:], baseAddr+uint64(offset), arch)
		if size == 0 {
			// Try old simple decoder as last resort
			inst, size = decodeInstruction(data[offset:], baseAddr+uint64(offset), arch)
		}
		if size == 0 {
			offset++
			continue
		}

		fallbackInstructions = append(fallbackInstructions, inst)
		offset += size
	}

	return fallbackInstructions, nil
}

// decodeInstruction attempts to decode a single instruction
// This is a simplified decoder - production code should use capstone or similar
func decodeInstruction(data []byte, addr uint64, arch string) (Instruction, int) {
	if len(data) == 0 {
		return Instruction{}, 0
	}

	inst := Instruction{
		Address: addr,
	}

	// Common x86/x64 instruction patterns
	switch data[0] {
	case 0x55: // push rbp/ebp
		inst.Mnemonic = "push"
		inst.Operands = "rbp"
		inst.Size = 1
		inst.Bytes = data[:1]

	case 0x48: // REX.W prefix (64-bit)
		if len(data) < 2 {
			return Instruction{}, 0
		}
		switch data[1] {
		case 0x89: // mov
			if len(data) < 3 {
				return Instruction{}, 0
			}
			inst.Mnemonic = "mov"
			inst.Operands = decodeModRM(data[2])
			inst.Size = 3
			inst.Bytes = data[:3]
		case 0x8b: // mov (reverse direction)
			if len(data) < 3 {
				return Instruction{}, 0
			}
			inst.Mnemonic = "mov"
			inst.Operands = decodeModRM(data[2])
			inst.Size = 3
			inst.Bytes = data[:3]
		default:
			inst.Mnemonic = fmt.Sprintf("rex.w+0x%02x", data[1])
			inst.Size = 2
			inst.Bytes = data[:2]
		}

	case 0x89: // mov r/m32, r32
		if len(data) < 2 {
			return Instruction{}, 0
		}
		inst.Mnemonic = "mov"
		inst.Operands = decodeModRM(data[1])
		inst.Size = 2
		inst.Bytes = data[:2]

	case 0x8b: // mov r32, r/m32
		if len(data) < 2 {
			return Instruction{}, 0
		}
		inst.Mnemonic = "mov"
		inst.Operands = decodeModRM(data[1])
		inst.Size = 2
		inst.Bytes = data[:2]

	case 0xc3: // ret
		inst.Mnemonic = "ret"
		inst.Size = 1
		inst.Bytes = data[:1]

	case 0xe8: // call rel32
		if len(data) < 5 {
			return Instruction{}, 0
		}
		offset := int32(binary.LittleEndian.Uint32(data[1:5]))
		target := addr + uint64(offset) + 5
		inst.Mnemonic = "call"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Size = 5
		inst.Bytes = data[:5]

	case 0xff: // Various operations based on ModR/M
		if len(data) < 2 {
			return Instruction{}, 0
		}
		modrm := data[1]
		reg := (modrm >> 3) & 0x7
		if reg == 2 {
			inst.Mnemonic = "call"
		} else if reg == 4 {
			inst.Mnemonic = "jmp"
		}
		inst.Operands = decodeModRM(modrm)
		inst.Size = 2
		inst.Bytes = data[:2]

	case 0x50, 0x51, 0x52, 0x53, 0x54, 0x56, 0x57: // push r64 (excluding 0x55 which is handled above)
		inst.Mnemonic = "push"
		inst.Operands = regName(data[0]-0x50, arch)
		inst.Size = 1
		inst.Bytes = data[:1]

	case 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f: // pop r64
		inst.Mnemonic = "pop"
		inst.Operands = regName(data[0]-0x58, arch)
		inst.Size = 1
		inst.Bytes = data[:1]

	case 0x90: // nop
		inst.Mnemonic = "nop"
		inst.Size = 1
		inst.Bytes = data[:1]

	default:
		// Unknown instruction
		inst.Mnemonic = fmt.Sprintf("db 0x%02x", data[0])
		inst.Size = 1
		inst.Bytes = data[:1]
	}

	return inst, inst.Size
}

func decodeModRM(modrm byte) string {
	mod := (modrm >> 6) & 0x3
	rm := modrm & 0x7
	reg := (modrm >> 3) & 0x7

	regStr := regName(reg, "x86_64")
	rmStr := regName(rm, "x86_64")

	switch mod {
	case 0:
		return fmt.Sprintf("%s, [%s]", regStr, rmStr)
	case 1:
		return fmt.Sprintf("%s, [%s+disp8]", regStr, rmStr)
	case 2:
		return fmt.Sprintf("%s, [%s+disp32]", regStr, rmStr)
	case 3:
		return fmt.Sprintf("%s, %s", regStr, rmStr)
	}
	return "?"
}

func regName(n byte, arch string) string {
	if arch == "x86_64" {
		regs := []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"}
		if int(n) < len(regs) {
			return regs[n]
		}
	} else {
		regs := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
		if int(n) < len(regs) {
			return regs[n]
		}
	}
	return fmt.Sprintf("r%d", n)
}

// FindFunctions attempts to identify function boundaries
func FindFunctions(instructions []Instruction, symbols []parser.Symbol) []Function {
	var functions []Function

	// Create function map from symbols - these are reliable entry points
	symbolMap := make(map[uint64]string)
	symbolAddrs := make(map[uint64]bool)
	for _, sym := range symbols {
		if sym.Name != "" {
			symbolMap[sym.Address] = sym.Name
			symbolAddrs[sym.Address] = true
		}
	}

	// Find function boundaries using multiple heuristics
	var currentFunc *Function
	funcStarts := make(map[uint64]bool)

	// First pass: mark probable function starts
	for i, inst := range instructions {
		isStart := false

		// Skip padding and data sections
		if isPaddingOrData(instructions, i) {
			continue
		}

		// 1. Symbol addresses are definite starts (most reliable)
		if symbolAddrs[inst.Address] {
			isStart = true
		}

		// 2. Instruction after RET is likely a new function
		if i > 0 && instructions[i-1].Mnemonic == "ret" {
			// Skip padding/nops after return
			if inst.Mnemonic != "nop" && inst.Mnemonic != "int" &&
			   !strings.HasPrefix(inst.Mnemonic, "unk_") {
				isStart = true
			}
		}

		// 3. Traditional prologue: push rbp/ebp
		if inst.Mnemonic == "push" && (inst.Operands == "rbp" || inst.Operands == "ebp") {
			// Verify this looks like real code (not in padding area)
			if i+1 < len(instructions) && !isPaddingSequence(instructions, i, 5) {
				isStart = true
			}
		}

		// 4. Modern frame setup: sub rsp, imm
		if inst.Mnemonic == "sub" && strings.Contains(inst.Operands, "rsp") {
			// Check if previous instruction could be function start
			if i == 0 || instructions[i-1].Category == CatReturn {
				isStart = true
			}
		}

		// 5. Common function entry patterns
		if inst.Mnemonic == "mov" && strings.Contains(inst.Operands, "rsp") {
			// mov reg, rsp often starts functions
			if i == 0 || (i > 0 && instructions[i-1].Category == CatReturn) {
				isStart = true
			}
		}

		if isStart {
			funcStarts[inst.Address] = true
		}
	}

	// Second pass: create functions
	for i, inst := range instructions {
		// Start new function at marked addresses
		if funcStarts[inst.Address] {
			if currentFunc != nil {
				currentFunc.EndAddr = inst.Address - 1
				if len(currentFunc.Instructions) > 0 {
					functions = append(functions, *currentFunc)
				}
			}

			name := symbolMap[inst.Address]
			if name == "" {
				name = fmt.Sprintf("sub_%x", inst.Address)
			}

			currentFunc = &Function{
				Name:      name,
				StartAddr: inst.Address,
			}
		}

		if currentFunc != nil {
			currentFunc.Instructions = append(currentFunc.Instructions, inst)

			// Track function calls
			if inst.Mnemonic == "call" {
				currentFunc.Calls = append(currentFunc.Calls, inst.Address)
			}

			// Function epilogue: ret
			if inst.Mnemonic == "ret" {
				currentFunc.EndAddr = inst.Address
				if len(currentFunc.Instructions) > 0 {
					functions = append(functions, *currentFunc)
				}
				currentFunc = nil
			}
		}

		// Handle last function
		if i == len(instructions)-1 && currentFunc != nil {
			currentFunc.EndAddr = inst.Address
			if len(currentFunc.Instructions) > 0 {
				functions = append(functions, *currentFunc)
			}
		}
	}

	return functions
}

// isPaddingOrData detects if an instruction is likely padding or data
func isPaddingOrData(instructions []Instruction, index int) bool {
	if index >= len(instructions) {
		return false
	}

	inst := instructions[index]

	// INT 3 (0xCC) is common padding
	if inst.Mnemonic == "int" && inst.Operands == "3" {
		return true
	}

	// Long sequences of NOPs are padding
	if inst.Mnemonic == "nop" {
		// Check if surrounded by more NOPs
		nopCount := 1
		for i := index + 1; i < len(instructions) && i < index+10; i++ {
			if instructions[i].Mnemonic == "nop" {
				nopCount++
			} else {
				break
			}
		}
		if nopCount > 5 {
			return true
		}
	}

	return false
}

// isPaddingSequence checks if the next N instructions are padding
func isPaddingSequence(instructions []Instruction, start, count int) bool {
	paddingCount := 0
	for i := start; i < len(instructions) && i < start+count; i++ {
		inst := instructions[i]
		if inst.Mnemonic == "int" || inst.Mnemonic == "nop" {
			paddingCount++
		}
	}
	// If more than half are padding, it's a padding sequence
	return paddingCount > count/2
}
