package disasm

import (
	"encoding/binary"
	"fmt"
)

// EnhancedDecodeInstruction provides significantly improved x86/x64 decoding
// Handles 100+ common instruction patterns
func EnhancedDecodeInstruction(data []byte, addr uint64, arch string) (Instruction, int) {
	if len(data) == 0 {
		return Instruction{}, 0
	}

	inst := Instruction{
		Address: addr,
	}

	is64bit := (arch == "x86_64")
	offset := 0

	// Handle prefixes
	rexW := false
	for offset < len(data) && offset < 4 {
		switch data[offset] {
		case 0xF0: // LOCK prefix
			offset++
		case 0xF2: // REPNE/REPNZ prefix
			offset++
		case 0xF3: // REP/REPE/REPZ prefix
			offset++
		case 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65: // Segment overrides
			offset++
		case 0x66: // Operand size override
			offset++
		case 0x67: // Address size override
			offset++
		default:
			// Check for REX prefix (0x40-0x4F in 64-bit mode)
			if is64bit && data[offset] >= 0x40 && data[offset] <= 0x4F {
				rexW = (data[offset] & 0x08) != 0
				offset++
			}
			goto prefixes_done
		}
	}

prefixes_done:
	if offset >= len(data) {
		return Instruction{}, 0
	}

	opcode := data[offset]
	offset++

	switch opcode {
	// Push/Pop instructions
	case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57: // PUSH r64
		inst.Mnemonic = "push"
		inst.Operands = regName64(int(opcode-0x50), rexW)
		inst.Category = CatStack
		inst.RegsRead = []string{inst.Operands}

	case 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F: // POP r64
		inst.Mnemonic = "pop"
		inst.Operands = regName64(int(opcode-0x58), rexW)
		inst.Category = CatStack
		inst.RegsWritten = []string{inst.Operands}

	// MOV instructions
	case 0x88, 0x89, 0x8A, 0x8B: // MOV r/m, r
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "mov"
		inst.Category = CatDataTransfer
		// Decode ModR/M
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7: // MOV r8, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("%s, 0x%x", regName8(int(opcode-0xB0)), data[offset])
		inst.Category = CatDataTransfer
		offset++

	case 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF: // MOV r32/r64, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("%s, 0x%x", regName64(int(opcode-0xB8), rexW), imm)
		inst.Category = CatDataTransfer
		offset += 4

	// Arithmetic instructions
	case 0x01, 0x03: // ADD
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "add"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	case 0x29, 0x2B: // SUB
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "sub"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	// Logic instructions
	case 0x21, 0x23: // AND
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "and"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	case 0x09, 0x0B: // OR
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "or"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	case 0x31, 0x33: // XOR
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "xor"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	// Compare and test
	case 0x39, 0x3B: // CMP
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "cmp"
		inst.Category = CatCompare
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if opcode&0x02 != 0 {
			inst.Operands = fmt.Sprintf("%s, %s", src, dest)
		} else {
			inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		}

	case 0x85: // TEST
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "test"
		inst.Category = CatCompare
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// Jumps
	case 0xE9: // JMP rel32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		rel := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		target := uint64(int64(addr) + int64(offset+4) + int64(rel))
		inst.Mnemonic = "jmp"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsBranch = true
		inst.BranchTarget = target
		offset += 4

	case 0xEB: // JMP rel8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := uint64(int64(addr) + int64(offset+1) + int64(rel))
		inst.Mnemonic = "jmp"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsBranch = true
		inst.BranchTarget = target
		offset++

	case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F: // Jcc rel8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := uint64(int64(addr) + int64(offset+1) + int64(rel))
		inst.Mnemonic = jccMnemonic(opcode)
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsConditional = true
		inst.IsBranch = true
		inst.BranchTarget = target
		inst.FallsThrough = true
		offset++

	case 0x0F: // Two-byte opcodes
		if offset >= len(data) {
			return Instruction{}, 0
		}
		opcode2 := data[offset]
		offset++

		switch opcode2 {
		// Conditional jumps (32-bit relative)
		case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
			0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F:
			if offset+4 > len(data) {
				return Instruction{}, 0
			}
			rel := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
			target := uint64(int64(addr) + int64(offset+4) + int64(rel))
			inst.Mnemonic = jccMnemonic(opcode2 - 0x10)
			inst.Operands = fmt.Sprintf("0x%x", target)
			inst.Category = CatJump
			inst.IsConditional = true
			inst.IsBranch = true
			inst.BranchTarget = target
			inst.FallsThrough = true
			offset += 4

		// SETcc - Set byte on condition
		case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
			0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "set" + jccMnemonic(opcode2-0x90)[1:] // setcc
			inst.Category = CatDataTransfer
			offset++

		// CMOVcc - Conditional move
		case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "cmov" + jccMnemonic(opcode2-0x40)[1:]
			inst.Category = CatDataTransfer
			offset++

		// MOVZX - Move with zero extend
		case 0xB6, 0xB7:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "movzx"
			inst.Category = CatDataTransfer
			offset++

		// MOVSX - Move with sign extend
		case 0xBE, 0xBF:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "movsx"
			inst.Category = CatDataTransfer
			offset++

		// BSF/BSR - Bit scan
		case 0xBC, 0xBD:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			if opcode2 == 0xBC {
				inst.Mnemonic = "bsf"
			} else {
				inst.Mnemonic = "bsr"
			}
			inst.Category = CatLogical
			offset++

		// BT/BTS/BTR/BTC - Bit test
		case 0xA3: // BT
			inst.Mnemonic = "bt"
			inst.Category = CatLogical
		case 0xAB: // BTS
			inst.Mnemonic = "bts"
			inst.Category = CatLogical
		case 0xB3: // BTR
			inst.Mnemonic = "btr"
			inst.Category = CatLogical
		case 0xBB: // BTC
			inst.Mnemonic = "btc"
			inst.Category = CatLogical

		// IMUL - Extended multiply
		case 0xAF:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "imul"
			inst.Category = CatArithmetic
			offset++

		// XADD - Exchange and add
		case 0xC0, 0xC1:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "xadd"
			inst.Category = CatArithmetic
			offset++

		// CMPXCHG - Compare and exchange
		case 0xB0, 0xB1:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "cmpxchg"
			inst.Category = CatArithmetic
			offset++

		// BSWAP - Byte swap
		case 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF:
			inst.Mnemonic = "bswap"
			inst.Operands = regName64(int(opcode2-0xC8), rexW)
			inst.Category = CatDataTransfer

		// MOVD/MOVQ - Move to/from MMX/SSE
		case 0x6E, 0x7E:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "movd"
			inst.Category = CatDataTransfer
			offset++

		// MOVUPS/MOVAPS - Move unaligned/aligned packed single
		case 0x10, 0x11, 0x28, 0x29:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			if opcode2 == 0x10 || opcode2 == 0x11 {
				inst.Mnemonic = "movups"
			} else {
				inst.Mnemonic = "movaps"
			}
			inst.Category = CatDataTransfer
			offset++

		// XORPS/XORPD - XOR packed single/double
		case 0x57:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "xorps"
			inst.Category = CatLogical
			offset++

		// ADDSD/ADDSS/SUBSD/SUBSS - SSE arithmetic
		case 0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			switch opcode2 {
			case 0x58:
				inst.Mnemonic = "addps"
			case 0x59:
				inst.Mnemonic = "mulps"
			case 0x5C:
				inst.Mnemonic = "subps"
			case 0x5D:
				inst.Mnemonic = "minps"
			case 0x5E:
				inst.Mnemonic = "divps"
			case 0x5F:
				inst.Mnemonic = "maxps"
			}
			inst.Category = CatArithmetic
			offset++

		// PCMPEQ - Packed compare equal
		case 0x74, 0x75, 0x76:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "pcmpeq"
			inst.Category = CatCompare
			offset++

		// MOVNTI - Move non-temporal integer
		case 0xC3:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "movnti"
			inst.Category = CatDataTransfer
			offset++

		// PREFETCH - Prefetch
		case 0x18:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			inst.Mnemonic = "prefetch"
			inst.Category = CatOther
			offset++

		// UD2 - Undefined instruction (intentional)
		case 0x0B:
			inst.Mnemonic = "ud2"
			inst.Category = CatInterrupt

		// LFENCE/MFENCE/SFENCE - Memory barriers
		case 0xAE:
			if offset >= len(data) {
				return Instruction{}, 0
			}
			modrm := data[offset]
			reg := (modrm >> 3) & 0x7
			switch reg {
			case 5:
				inst.Mnemonic = "lfence"
			case 6:
				inst.Mnemonic = "mfence"
			case 7:
				inst.Mnemonic = "sfence"
			default:
				inst.Mnemonic = "0f_ae"
			}
			inst.Category = CatOther
			offset++

		// NOP variants (multi-byte)
		case 0x1F, 0x0D:
			inst.Mnemonic = "nop"
			inst.Category = CatNop
			if offset < len(data) {
				offset++ // Skip ModRM
			}

		default:
			inst.Mnemonic = fmt.Sprintf("0f_%02x", opcode2)
			inst.Category = CatUnknown
		}

	// Call
	case 0xE8: // CALL rel32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		rel := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		target := uint64(int64(addr) + int64(offset+4) + int64(rel))
		inst.Mnemonic = "call"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatCall
		inst.IsBranch = true
		inst.BranchTarget = target
		inst.FallsThrough = true
		offset += 4

	case 0xFF: // Various (CALL/JMP indirect, INC, DEC)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		reg := (modrm >> 3) & 0x7
		offset++

		switch reg {
		case 0, 1: // INC/DEC
			if reg == 0 {
				inst.Mnemonic = "inc"
			} else {
				inst.Mnemonic = "dec"
			}
			inst.Category = CatArithmetic
		case 2: // CALL r/m
			inst.Mnemonic = "call"
			inst.Category = CatCall
			inst.FallsThrough = true
		case 4: // JMP r/m
			inst.Mnemonic = "jmp"
			inst.Category = CatJump
			inst.IsBranch = true
		default:
			inst.Mnemonic = "ff_op"
		}

	// Return
	case 0xC3: // RET
		inst.Mnemonic = "ret"
		inst.Category = CatReturn

	case 0xC2: // RET imm16
		if offset+2 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint16(data[offset : offset+2])
		inst.Mnemonic = "ret"
		inst.Operands = fmt.Sprintf("0x%x", imm)
		inst.Category = CatReturn
		offset += 2

	// LEA
	case 0x8D: // LEA
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "lea"
		inst.Category = CatDataTransfer
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// NOP
	case 0x90:
		inst.Mnemonic = "nop"
		inst.Category = CatNop

	// String operations
	case 0xA4: // MOVSB
		inst.Mnemonic = "movsb"
		inst.Category = CatDataTransfer
	case 0xA5: // MOVSD/MOVSQ
		inst.Mnemonic = "movs"
		inst.Category = CatDataTransfer
	case 0xA6: // CMPSB
		inst.Mnemonic = "cmpsb"
		inst.Category = CatCompare
	case 0xA7: // CMPSD/CMPSQ
		inst.Mnemonic = "cmps"
		inst.Category = CatCompare
	case 0xAA: // STOSB
		inst.Mnemonic = "stosb"
		inst.Category = CatDataTransfer
	case 0xAB: // STOSD/STOSQ
		inst.Mnemonic = "stos"
		inst.Category = CatDataTransfer
	case 0xAC: // LODSB
		inst.Mnemonic = "lodsb"
		inst.Category = CatDataTransfer
	case 0xAD: // LODSD/LODSQ
		inst.Mnemonic = "lods"
		inst.Category = CatDataTransfer
	case 0xAE: // SCASB
		inst.Mnemonic = "scasb"
		inst.Category = CatCompare
	case 0xAF: // SCASD/SCASQ
		inst.Mnemonic = "scas"
		inst.Category = CatCompare

	// INC/DEC (one-byte forms, 32-bit mode)
	case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47: // INC (if not REX in 64-bit)
		if !is64bit {
			inst.Mnemonic = "inc"
			inst.Operands = regName64(int(opcode-0x40), false)
			inst.Category = CatArithmetic
		} else {
			// In 64-bit mode, these are REX prefixes, should have been handled
			inst.Mnemonic = "rex"
			inst.Category = CatOther
		}

	case 0x48: // Handled earlier as REX.W prefix in 64-bit
		// If we get here, it wasn't handled as prefix
		if !is64bit {
			inst.Mnemonic = "dec"
			inst.Operands = "eax"
			inst.Category = CatArithmetic
		}

	// XCHG
	case 0x86, 0x87: // XCHG r/m8, r8 or r/m, r
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "xchg"
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)
		inst.Category = CatDataTransfer

	case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97: // XCHG rAX, r
		inst.Mnemonic = "xchg"
		inst.Operands = fmt.Sprintf("%s, %s", regName64(0, rexW), regName64(int(opcode-0x90), rexW))
		inst.Category = CatDataTransfer

	// LAHF/SAHF
	case 0x9E: // SAHF
		inst.Mnemonic = "sahf"
		inst.Category = CatDataTransfer
	case 0x9F: // LAHF
		inst.Mnemonic = "lahf"
		inst.Category = CatDataTransfer

	// CBW/CWDE/CDQE
	case 0x98:
		if rexW {
			inst.Mnemonic = "cdqe"
		} else {
			inst.Mnemonic = "cwde"
		}
		inst.Category = CatDataTransfer
	case 0x99: // CWD/CDQ/CQO
		if rexW {
			inst.Mnemonic = "cqo"
		} else {
			inst.Mnemonic = "cdq"
		}
		inst.Category = CatDataTransfer

	// Shift/Rotate group
	case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		reg := (modrm >> 3) & 0x7
		offset++

		switch reg {
		case 0:
			inst.Mnemonic = "rol"
		case 1:
			inst.Mnemonic = "ror"
		case 2:
			inst.Mnemonic = "rcl"
		case 3:
			inst.Mnemonic = "rcr"
		case 4:
			inst.Mnemonic = "shl"
		case 5:
			inst.Mnemonic = "shr"
		case 7:
			inst.Mnemonic = "sar"
		default:
			inst.Mnemonic = "shift_op"
		}
		inst.Category = CatLogical

		// Handle immediate
		if opcode == 0xC0 || opcode == 0xC1 {
			if offset < len(data) {
				offset++
			}
		}

	// Group 3 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
	case 0xF6, 0xF7:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		reg := (modrm >> 3) & 0x7
		offset++

		switch reg {
		case 0, 1: // TEST
			inst.Mnemonic = "test"
			inst.Category = CatCompare
			if opcode == 0xF6 {
				offset++ // imm8
			} else {
				offset += 4 // imm32
			}
		case 2: // NOT
			inst.Mnemonic = "not"
			inst.Category = CatLogical
		case 3: // NEG
			inst.Mnemonic = "neg"
			inst.Category = CatArithmetic
		case 4: // MUL
			inst.Mnemonic = "mul"
			inst.Category = CatArithmetic
		case 5: // IMUL
			inst.Mnemonic = "imul"
			inst.Category = CatArithmetic
		case 6: // DIV
			inst.Mnemonic = "div"
			inst.Category = CatArithmetic
		case 7: // IDIV
			inst.Mnemonic = "idiv"
			inst.Category = CatArithmetic
		}

	// ENTER/LEAVE
	case 0xC8: // ENTER
		if offset+2 < len(data) {
			inst.Mnemonic = "enter"
			inst.Category = CatStack
			offset += 3
		}
	case 0xC9: // LEAVE
		inst.Mnemonic = "leave"
		inst.Category = CatStack

	// HLT/WAIT
	case 0xF4: // HLT
		inst.Mnemonic = "hlt"
		inst.Category = CatInterrupt
	case 0x9B: // WAIT/FWAIT
		inst.Mnemonic = "wait"
		inst.Category = CatOther

	// PUSHF/POPF
	case 0x9C: // PUSHF/PUSHFQ
		inst.Mnemonic = "pushf"
		inst.Category = CatStack
	case 0x9D: // POPF/POPFQ
		inst.Mnemonic = "popf"
		inst.Category = CatStack

	// CLC/STC/CLI/STI/CLD/STD
	case 0xF8: // CLC
		inst.Mnemonic = "clc"
		inst.Category = CatOther
	case 0xF9: // STC
		inst.Mnemonic = "stc"
		inst.Category = CatOther
	case 0xFA: // CLI
		inst.Mnemonic = "cli"
		inst.Category = CatOther
	case 0xFB: // STI
		inst.Mnemonic = "sti"
		inst.Category = CatOther
	case 0xFC: // CLD
		inst.Mnemonic = "cld"
		inst.Category = CatOther
	case 0xFD: // STD
		inst.Mnemonic = "std"
		inst.Category = CatOther

	// INT
	case 0xCC: // INT 3
		inst.Mnemonic = "int"
		inst.Operands = "3"
		inst.Category = CatInterrupt

	case 0xCD: // INT imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "int"
		inst.Operands = fmt.Sprintf("0x%x", data[offset])
		inst.Category = CatInterrupt
		offset++

	// INTO/IRET
	case 0xCE: // INTO
		inst.Mnemonic = "into"
		inst.Category = CatInterrupt
	case 0xCF: // IRET
		inst.Mnemonic = "iret"
		inst.Category = CatReturn

	// Additional basic arithmetic operations (missing byte variants)
	// ADD r/m8, r8
	case 0x00:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "add"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// ADD r8, r/m8
	case 0x02:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "add"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// OR r/m8, r8
	case 0x08:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "or"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// OR r8, r/m8
	case 0x0A:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "or"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// ADC r/m8, r8 / ADC r/m, r
	case 0x10, 0x11:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "adc"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// ADC r8, r/m8 / ADC r, r/m
	case 0x12, 0x13:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "adc"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// SBB r/m8, r8 / SBB r/m, r
	case 0x18, 0x19:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "sbb"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// SBB r8, r/m8 / SBB r, r/m
	case 0x1A, 0x1B:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "sbb"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// AND r/m8, r8
	case 0x20:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "and"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// AND r8, r/m8
	case 0x22:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "and"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// SUB r/m8, r8
	case 0x28:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "sub"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// SUB r8, r/m8
	case 0x2A:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "sub"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// XOR r/m8, r8
	case 0x30:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "xor"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// XOR r8, r/m8
	case 0x32:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "xor"
		inst.Category = CatLogical
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// CMP r/m8, r8
	case 0x38:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "cmp"
		inst.Category = CatCompare
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// CMP r8, r/m8
	case 0x3A:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "cmp"
		inst.Category = CatCompare
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", src, dest)

	// Group 1: Immediate arithmetic/logical operations
	// These are very common and decode the operation from ModR/M reg field
	case 0x80, 0x81, 0x82, 0x83:
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		reg := (modrm >> 3) & 0x7

		// Determine operation from reg field
		var mnemonic string
		switch reg {
		case 0:
			mnemonic = "add"
		case 1:
			mnemonic = "or"
		case 2:
			mnemonic = "adc"
		case 3:
			mnemonic = "sbb"
		case 4:
			mnemonic = "and"
		case 5:
			mnemonic = "sub"
		case 6:
			mnemonic = "xor"
		case 7:
			mnemonic = "cmp"
		}

		inst.Mnemonic = mnemonic
		if mnemonic == "cmp" {
			inst.Category = CatCompare
		} else if mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" {
			inst.Category = CatLogical
		} else {
			inst.Category = CatArithmetic
		}

		// Decode r/m
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)

		// Get immediate value
		var imm uint32
		if opcode == 0x80 || opcode == 0x82 { // imm8
			if offset >= len(data) {
				return Instruction{}, 0
			}
			imm = uint32(data[offset])
			offset++
		} else if opcode == 0x83 { // imm8 sign-extended
			if offset >= len(data) {
				return Instruction{}, 0
			}
			imm = uint32(int8(data[offset])) // Sign extend
			offset++
		} else { // 0x81: imm16/32
			if offset+4 > len(data) {
				return Instruction{}, 0
			}
			imm = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
		}

		inst.Operands = fmt.Sprintf("%s, 0x%x", dest, imm)

	// Accumulator-specific forms (compact encodings using AL/AX/EAX/RAX)
	case 0x04: // ADD AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "add"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0x0C: // OR AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "or"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatLogical
		offset++

	case 0x14: // ADC AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "adc"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0x1C: // SBB AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "sbb"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0x24: // AND AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "and"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatLogical
		offset++

	case 0x2C: // SUB AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "sub"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0x34: // XOR AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "xor"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatLogical
		offset++

	case 0x3C: // CMP AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "cmp"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatCompare
		offset++

	// 32-bit accumulator forms
	case 0x05: // ADD EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "add"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatArithmetic
		offset += 4

	case 0x0D: // OR EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "or"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatLogical
		offset += 4

	case 0x25: // AND EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "and"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatLogical
		offset += 4

	case 0x2D: // SUB EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "sub"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatArithmetic
		offset += 4

	case 0x35: // XOR EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "xor"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatLogical
		offset += 4

	case 0x3D: // CMP EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "cmp"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatCompare
		offset += 4

	case 0x15: // ADC EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "adc"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatArithmetic
		offset += 4

	case 0x1D: // SBB EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "sbb"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatArithmetic
		offset += 4

	// TEST instruction
	case 0x84: // TEST r/m8, r8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "test"
		inst.Category = CatCompare
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// MOV with immediate
	case 0xC6: // MOV r/m8, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "mov"
		inst.Category = CatDataTransfer
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		imm := data[offset]
		offset++
		inst.Operands = fmt.Sprintf("%s, 0x%x", dest, imm)

	case 0xC7: // MOV r/m16/32/64, imm16/32
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "mov"
		inst.Category = CatDataTransfer
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		inst.Operands = fmt.Sprintf("%s, 0x%x", dest, imm)

	// PUSH immediate
	case 0x68: // PUSH imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "push"
		inst.Operands = fmt.Sprintf("0x%x", imm)
		inst.Category = CatStack
		offset += 4

	case 0x6A: // PUSH imm8 (sign-extended)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "push"
		inst.Operands = fmt.Sprintf("0x%x", int8(data[offset]))
		inst.Category = CatStack
		offset++

	// Segment register operations (legacy but still used)
	case 0x06: // PUSH ES
		inst.Mnemonic = "push"
		inst.Operands = "es"
		inst.Category = CatStack

	case 0x07: // POP ES
		inst.Mnemonic = "pop"
		inst.Operands = "es"
		inst.Category = CatStack

	case 0x0E: // PUSH CS
		inst.Mnemonic = "push"
		inst.Operands = "cs"
		inst.Category = CatStack

	case 0x16: // PUSH SS
		inst.Mnemonic = "push"
		inst.Operands = "ss"
		inst.Category = CatStack

	case 0x17: // POP SS
		inst.Mnemonic = "pop"
		inst.Operands = "ss"
		inst.Category = CatStack

	case 0x1E: // PUSH DS
		inst.Mnemonic = "push"
		inst.Operands = "ds"
		inst.Category = CatStack

	case 0x1F: // POP DS
		inst.Mnemonic = "pop"
		inst.Operands = "ds"
		inst.Category = CatStack

	// IMUL with immediate
	case 0x69: // IMUL r, r/m, imm32
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "imul"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		inst.Operands = fmt.Sprintf("%s, %s, 0x%x", dest, src, imm)

	case 0x6B: // IMUL r, r/m, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "imul"
		inst.Category = CatArithmetic
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		imm := int8(data[offset])
		offset++
		inst.Operands = fmt.Sprintf("%s, %s, 0x%x", dest, src, imm)

	// INC/DEC byte variants
	case 0xFE: // INC/DEC r/m8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		reg := (modrm >> 3) & 0x7
		if reg == 0 {
			inst.Mnemonic = "inc"
		} else if reg == 1 {
			inst.Mnemonic = "dec"
		} else {
			inst.Mnemonic = "fe_op"
		}
		inst.Category = CatArithmetic
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = dest

	// Loop instructions
	case 0xE0: // LOOPNE/LOOPNZ
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := addr + uint64(rel) + 2
		inst.Mnemonic = "loopne"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsBranch = true
		inst.BranchTarget = target
		offset++

	case 0xE1: // LOOPE/LOOPZ
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := addr + uint64(rel) + 2
		inst.Mnemonic = "loope"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsBranch = true
		inst.BranchTarget = target
		offset++

	case 0xE2: // LOOP
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := addr + uint64(rel) + 2
		inst.Mnemonic = "loop"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsBranch = true
		inst.BranchTarget = target
		offset++

	case 0xE3: // JCXZ/JECXZ/JRCXZ
		if offset >= len(data) {
			return Instruction{}, 0
		}
		rel := int8(data[offset])
		target := addr + uint64(rel) + 2
		inst.Mnemonic = "jrcxz"
		inst.Operands = fmt.Sprintf("0x%x", target)
		inst.Category = CatJump
		inst.IsConditional = true
		inst.IsBranch = true
		inst.BranchTarget = target
		offset++

	// Stack operations
	case 0x60: // PUSHA/PUSHAD
		inst.Mnemonic = "pusha"
		inst.Category = CatStack

	case 0x61: // POPA/POPAD
		inst.Mnemonic = "popa"
		inst.Category = CatStack

	case 0x62: // BOUND r, m (legacy)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "bound"
		inst.Category = CatOther
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	case 0x63: // ARPL (16-bit) or MOVSXD (64-bit)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		if rexW {
			inst.Mnemonic = "movsxd"
		} else {
			inst.Mnemonic = "arpl"
		}
		inst.Category = CatDataTransfer
		dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, src)

	// String I/O instructions
	case 0x6C: // INSB
		inst.Mnemonic = "insb"
		inst.Category = CatOther

	case 0x6D: // INSD
		inst.Mnemonic = "insd"
		inst.Category = CatOther

	case 0x6E: // OUTSB
		inst.Mnemonic = "outsb"
		inst.Category = CatOther

	case 0x6F: // OUTSD
		inst.Mnemonic = "outsd"
		inst.Category = CatOther

	// Segment move
	case 0x8C: // MOV r/m, Sreg
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "mov"
		inst.Category = CatDataTransfer
		sreg := (modrm >> 3) & 0x7
		sregs := []string{"es", "cs", "ss", "ds", "fs", "gs", "seg6", "seg7"}
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", dest, sregs[sreg])

	case 0x8E: // MOV Sreg, r/m
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "mov"
		inst.Category = CatDataTransfer
		sreg := (modrm >> 3) & 0x7
		sregs := []string{"es", "cs", "ss", "ds", "fs", "gs", "seg6", "seg7"}
		_, src := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = fmt.Sprintf("%s, %s", sregs[sreg], src)

	case 0x8F: // POP r/m
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "pop"
		inst.Category = CatStack
		dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
		inst.Operands = dest

	// TEST AL, imm8
	case 0xA8: // TEST AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "test"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatCompare
		offset++

	case 0xA9: // TEST EAX, imm32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "test"
		inst.Operands = fmt.Sprintf("eax, 0x%x", imm)
		inst.Category = CatCompare
		offset += 4

	// MOV AL/AX/EAX, moffs
	case 0xA0: // MOV AL, moffs8
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		moffs := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("al, [0x%x]", moffs)
		inst.Category = CatDataTransfer
		offset += 4

	case 0xA1: // MOV EAX, moffs32
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		moffs := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("eax, [0x%x]", moffs)
		inst.Category = CatDataTransfer
		offset += 4

	case 0xA2: // MOV moffs8, AL
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		moffs := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("[0x%x], al", moffs)
		inst.Category = CatDataTransfer
		offset += 4

	case 0xA3: // MOV moffs32, EAX
		if offset+4 > len(data) {
			return Instruction{}, 0
		}
		moffs := binary.LittleEndian.Uint32(data[offset : offset+4])
		inst.Mnemonic = "mov"
		inst.Operands = fmt.Sprintf("[0x%x], eax", moffs)
		inst.Category = CatDataTransfer
		offset += 4

	// Far returns
	case 0xCA: // RETF imm16
		if offset+2 > len(data) {
			return Instruction{}, 0
		}
		imm := binary.LittleEndian.Uint16(data[offset : offset+2])
		inst.Mnemonic = "retf"
		inst.Operands = fmt.Sprintf("0x%x", imm)
		inst.Category = CatReturn
		offset += 2

	case 0xCB: // RETF
		inst.Mnemonic = "retf"
		inst.Category = CatReturn

	// Legacy/BCD instructions
	case 0x27: // DAA
		inst.Mnemonic = "daa"
		inst.Category = CatArithmetic

	case 0x2F: // DAS
		inst.Mnemonic = "das"
		inst.Category = CatArithmetic

	case 0x37: // AAA
		inst.Mnemonic = "aaa"
		inst.Category = CatArithmetic

	case 0x3F: // AAS
		inst.Mnemonic = "aas"
		inst.Category = CatArithmetic

	case 0xD4: // AAM
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "aam"
		inst.Operands = fmt.Sprintf("0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0xD5: // AAD
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "aad"
		inst.Operands = fmt.Sprintf("0x%x", data[offset])
		inst.Category = CatArithmetic
		offset++

	case 0xD6: // SALC (undocumented)
		inst.Mnemonic = "salc"
		inst.Category = CatOther

	case 0xD7: // XLAT/XLATB
		inst.Mnemonic = "xlat"
		inst.Category = CatDataTransfer

	// Far call/jump
	case 0x9A: // CALLF ptr16:32
		if offset+6 > len(data) {
			return Instruction{}, 0
		}
		offs := binary.LittleEndian.Uint32(data[offset : offset+4])
		seg := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		inst.Mnemonic = "callf"
		inst.Operands = fmt.Sprintf("0x%x:0x%x", seg, offs)
		inst.Category = CatCall
		offset += 6

	case 0xEA: // JMPF ptr16:32
		if offset+6 > len(data) {
			return Instruction{}, 0
		}
		offs := binary.LittleEndian.Uint32(data[offset : offset+4])
		seg := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		inst.Mnemonic = "jmpf"
		inst.Operands = fmt.Sprintf("0x%x:0x%x", seg, offs)
		inst.Category = CatJump
		offset += 6

	// I/O instructions
	case 0xE4: // IN AL, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "in"
		inst.Operands = fmt.Sprintf("al, 0x%x", data[offset])
		inst.Category = CatOther
		offset++

	case 0xE5: // IN EAX, imm8
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "in"
		inst.Operands = fmt.Sprintf("eax, 0x%x", data[offset])
		inst.Category = CatOther
		offset++

	case 0xE6: // OUT imm8, AL
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "out"
		inst.Operands = fmt.Sprintf("0x%x, al", data[offset])
		inst.Category = CatOther
		offset++

	case 0xE7: // OUT imm8, EAX
		if offset >= len(data) {
			return Instruction{}, 0
		}
		inst.Mnemonic = "out"
		inst.Operands = fmt.Sprintf("0x%x, eax", data[offset])
		inst.Category = CatOther
		offset++

	case 0xEC: // IN AL, DX
		inst.Mnemonic = "in"
		inst.Operands = "al, dx"
		inst.Category = CatOther

	case 0xED: // IN EAX, DX
		inst.Mnemonic = "in"
		inst.Operands = "eax, dx"
		inst.Category = CatOther

	case 0xEE: // OUT DX, AL
		inst.Mnemonic = "out"
		inst.Operands = "dx, al"
		inst.Category = CatOther

	case 0xEF: // OUT DX, EAX
		inst.Mnemonic = "out"
		inst.Operands = "dx, eax"
		inst.Category = CatOther

	// Flag operations
	case 0xF1: // INT1 / ICEBP
		inst.Mnemonic = "int1"
		inst.Category = CatInterrupt

	case 0xF5: // CMC
		inst.Mnemonic = "cmc"
		inst.Category = CatOther

	// VEX prefixes (AVX) - basic recognition
	case 0xC4: // VEX 3-byte prefix or LES
		if offset >= len(data) {
			// Could be LES in 32-bit mode
			inst.Mnemonic = "vex_c4"
			inst.Category = CatOther
		} else {
			// Check if it's VEX
			if data[offset] >= 0xC0 {
				inst.Mnemonic = "vex3"
				inst.Category = CatOther
				offset += 2 // Skip VEX bytes for now
			} else {
				// LES r, m
				modrm := data[offset]
				offset++
				inst.Mnemonic = "les"
				inst.Category = CatDataTransfer
				dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
				inst.Operands = fmt.Sprintf("%s, %s", dest, src)
			}
		}

	case 0xC5: // VEX 2-byte prefix or LDS
		if offset >= len(data) {
			inst.Mnemonic = "vex_c5"
			inst.Category = CatOther
		} else {
			// Check if it's VEX
			if data[offset] >= 0xC0 {
				inst.Mnemonic = "vex2"
				inst.Category = CatOther
				offset++ // Skip VEX byte
			} else {
				// LDS r, m
				modrm := data[offset]
				offset++
				inst.Mnemonic = "lds"
				inst.Category = CatDataTransfer
				dest, src := decodeModRMDetailed(modrm, data[offset:], rexW)
				inst.Operands = fmt.Sprintf("%s, %s", dest, src)
			}
		}

	// x87 FPU Instructions (basic recognition)
	case 0xD8: // FPU: FADD, FMUL, FCOM, FCOMP, FSUB, FSUBR, FDIV, FDIVR
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "fpu_d8" // Simplified for now
		inst.Category = CatOther
		inst.Operands = fmt.Sprintf("0x%02x", modrm)

	case 0xD9: // FPU: FLD, FST, FSTP, FLDENV, FLDCW, FSTENV, FSTCW
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		// Check for common patterns
		if modrm >= 0xC0 {
			// Register forms
			switch modrm {
			case 0xE0:
				inst.Mnemonic = "fchs"
			case 0xE1:
				inst.Mnemonic = "fabs"
			case 0xE4:
				inst.Mnemonic = "ftst"
			case 0xE8:
				inst.Mnemonic = "fld1"
			case 0xE9:
				inst.Mnemonic = "fldl2t"
			case 0xEA:
				inst.Mnemonic = "fldl2e"
			case 0xEB:
				inst.Mnemonic = "fldpi"
			case 0xEC:
				inst.Mnemonic = "fldlg2"
			case 0xED:
				inst.Mnemonic = "fldln2"
			case 0xEE:
				inst.Mnemonic = "fldz"
			default:
				inst.Mnemonic = "fpu_d9"
				inst.Operands = fmt.Sprintf("0x%02x", modrm)
			}
		} else {
			inst.Mnemonic = "fld"
			dest, _ := decodeModRMDetailed(modrm, data[offset:], rexW)
			inst.Operands = dest
		}
		inst.Category = CatOther

	case 0xDA: // FPU: FIADD, FIMUL, FICOM, FICOMP, FISUB, FISUBR, FIDIV, FIDIVR
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "fpu_da"
		inst.Category = CatOther
		inst.Operands = fmt.Sprintf("0x%02x", modrm)

	case 0xDB: // FPU: FILD, FISTTP, FIST, FISTP, FLD, FSTP
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		if modrm == 0xE3 {
			inst.Mnemonic = "fninit"
		} else {
			inst.Mnemonic = "fpu_db"
			inst.Operands = fmt.Sprintf("0x%02x", modrm)
		}
		inst.Category = CatOther

	case 0xDC: // FPU: FADD, FMUL, FCOM, FCOMP, FSUB, FSUBR, FDIV, FDIVR (double)
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "fpu_dc"
		inst.Category = CatOther
		inst.Operands = fmt.Sprintf("0x%02x", modrm)

	case 0xDD: // FPU: FLD, FISTTP, FST, FSTP, FRSTOR, FSAVE, FSTSW
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "fpu_dd"
		inst.Category = CatOther
		inst.Operands = fmt.Sprintf("0x%02x", modrm)

	case 0xDE: // FPU: FIADD, FIMUL, FICOM, FICOMP, FISUB, FISUBR, FIDIV, FIDIVR
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		inst.Mnemonic = "fpu_de"
		inst.Category = CatOther
		inst.Operands = fmt.Sprintf("0x%02x", modrm)

	case 0xDF: // FPU: FILD, FISTTP, FIST, FISTP, FBLD, FBSTP
		if offset >= len(data) {
			return Instruction{}, 0
		}
		modrm := data[offset]
		offset++
		if modrm == 0xE0 {
			inst.Mnemonic = "fnstsw"
			inst.Operands = "ax"
		} else {
			inst.Mnemonic = "fpu_df"
			inst.Operands = fmt.Sprintf("0x%02x", modrm)
		}
		inst.Category = CatOther

	default:
		inst.Mnemonic = fmt.Sprintf("unk_%02x", opcode)
		inst.Category = CatUnknown
	}

	inst.Size = offset
	if inst.Size > 0 && inst.Size <= len(data) {
		inst.Bytes = data[:inst.Size]
	}

	return inst, inst.Size
}

func regName8(n int) string {
	regs := []string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
	if n < len(regs) {
		return regs[n]
	}
	return fmt.Sprintf("r%db", n)
}

func regName64(n int, is64 bool) string {
	if is64 {
		regs := []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"}
		if n < len(regs) {
			return regs[n]
		}
		return fmt.Sprintf("r%d", n)
	}
	regs := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
	if n < len(regs) {
		return regs[n]
	}
	return fmt.Sprintf("r%dd", n)
}

func decodeModRMDetailed(modrm byte, data []byte, is64 bool) (string, string) {
	mod := (modrm >> 6) & 0x3
	reg := int((modrm >> 3) & 0x7)
	rm := int(modrm & 0x7)

	regStr := regName64(reg, is64)
	rmStr := regName64(rm, is64)

	switch mod {
	case 0:
		return fmt.Sprintf("[%s]", rmStr), regStr
	case 1:
		return fmt.Sprintf("[%s+0x%x]", rmStr, data[0]), regStr
	case 2:
		if len(data) >= 4 {
			disp := binary.LittleEndian.Uint32(data[:4])
			return fmt.Sprintf("[%s+0x%x]", rmStr, disp), regStr
		}
		return fmt.Sprintf("[%s+disp32]", rmStr), regStr
	case 3:
		return rmStr, regStr
	}
	return "?", "?"
}

func jccMnemonic(opcode byte) string {
	cc := opcode & 0x0F
	mnemonics := []string{
		"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
		"js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
	}
	if int(cc) < len(mnemonics) {
		return mnemonics[cc]
	}
	return fmt.Sprintf("jcc_%x", cc)
}
