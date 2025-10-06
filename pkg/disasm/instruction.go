package disasm

// InstructionCategory represents the category of an instruction
type InstructionCategory int

const (
	CatUnknown InstructionCategory = iota
	CatDataTransfer
	CatArithmetic
	CatLogical
	CatCompare
	CatCall
	CatReturn
	CatJump
	CatStack
	CatInterrupt
	CatNop
	CatOther
)

func (ic InstructionCategory) String() string {
	switch ic {
	case CatDataTransfer:
		return "DataTransfer"
	case CatArithmetic:
		return "Arithmetic"
	case CatLogical:
		return "Logical"
	case CatCompare:
		return "Compare"
	case CatCall:
		return "Call"
	case CatReturn:
		return "Return"
	case CatJump:
		return "Jump"
	case CatStack:
		return "Stack"
	case CatInterrupt:
		return "Interrupt"
	case CatNop:
		return "Nop"
	default:
		return "Other"
	}
}

// Instruction represents a disassembled instruction with enhanced metadata
type Instruction struct {
	Address          uint64
	Bytes            []byte
	Mnemonic         string
	Operands         string
	Size             int
	Category         InstructionCategory
	RegsRead         []string
	RegsWritten      []string
	HasMemoryAccess  bool
	MemoryBase       string
	MemoryIndex      string
	MemoryDisp       int64
	MemoryScale      int
	IsConditional    bool
	IsBranch         bool
	BranchTarget     uint64
	FallsThrough     bool
}

// IsControlFlow returns true if this instruction affects control flow
func (i *Instruction) IsControlFlow() bool {
	return i.Category == CatCall || i.Category == CatReturn || i.Category == CatJump
}

// IsTerminator returns true if this instruction terminates a basic block
func (i *Instruction) IsTerminator() bool {
	return i.Category == CatReturn || i.Category == CatJump || i.Category == CatCall
}

// ModifiesRegister returns true if the instruction modifies the given register
func (i *Instruction) ModifiesRegister(reg string) bool {
	for _, r := range i.RegsWritten {
		if r == reg {
			return true
		}
	}
	return false
}

// ReadsRegister returns true if the instruction reads the given register
func (i *Instruction) ReadsRegister(reg string) bool {
	for _, r := range i.RegsRead {
		if r == reg {
			return true
		}
	}
	return false
}

// GetOperandCount returns the number of operands
func (i *Instruction) GetOperandCount() int {
	if i.Operands == "" {
		return 0
	}
	// Simple approximation - count commas + 1
	count := 1
	for _, c := range i.Operands {
		if c == ',' {
			count++
		}
	}
	return count
}

// Section represents a section in a binary (moved from parser to avoid circular dependency)
type Section struct {
	Name    string
	Address uint64
	Size    uint64
	Data    []byte
	Flags   uint32
}
