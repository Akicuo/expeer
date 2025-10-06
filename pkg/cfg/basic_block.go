package cfg

import (
	"expeer/pkg/disasm"
)

// BasicBlock represents a basic block in the control flow graph
type BasicBlock struct {
	ID           int
	StartAddr    uint64
	EndAddr      uint64
	Instructions []disasm.Instruction
	Successors   []*BasicBlock
	Predecessors []*BasicBlock
	IsEntry      bool
	IsExit       bool
	LoopHeader   *BasicBlock // Points to loop header if this is in a loop
	DominatedBy  *BasicBlock // Immediate dominator
}

// AddSuccessor adds a successor block
func (bb *BasicBlock) AddSuccessor(succ *BasicBlock) {
	// Avoid duplicates
	for _, s := range bb.Successors {
		if s == succ {
			return
		}
	}
	bb.Successors = append(bb.Successors, succ)

	// Also update predecessor
	for _, p := range succ.Predecessors {
		if p == bb {
			return
		}
	}
	succ.Predecessors = append(succ.Predecessors, bb)
}

// GetLastInstruction returns the last instruction in the block
func (bb *BasicBlock) GetLastInstruction() *disasm.Instruction {
	if len(bb.Instructions) == 0 {
		return nil
	}
	return &bb.Instructions[len(bb.Instructions)-1]
}

// GetFirstInstruction returns the first instruction in the block
func (bb *BasicBlock) GetFirstInstruction() *disasm.Instruction {
	if len(bb.Instructions) == 0 {
		return nil
	}
	return &bb.Instructions[0]
}

// IsConditionalBranch returns true if block ends with conditional branch
func (bb *BasicBlock) IsConditionalBranch() bool {
	last := bb.GetLastInstruction()
	if last == nil {
		return false
	}
	return last.IsConditional && last.IsBranch
}

// IsUnconditionalBranch returns true if block ends with unconditional branch
func (bb *BasicBlock) IsUnconditionalBranch() bool {
	last := bb.GetLastInstruction()
	if last == nil {
		return false
	}
	return !last.IsConditional && last.IsBranch && last.Category != disasm.CatReturn
}

// EndsWithReturn returns true if block ends with return
func (bb *BasicBlock) EndsWithReturn() bool {
	last := bb.GetLastInstruction()
	if last == nil {
		return false
	}
	return last.Category == disasm.CatReturn
}

// HasSingleSuccessor returns true if block has exactly one successor
func (bb *BasicBlock) HasSingleSuccessor() bool {
	return len(bb.Successors) == 1
}

// HasMultipleSuccessors returns true if block has more than one successor
func (bb *BasicBlock) HasMultipleSuccessors() bool {
	return len(bb.Successors) > 1
}

// Dominates returns true if this block dominates the target block
func (bb *BasicBlock) Dominates(target *BasicBlock) bool {
	current := target
	for current != nil {
		if current == bb {
			return true
		}
		current = current.DominatedBy
	}
	return false
}
