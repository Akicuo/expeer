package cfg

import (
	"fmt"

	"expeer/pkg/disasm"
)

// ControlFlowGraph represents the CFG of a function
type ControlFlowGraph struct {
	Blocks     []*BasicBlock
	EntryBlock *BasicBlock
	ExitBlocks []*BasicBlock
	Function   *disasm.Function
	BlockMap   map[uint64]*BasicBlock // Address -> Block mapping
}

// BuildCFG constructs a control flow graph from a function
func BuildCFG(fn *disasm.Function) (*ControlFlowGraph, error) {
	cfg := &ControlFlowGraph{
		Function: fn,
		BlockMap: make(map[uint64]*BasicBlock),
	}

	if len(fn.Instructions) == 0 {
		return cfg, nil
	}

	// Step 1: Identify basic block boundaries
	leaders := identifyLeaders(fn)

	// Step 2: Create basic blocks
	blocks := createBasicBlocks(fn, leaders)
	cfg.Blocks = blocks

	// Build address to block mapping
	for _, block := range blocks {
		cfg.BlockMap[block.StartAddr] = block
	}

	// Step 3: Connect blocks (add edges)
	connectBlocks(cfg)

	// Step 4: Identify entry and exit blocks
	if len(cfg.Blocks) > 0 {
		cfg.EntryBlock = cfg.Blocks[0]
		cfg.EntryBlock.IsEntry = true
	}

	for _, block := range cfg.Blocks {
		if block.EndsWithReturn() || len(block.Successors) == 0 {
			block.IsExit = true
			cfg.ExitBlocks = append(cfg.ExitBlocks, block)
		}
	}

	// Step 5: Compute dominators
	computeDominators(cfg)

	return cfg, nil
}

// identifyLeaders finds instruction addresses that start basic blocks
func identifyLeaders(fn *disasm.Function) map[uint64]bool {
	leaders := make(map[uint64]bool)

	if len(fn.Instructions) == 0 {
		return leaders
	}

	// First instruction is always a leader
	leaders[fn.Instructions[0].Address] = true

	// Scan all instructions
	for i, inst := range fn.Instructions {
		// Target of any jump is a leader
		if inst.IsBranch && inst.BranchTarget != 0 {
			leaders[inst.BranchTarget] = true
		}

		// Instruction following a jump/call/ret is a leader
		if inst.IsControlFlow() && i+1 < len(fn.Instructions) {
			// If instruction can fall through, next instruction is a leader
			if inst.FallsThrough || inst.Category == disasm.CatCall {
				leaders[fn.Instructions[i+1].Address] = true
			}
		}
	}

	return leaders
}

// createBasicBlocks creates basic blocks from leaders
func createBasicBlocks(fn *disasm.Function, leaders map[uint64]bool) []*BasicBlock {
	var blocks []*BasicBlock
	var currentBlock *BasicBlock
	blockID := 0

	for i, inst := range fn.Instructions {
		// Start new block if this is a leader
		if leaders[inst.Address] {
			if currentBlock != nil {
				blocks = append(blocks, currentBlock)
			}
			currentBlock = &BasicBlock{
				ID:           blockID,
				StartAddr:    inst.Address,
				Instructions: []disasm.Instruction{},
			}
			blockID++
		}

		// Add instruction to current block
		if currentBlock != nil {
			currentBlock.Instructions = append(currentBlock.Instructions, inst)
			currentBlock.EndAddr = inst.Address

			// End block after terminator instruction
			if inst.IsTerminator() && i+1 < len(fn.Instructions) {
				// Only end if next instruction is a leader or doesn't exist
				if leaders[fn.Instructions[i+1].Address] {
					blocks = append(blocks, currentBlock)
					currentBlock = nil
				}
			}
		}
	}

	// Add final block if exists
	if currentBlock != nil {
		blocks = append(blocks, currentBlock)
	}

	return blocks
}

// connectBlocks creates edges between basic blocks
func connectBlocks(cfg *ControlFlowGraph) {
	for i, block := range cfg.Blocks {
		lastInst := block.GetLastInstruction()
		if lastInst == nil {
			continue
		}

		// Handle different terminator types
		switch lastInst.Category {
		case disasm.CatJump:
			if lastInst.IsConditional {
				// Conditional jump: two successors
				// 1. Jump target
				if target := cfg.BlockMap[lastInst.BranchTarget]; target != nil {
					block.AddSuccessor(target)
				}
				// 2. Fall-through (next block)
				if i+1 < len(cfg.Blocks) {
					block.AddSuccessor(cfg.Blocks[i+1])
				}
			} else {
				// Unconditional jump: one successor
				if target := cfg.BlockMap[lastInst.BranchTarget]; target != nil {
					block.AddSuccessor(target)
				}
			}

		case disasm.CatCall:
			// Call always falls through to next block
			if i+1 < len(cfg.Blocks) {
				block.AddSuccessor(cfg.Blocks[i+1])
			}

		case disasm.CatReturn:
			// Return has no successors (exit block)
			continue

		default:
			// Default: fall through to next block
			if i+1 < len(cfg.Blocks) {
				block.AddSuccessor(cfg.Blocks[i+1])
			}
		}
	}
}

// computeDominators calculates the dominator tree
// Uses iterative algorithm
func computeDominators(cfg *ControlFlowGraph) {
	if cfg.EntryBlock == nil || len(cfg.Blocks) == 0 {
		return
	}

	// Initialize: entry dominates itself, all others dominated by all blocks
	cfg.EntryBlock.DominatedBy = cfg.EntryBlock

	changed := true
	maxIterations := len(cfg.Blocks) * len(cfg.Blocks) // Prevent infinite loop

	for changed && maxIterations > 0 {
		changed = false
		maxIterations--

		for _, block := range cfg.Blocks {
			if block == cfg.EntryBlock {
				continue
			}

			// Find intersection of predecessors' dominators
			var newDom *BasicBlock
			for _, pred := range block.Predecessors {
				if pred.DominatedBy == nil {
					continue
				}

				if newDom == nil {
					newDom = pred.DominatedBy
				} else {
					newDom = intersectDominators(pred.DominatedBy, newDom)
				}
			}

			if newDom != nil && newDom != block.DominatedBy {
				block.DominatedBy = newDom
				changed = true
			}
		}
	}
}

// intersectDominators finds the common dominator of two blocks
func intersectDominators(b1, b2 *BasicBlock) *BasicBlock {
	finger1 := b1
	finger2 := b2

	for finger1 != finger2 {
		for finger1.ID > finger2.ID {
			if finger1.DominatedBy == nil {
				return finger2
			}
			finger1 = finger1.DominatedBy
		}
		for finger2.ID > finger1.ID {
			if finger2.DominatedBy == nil {
				return finger1
			}
			finger2 = finger2.DominatedBy
		}
	}

	return finger1
}

// PrintCFG prints the CFG for debugging
func (cfg *ControlFlowGraph) PrintCFG() {
	fmt.Printf("Control Flow Graph for %s\n", cfg.Function.Name)
	fmt.Printf("Blocks: %d\n", len(cfg.Blocks))
	fmt.Printf("Entry: Block %d\n", cfg.EntryBlock.ID)

	for _, block := range cfg.Blocks {
		fmt.Printf("\nBlock %d (0x%x - 0x%x):\n", block.ID, block.StartAddr, block.EndAddr)
		fmt.Printf("  Instructions: %d\n", len(block.Instructions))
		fmt.Printf("  Predecessors: ")
		for _, pred := range block.Predecessors {
			fmt.Printf("%d ", pred.ID)
		}
		fmt.Printf("\n  Successors: ")
		for _, succ := range block.Successors {
			fmt.Printf("%d ", succ.ID)
		}
		if block.DominatedBy != nil {
			fmt.Printf("\n  Dominated by: %d", block.DominatedBy.ID)
		}
		fmt.Printf("\n")
	}
}
