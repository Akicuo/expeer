package cfg

// ConditionalStructure represents an if/else or switch structure
type ConditionalStructure struct {
	Type          CondType
	Condition     *BasicBlock // Block containing the condition
	ThenBranch    *BasicBlock
	ElseBranch    *BasicBlock
	MergePoint    *BasicBlock // Where branches rejoin
	CaseBlocks    []*BasicBlock // For switch statements
}

type CondType int

const (
	CondIfThen CondType = iota
	CondIfThenElse
	CondSwitch
)

// DetectConditionals identifies if/else and switch structures
func DetectConditionals(cfg *ControlFlowGraph) []*ConditionalStructure {
	var conditionals []*ConditionalStructure

	for _, block := range cfg.Blocks {
		// Look for blocks with conditional branches
		if !block.IsConditionalBranch() {
			continue
		}

		if len(block.Successors) == 2 {
			cond := analyzeIfElse(block)
			if cond != nil {
				conditionals = append(conditionals, cond)
			}
		} else if len(block.Successors) > 2 {
			// Potential switch statement
			cond := analyzeSwitch(block)
			if cond != nil {
				conditionals = append(conditionals, cond)
			}
		}
	}

	return conditionals
}

// analyzeIfElse analyzes a two-way branch for if/else structure
func analyzeIfElse(block *BasicBlock) *ConditionalStructure {
	if len(block.Successors) != 2 {
		return nil
	}

	then := block.Successors[0]
	els := block.Successors[1]

	cond := &ConditionalStructure{
		Condition:  block,
		ThenBranch: then,
		ElseBranch: els,
	}

	// Try to find merge point
	mergePoint := findMergePoint(then, els)
	if mergePoint != nil {
		cond.MergePoint = mergePoint
		cond.Type = CondIfThenElse
	} else {
		// Check if one branch is empty (if-then without else)
		if len(els.Instructions) == 0 && len(els.Successors) == 1 {
			cond.Type = CondIfThen
			cond.MergePoint = els.Successors[0]
		} else if len(then.Instructions) == 0 && len(then.Successors) == 1 {
			cond.Type = CondIfThen
			cond.MergePoint = then.Successors[0]
		}
	}

	return cond
}

// findMergePoint finds where two branches rejoin
func findMergePoint(branch1, branch2 *BasicBlock) *BasicBlock {
	// Simple approach: find first common successor
	visited1 := make(map[*BasicBlock]bool)

	// BFS from branch1
	queue := []*BasicBlock{branch1}
	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]

		if visited1[block] {
			continue
		}
		visited1[block] = true

		queue = append(queue, block.Successors...)
	}

	// BFS from branch2, looking for blocks visited from branch1
	visited2 := make(map[*BasicBlock]bool)
	queue = []*BasicBlock{branch2}
	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]

		if visited2[block] {
			continue
		}
		visited2[block] = true

		// Check if this block was visited from branch1
		if visited1[block] && block != branch1 && block != branch2 {
			return block
		}

		queue = append(queue, block.Successors...)
	}

	return nil
}

// analyzeSwitch analyzes a multi-way branch for switch structure
func analyzeSwitch(block *BasicBlock) *ConditionalStructure {
	if len(block.Successors) <= 2 {
		return nil
	}

	cond := &ConditionalStructure{
		Type:       CondSwitch,
		Condition:  block,
		CaseBlocks: block.Successors,
	}

	// Try to find default case and merge point
	// This is heuristic-based
	for _, succ := range block.Successors {
		// Look for common merge point
		if len(succ.Successors) == 1 {
			potentialMerge := succ.Successors[0]
			if isCommonSuccessor(potentialMerge, block.Successors) {
				cond.MergePoint = potentialMerge
				break
			}
		}
	}

	return cond
}

// isCommonSuccessor checks if a block is a successor of all blocks in the list
func isCommonSuccessor(target *BasicBlock, blocks []*BasicBlock) bool {
	for _, block := range blocks {
		found := false
		for _, succ := range block.Successors {
			if succ == target {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// GetConditionType returns the type as a string
func (c *ConditionalStructure) GetConditionType() string {
	switch c.Type {
	case CondIfThen:
		return "if-then"
	case CondIfThenElse:
		return "if-then-else"
	case CondSwitch:
		return "switch"
	default:
		return "unknown"
	}
}
