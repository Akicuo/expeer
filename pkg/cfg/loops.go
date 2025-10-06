package cfg

// Loop represents a natural loop in the CFG
type Loop struct {
	Header  *BasicBlock
	Blocks  []*BasicBlock
	Exits   []*BasicBlock
	Parent  *Loop
	Nested  []*Loop
}

// DetectLoops identifies all natural loops in the CFG
// Uses dominator-based approach to find back edges
func DetectLoops(cfg *ControlFlowGraph) []*Loop {
	var loops []*Loop

	// Find back edges (edges to dominators)
	backEdges := findBackEdges(cfg)

	// For each back edge, construct the natural loop
	for _, edge := range backEdges {
		loop := constructLoop(edge.from, edge.to)
		loops = append(loops, loop)

		// Mark loop header in blocks
		for _, block := range loop.Blocks {
			block.LoopHeader = loop.Header
		}
	}

	// Build loop nesting hierarchy
	buildLoopHierarchy(loops)

	return loops
}

// BackEdge represents an edge from a block to its dominator
type BackEdge struct {
	from *BasicBlock
	to   *BasicBlock // Loop header (dominator)
}

// findBackEdges identifies all back edges (edges to dominators)
func findBackEdges(cfg *ControlFlowGraph) []BackEdge {
	var backEdges []BackEdge

	for _, block := range cfg.Blocks {
		for _, succ := range block.Successors {
			// If successor dominates this block, it's a back edge
			if succ.Dominates(block) {
				backEdges = append(backEdges, BackEdge{
					from: block,
					to:   succ,
				})
			}
		}
	}

	return backEdges
}

// constructLoop builds the set of blocks in a natural loop
func constructLoop(tail, header *BasicBlock) *Loop {
	loop := &Loop{
		Header: header,
		Blocks: []*BasicBlock{header},
	}

	// Use worklist algorithm to find all blocks in loop
	worklist := []*BasicBlock{tail}
	visited := make(map[*BasicBlock]bool)
	visited[header] = true

	for len(worklist) > 0 {
		// Pop from worklist
		block := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		if visited[block] {
			continue
		}
		visited[block] = true

		// Add to loop
		loop.Blocks = append(loop.Blocks, block)

		// Add predecessors to worklist
		for _, pred := range block.Predecessors {
			if !visited[pred] {
				worklist = append(worklist, pred)
			}
		}
	}

	// Find loop exits (blocks with successors outside the loop)
	blockSet := make(map[*BasicBlock]bool)
	for _, b := range loop.Blocks {
		blockSet[b] = true
	}

	for _, block := range loop.Blocks {
		for _, succ := range block.Successors {
			if !blockSet[succ] {
				// This block has an exit edge
				loop.Exits = append(loop.Exits, block)
				break
			}
		}
	}

	return loop
}

// buildLoopHierarchy establishes parent-child relationships between nested loops
func buildLoopHierarchy(loops []*Loop) {
	// Sort loops by size (larger loops are parents of smaller ones)
	// Simple O(n^2) approach
	for i := 0; i < len(loops); i++ {
		for j := 0; j < len(loops); j++ {
			if i == j {
				continue
			}

			// Check if loop i contains loop j
			if loopContains(loops[i], loops[j]) {
				// loop i is a potential parent of loop j
				// Only set as parent if no smaller parent exists
				if loops[j].Parent == nil || len(loops[i].Blocks) < len(loops[j].Parent.Blocks) {
					loops[j].Parent = loops[i]
				}
			}
		}
	}

	// Build nested lists
	for _, loop := range loops {
		if loop.Parent != nil {
			loop.Parent.Nested = append(loop.Parent.Nested, loop)
		}
	}
}

// loopContains returns true if loop1 contains all blocks of loop2
func loopContains(loop1, loop2 *Loop) bool {
	blocks1 := make(map[*BasicBlock]bool)
	for _, b := range loop1.Blocks {
		blocks1[b] = true
	}

	for _, b := range loop2.Blocks {
		if !blocks1[b] {
			return false
		}
	}

	return true
}

// IsInfiniteLoop returns true if loop has no exits
func (l *Loop) IsInfiniteLoop() bool {
	return len(l.Exits) == 0
}

// GetDepth returns the nesting depth of the loop (0 = outermost)
func (l *Loop) GetDepth() int {
	depth := 0
	parent := l.Parent
	for parent != nil {
		depth++
		parent = parent.Parent
	}
	return depth
}
