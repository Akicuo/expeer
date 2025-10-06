package decompiler

import (
	"fmt"
	"strings"

	"expeer/pkg/disasm"
)

// Operation types
type OpType int

const (
	OpAssign OpType = iota
	OpCall
	OpReturn
	OpIf
	OpLoop
	OpCompare
	OpArithmetic
	OpMemoryAccess
)

// Operation represents a high-level operation
type Operation struct {
	Type     OpType
	Dest     string
	Src1     string
	Src2     string
	Operator string
	Address  uint64
	Comment  string
}

// Variable represents a detected variable
type Variable struct {
	Name     string
	Type     string
	Register string
	Offset   int
	IsLocal  bool
	IsParam  bool
}

// DecompiledFunction contains high-level representation
type DecompiledFunction struct {
	Function   disasm.Function
	Variables  []Variable
	Operations []Operation
	LocalVars  int
	HasReturn  bool
}

// Decompile converts assembly instructions to high-level operations
func Decompile(fn disasm.Function) *DecompiledFunction {
	df := &DecompiledFunction{
		Function: fn,
	}

	// Track register usage
	regMap := make(map[string]string) // register -> variable name
	varCount := 0

	for i, inst := range fn.Instructions {
		op := Operation{Address: inst.Address}

		switch inst.Mnemonic {
		case "push":
			if inst.Operands == "rbp" && i == 0 {
				// Function prologue - skip
				continue
			}
			op.Type = OpAssign
			op.Comment = fmt.Sprintf("save %s", inst.Operands)

		case "pop":
			if inst.Operands == "rbp" {
				// Function epilogue
				continue
			}
			op.Type = OpAssign
			op.Comment = fmt.Sprintf("restore %s", inst.Operands)

		case "mov":
			op.Type = OpAssign
			parts := strings.Split(inst.Operands, ",")
			if len(parts) == 2 {
				dest := strings.TrimSpace(parts[0])
				src := strings.TrimSpace(parts[1])

				// Check if this is a local variable access
				if strings.Contains(src, "rbp") || strings.Contains(src, "rsp") {
					// Local variable or parameter
					varName := fmt.Sprintf("var%d", varCount)
					varCount++
					regMap[dest] = varName
					df.Variables = append(df.Variables, Variable{
						Name:     varName,
						Register: dest,
						IsLocal:  true,
					})
					op.Dest = varName
					op.Src1 = src
				} else if strings.Contains(dest, "rbp") || strings.Contains(dest, "rsp") {
					// Storing to local
					if varName, ok := regMap[src]; ok {
						op.Dest = "local"
						op.Src1 = varName
					}
				} else {
					// Register to register
					if srcVar, ok := regMap[src]; ok {
						destVar := srcVar
						regMap[dest] = destVar
						op.Dest = dest
						op.Src1 = srcVar
					} else {
						varName := fmt.Sprintf("var%d", varCount)
						varCount++
						regMap[dest] = varName
						op.Dest = varName
						op.Src1 = src
					}
				}
			}

		case "call":
			op.Type = OpCall
			op.Dest = "result"
			op.Src1 = inst.Operands
			// Identify function name if possible
			if strings.HasPrefix(inst.Operands, "0x") {
				op.Comment = fmt.Sprintf("call to %s", inst.Operands)
			}

		case "ret":
			op.Type = OpReturn
			df.HasReturn = true
			if retVar, ok := regMap["rax"]; ok {
				op.Src1 = retVar
			}

		case "add", "sub", "mul", "imul", "div", "idiv":
			op.Type = OpArithmetic
			op.Operator = inst.Mnemonic
			parts := strings.Split(inst.Operands, ",")
			if len(parts) == 2 {
				dest := strings.TrimSpace(parts[0])
				src := strings.TrimSpace(parts[1])
				if varName, ok := regMap[dest]; ok {
					op.Dest = varName
					op.Src1 = varName
					op.Src2 = src
				} else {
					op.Dest = dest
					op.Src1 = dest
					op.Src2 = src
				}
			}

		case "cmp", "test":
			op.Type = OpCompare
			parts := strings.Split(inst.Operands, ",")
			if len(parts) == 2 {
				op.Src1 = strings.TrimSpace(parts[0])
				op.Src2 = strings.TrimSpace(parts[1])
			}

		case "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jb", "jbe", "jae":
			op.Type = OpIf
			op.Operator = inst.Mnemonic
			op.Src1 = inst.Operands
			op.Comment = fmt.Sprintf("conditional jump: %s", inst.Mnemonic)

		default:
			// Unknown instruction - add as comment
			op.Comment = fmt.Sprintf("%s %s", inst.Mnemonic, inst.Operands)
		}

		if op.Type != 0 || op.Comment != "" {
			df.Operations = append(df.Operations, op)
		}
	}

	df.LocalVars = varCount

	return df
}

// AnalyzeControlFlow identifies loops and conditionals
func AnalyzeControlFlow(df *DecompiledFunction) {
	// Track jump targets
	jumpTargets := make(map[uint64]bool)
	backwardJumps := make(map[uint64]uint64) // target -> source (potential loops)

	for _, op := range df.Operations {
		if op.Type == OpIf {
			// Parse jump target
			var target uint64
			if strings.HasPrefix(op.Src1, "0x") {
				fmt.Sscanf(op.Src1, "0x%x", &target)
				jumpTargets[target] = true

				// Check if it's a backward jump (potential loop)
				if target < op.Address {
					backwardJumps[target] = op.Address
				}
			}
		}
	}

	// Mark loop operations
	for i := range df.Operations {
		if _, isLoopTarget := backwardJumps[df.Operations[i].Address]; isLoopTarget {
			df.Operations[i].Comment = "LOOP_START: " + df.Operations[i].Comment
		}
	}
}

// InferTypes attempts to infer variable types
func InferTypes(df *DecompiledFunction) {
	for i := range df.Variables {
		v := &df.Variables[i]

		// Default to int for now
		v.Type = "int"

		// Check usage patterns
		for _, op := range df.Operations {
			if op.Dest == v.Name || op.Src1 == v.Name {
				// If used in pointer operations
				if strings.Contains(op.Src1, "[") || strings.Contains(op.Comment, "pointer") {
					v.Type = "void*"
				}
				// If used with large constants, might be pointer
				if strings.Contains(op.Src2, "0x") {
					var val uint64
					fmt.Sscanf(op.Src2, "0x%x", &val)
					if val > 0x10000 {
						v.Type = "void*"
					}
				}
			}
		}
	}
}
