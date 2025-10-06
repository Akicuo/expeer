# Example Output from Expeer

This file shows sample output from Expeer's decompilation process.

## Sample Function (C Output)

```c
/* Function: sub_27b8
   Address: 0x27b8 - 0x288e
   Instructions: 191 */
void sub_27b8(void) {
    /* Local variables */
    int var0;
    int var1;
    int var4;
    int var6;
    int var7;
    int var8;
    int var11;
    int var12;

    /* Decompiled code */
    func_29a0();  // call to 0x29a0
    func_2980();  // call to 0x2980
    func_2980();  // call to 0x2980
    // compare var0 with var1
    if (!=) {  // jne to 0x27c0
        // Jump target: 0x27c0
    }
    var0 = rax;
    return;
}
```

## Sample Function (Go Output)

```go
// sub_27b8 - Decompiled function
// Address: 0x27b8 - 0x288e
// Instructions: 191
func sub_27b8() {
	// Local variables
	var var0 int
	var var1 int
	var var4 int
	var var6 int
	var var7 int
	var var8 int
	var var11 int
	var var12 int

	// Decompiled code
	func_29a0()  // call to 0x29a0
	func_2980()  // call to 0x2980
	func_2980()  // call to 0x2980
	// compare var0 with var1
	if != {  // jne to 0x27c0
		// Jump target: 0x27c0
	}
	var0 = rax
	return
}
```

## What Expeer Generates

### ✅ Successfully Generated:
- **Function signatures** with inferred return types
- **Local variables** detected from stack operations
- **Function calls** with target addresses
- **Arithmetic operations** (add, sub, mul, div)
- **Comparisons** and conditional logic
- **Return statements**
- **Control flow** markers (loops, conditionals)

### ⚠️ Limitations:
- **Unknown instructions** appear as comments (db 0x...)
- **Variable types** default to `int` (basic inference)
- **Register names** sometimes appear directly (rax, rbx)
- **Condition expressions** may be incomplete (shows operator only)
- **Memory access patterns** shown as comments
- **Complex optimizations** may not be fully decompiled

## Real Output Stats

When run on `expeer.exe` (itself):
- **Binary size**: 6.8 MB
- **Detected language**: Go (99.80% confidence)
- **Functions found**: 2,306
- **Output size**: 4.5 MB of Go code
- **Function calls recognized**: Hundreds
- **Variables tracked**: Varies per function

## How to Use

```bash
# Generate Go code
./expeer.exe -lang go -o output.go binary.exe

# Generate C code
./expeer.exe -lang c -o output.c binary.exe

# Auto-detect language with verbose output
./expeer.exe -v -o output.go binary.exe
```

## Tips for Best Results

1. **Use unstripped binaries** - Symbols help identify functions
2. **Try both C and Go** - Sometimes one gives better results
3. **Look for patterns** - Even incomplete code shows structure
4. **Focus on function calls** - They reveal program flow
5. **Manual analysis still needed** - This is a starting point, not perfect decompilation
