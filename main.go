package main

import (
	"flag"
	"fmt"
	"os"

	"expeer/pkg/analyzer"
	"expeer/pkg/codegen"
	"expeer/pkg/parser"
)

func main() {
	// CLI flags
	outputLang := flag.String("lang", "auto", "Output language: auto, c, or go")
	verbose := flag.Bool("v", false, "Verbose output")
	outputFile := flag.String("o", "", "Output file (default: stdout)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: expeer [options] <executable>\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	executablePath := flag.Arg(0)

	// Parse the executable
	if *verbose {
		fmt.Fprintf(os.Stderr, "[*] Parsing executable: %s\n", executablePath)
	}

	binary, err := parser.ParseExecutable(executablePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing executable: %v\n", err)
		os.Exit(1)
	}

	// Analyze the binary
	if *verbose {
		fmt.Fprintf(os.Stderr, "[*] Analyzing binary format: %s\n", binary.Format)
		fmt.Fprintf(os.Stderr, "[*] Architecture: %s\n", binary.Arch)
	}

	analysis, err := analyzer.Analyze(binary, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing binary: %v\n", err)
		os.Exit(1)
	}

	// Detect language if auto mode
	lang := *outputLang
	if lang == "auto" {
		lang = analysis.DetectedLanguage
		if *verbose {
			fmt.Fprintf(os.Stderr, "[*] Detected language: %s (confidence: %.2f%%)\n",
				lang, analysis.Confidence*100)
		}
	}

	// Generate code
	if *verbose {
		fmt.Fprintf(os.Stderr, "[*] Generating %s code...\n", lang)
	}

	var code string
	switch lang {
	case "c":
		code = codegen.GenerateC(analysis)
	case "go", "golang":
		code = codegen.GenerateGo(analysis)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported language: %s\n", lang)
		os.Exit(1)
	}

	// Output results
	if *outputFile != "" {
		err = os.WriteFile(*outputFile, []byte(code), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] Code written to: %s\n", *outputFile)
		}
	} else {
		fmt.Print(code)
	}
}
