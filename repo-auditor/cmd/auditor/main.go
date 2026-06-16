package main

import (
	"flag"
	"fmt"
	"os"

	"repo-auditor/pkg/analyzer"
	"repo-auditor/pkg/renderer"
)

func main() {
	pathFlag := flag.String("path", ".", "Root path to scan for git repositories")
	concurrencyFlag := flag.Int("concurrency", 4, "Number of concurrent workers")
	flag.Parse()

	info, err := os.Stat(*pathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing path: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Path must be a directory\n")
		os.Exit(1)
	}

	fmt.Printf("Starting analysis in %s with %d workers...\n", *pathFlag, *concurrencyFlag)

	a := analyzer.NewAnalyzer(*pathFlag, *concurrencyFlag)

	projects, secReport, err := a.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during analysis: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d projects. Generating architecture map...\n", len(projects))

	err = renderer.GenerateMarkdown(projects, secReport, *pathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating markdown: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully generated architecture_map.md")
}
