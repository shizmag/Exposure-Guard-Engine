package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/exposureguard/exposureguard/internal/distribution"
)

func main() {
	root := flag.String("root", ".", "distribution root directory")
	schema := flag.String("schema", "schemas/distribution-manifest.schema.json", "manifest JSON schema")
	version := flag.String("version", "0.1.0-dev", "Engine version")
	commit := flag.String("commit", "unknown", "Engine git commit")
	check := flag.Bool("check", false, "validate existing manifest and installed files")
	flag.Parse()
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fail(err)
	}
	absSchema := *schema
	if !filepath.IsAbs(absSchema) {
		absSchema = filepath.Join(absRoot, absSchema)
	}
	if *check {
		if err := distribution.Check(absRoot, absSchema); err != nil {
			fail(err)
		}
		fmt.Println("Distribution validation passed")
		return
	}
	manifest, err := distribution.Write(absRoot, *version, *commit, absSchema)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Generated %s distribution manifest\n", manifest.DistributionType)
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
