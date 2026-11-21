// Command gensearches regenerates extension/saved_searches from the path-kind
// snapshot: go run ./tools/gensearches
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0x3df/LLMHound/internal/savedsearch"
)

func main() {
	dir := "extension/saved_searches"
	data, err := os.ReadFile(filepath.Join(dir, "path_kinds.txt"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	kinds, err := savedsearch.ParsePathKinds(string(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, q := range savedsearch.Generate(kinds) {
		b, err := savedsearch.Marshal(q)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(dir, savedsearch.FileName(q)), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
