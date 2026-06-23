// CLI entrypoint for the Go port of sbomb.
//
//	go run . <rootfs>      # scan a rootfs, print CycloneDX JSON
//	exit 1 when vulnerabilities are found (CI gate), 2 on a bad path.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	comps, err := ScanRootfs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	total := MatchVulns(comps)
	out, _ := json.MarshalIndent(BuildCycloneDX(comps), "", "  ")
	fmt.Println(string(out))
	if total > 0 {
		os.Exit(1)
	}
}
