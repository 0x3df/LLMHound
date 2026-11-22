// Package rules embeds the shipped path-qualification rule definitions.
package rules

import "embed"

// FS holds the embedded JSON path-qualification rules.
//
//go:embed *.json
var FS embed.FS
