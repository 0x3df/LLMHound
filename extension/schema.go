package extension

import _ "embed"

// SchemaJSON is the embedded BloodHound CE OpenGraph extension schema.
//
//go:embed schema.json
var SchemaJSON []byte
