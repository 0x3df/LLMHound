package mcp_test

import (
	"reflect"
	"testing"

	"github.com/0x3df/LLMHound/internal/collectors/mcp"
)

func TestClassifyCapabilityHints(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		desc   string
		schema any
		want   []string
	}{
		{
			name:   "shell and filesystem tool",
			tool:   "run_shell_command",
			desc:   "Execute a bash command and read output file",
			schema: map[string]any{"properties": map[string]any{"command": map[string]any{"type": "string"}, "file_path": map[string]any{"type": "string"}}},
			want:   []string{"filesystem", "shell"},
		},
		{
			name:   "secrets and python eval",
			tool:   "inspect_env",
			desc:   "Evaluate a python snippet to fetch vault secrets",
			schema: map[string]any{"properties": map[string]any{"api_key": map[string]any{"type": "string"}}},
			want:   []string{"code", "secrets"},
		},
		{
			name:   "database and network",
			tool:   "query_postgres",
			desc:   "Run SQL query or send http_request webhook",
			schema: nil,
			want:   []string{"database", "network"},
		},
		{
			name:   "benign weather tool has no hints",
			tool:   "get_weather",
			desc:   "Look up forecast temperature for a city",
			schema: map[string]any{"properties": map[string]any{"city": map[string]any{"type": "string"}}},
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mcp.ClassifyCapabilityHints(tc.tool, tc.desc, tc.schema)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
