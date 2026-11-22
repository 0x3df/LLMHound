package mcp

import (
	"encoding/json"
	"sort"
	"strings"
)

// ClassifyCapabilityHints inspects advertised MCP tool name, description, and
// bounded inputSchema property names to produce sorted unique declared hints
// drawn from the closed vocabulary: code, database, filesystem, network,
// secrets, shell. Returns nil if no hint matches.
func ClassifyCapabilityHints(name, description string, inputSchema any) []string {
	text := normalizeHintText(name, description, inputSchema)
	if text == "" {
		return nil
	}

	var matched []string
	for category, terms := range capabilityKeywords {
		if matchesAnyKeyword(text, terms) {
			matched = append(matched, category)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	sort.Strings(matched)
	return matched
}

var capabilityKeywords = map[string][]string{
	"shell": {
		"shell", "bash", "zsh", "powershell", "cmd", "exec", "execute_command",
		"run_command", "terminal", "subprocess", "popen", "system_command",
		"command_line", "spawn", "sh",
	},
	"filesystem": {
		"filesystem", "read_file", "write_file", "edit_file", "delete_file",
		"list_dir", "list_directory", "file_path", "filepath", "directory",
		"mkdir", "upload_file", "download_file", "fs_read", "fs_write",
		"readfile", "writefile", "rmdir", "path",
	},
	"secrets": {
		"secret", "secrets", "credential", "credentials", "password",
		"api_key", "apikey", "token", "vault", "kms", "env_var", "getenv",
		"private_key", "ssh_key", "kubeconfig", "aws_credentials",
	},
	"code": {
		"eval", "python", "run_code", "execute_code", "code_interpreter",
		"repl", "script", "compile", "notebook", "javascript", "node_exec",
	},
	"database": {
		"sql", "query_db", "postgres", "postgresql", "mysql", "sqlite",
		"mongodb", "redis", "cypher", "execute_sql", "database",
	},
	"network": {
		"http_request", "fetch_url", "curl", "wget", "webhook", "ssh",
		"proxy", "socket", "dns_lookup", "http_get", "http_post",
	},
}

func normalizeHintText(name, description string, inputSchema any) string {
	var parts []string
	if n := strings.TrimSpace(name); n != "" {
		parts = append(parts, n)
	}
	if d := strings.TrimSpace(description); d != "" {
		if len(d) > 2048 {
			d = d[:2048]
		}
		parts = append(parts, d)
	}
	if keys := schemaPropertyKeys(inputSchema); len(keys) > 0 {
		parts = append(parts, keys...)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func schemaPropertyKeys(inputSchema any) []string {
	if inputSchema == nil {
		return nil
	}
	b, err := json.Marshal(inputSchema)
	if err != nil || len(b) == 0 {
		return nil
	}
	if len(b) > 8192 {
		b = b[:8192]
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var keys []string
	props, ok := doc["properties"].(map[string]any)
	if ok {
		for k := range props {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func matchesAnyKeyword(lowerText string, terms []string) bool {
	tokens := tokenizeHintText(lowerText)
	for _, kw := range terms {
		if strings.Contains(kw, "_") {
			if strings.Contains(lowerText, kw) {
				return true
			}
			// Also match underscore terms when written with spaces or hyphens.
			spaced := strings.ReplaceAll(kw, "_", " ")
			if strings.Contains(lowerText, spaced) {
				return true
			}
			hyphen := strings.ReplaceAll(kw, "_", "-")
			if strings.Contains(lowerText, hyphen) {
				return true
			}
			continue
		}
		if tokens[kw] {
			return true
		}
	}
	return false
}

func tokenizeHintText(lowerText string) map[string]bool {
	tokens := make(map[string]bool)
	fields := strings.FieldsFunc(lowerText, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	for _, f := range fields {
		tokens[f] = true
	}
	return tokens
}
