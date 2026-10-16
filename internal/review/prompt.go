package review

import (
	_ "embed"
	"maps"
	"slices"
)

// systemPrompt is the reviewer's brief, in prompt.txt so it can be read as it is (the
// site links to it). It never changes per request, so it is cached; changing it means
// bumping PromptVersion.
//
//go:embed prompt.txt
var systemPrompt string

// resultSchema is Result's JSON Schema for structured output.
var resultSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"summary": map[string]any{"type": "string"},
		"verdict": map[string]any{"type": "string", "enum": []string{"pass", "fail"}},
		"findings": map[string]any{
			"type": "array",
			"items": object(map[string]any{
				"severity": map[string]any{"type": "string", "enum": []string{"info", "concern", "malicious"}},
				"file":     map[string]any{"type": "string"},
				"line":     map[string]any{"type": "integer"},
				"title":    map[string]any{"type": "string"},
				"detail":   map[string]any{"type": "string"},
			}),
		},
		"capabilities": map[string]any{
			"type": "array",
			"items": object(map[string]any{
				"package":     map[string]any{"type": "string"},
				"capability":  map[string]any{"type": "string"},
				"explanation": map[string]any{"type": "string"},
				"file":        map[string]any{"type": "string"},
			}),
		},
		"data_flows": map[string]any{
			"type": "array",
			"items": object(map[string]any{
				"what": map[string]any{"type": "string"},
				"to":   map[string]any{"type": "string"},
				"file": map[string]any{"type": "string"},
			}),
		},
	},
	"required":             []string{"summary", "verdict", "findings", "capabilities", "data_flows"},
	"additionalProperties": false,
}

// object is a strict object schema requiring every property. The list is sorted so the
// schema's bytes, part of every request, never vary.
func object(props map[string]any) map[string]any {
	required := slices.Sorted(maps.Keys(props))
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}
