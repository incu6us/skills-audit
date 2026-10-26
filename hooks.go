package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// autoRunFindings lists what a plugin or settings file runs without the
// agent deciding to: hook commands, hook prompts and URLs, and MCP server
// launches. Each value is decoded from JSON and scanned again, so JSON
// escapes can't hide a command from the line rules.
func autoRunFindings(rel, text string) []Finding {
	if !strings.Contains(text, `"hooks"`) && !strings.Contains(text, `"mcpServers"`) {
		return nil
	}
	var doc any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil
	}

	var (
		out  []Finding
		walk func(v any, keys []string)
	)
	walk = func(v any, keys []string) {
		switch v := v.(type) {
		case map[string]any:
			out = append(out, autoRunEntry(rel, text, v, keys)...)
			for _, k := range slices.Sorted(maps.Keys(v)) {
				walk(v[k], append(slices.Clip(keys), k))
			}
		case []any:
			for _, child := range v {
				walk(child, keys)
			}
		}
	}
	walk(doc, nil)
	return out
}

func autoRunEntry(rel, text string, entry map[string]any, keys []string) []Finding {
	if event, ok := keyAfter(keys, "hooks"); ok {
		var out []Finding
		if cmd, ok := entry["command"].(string); ok {
			out = append(out, autoRun(rel, text, "hook-command", codeFile, "runs automatically on "+event, cmd)...)
		}
		if prompt, ok := entry["prompt"].(string); ok {
			out = append(out, autoRun(rel, text, "hook-prompt", docFile, "injects a prompt on "+event, prompt)...)
		}
		if u, ok := entry["url"].(string); ok {
			out = append(out, autoRun(rel, text, "hook-url", codeFile, "sends event data to a URL on "+event, u)...)
		}
		return out
	}
	if name, ok := keyAfter(keys, "mcpServers"); ok {
		if cmd, ok := entry["command"].(string); ok {
			full := strings.Join(append([]string{cmd}, stringsIn(entry["args"])...), " ")
			return autoRun(rel, text, "mcp-server", codeFile, fmt.Sprintf("starts MCP server %q", name), full)
		}
	}
	return nil
}

// autoRun lists the value as low-severity inventory and lets the regular
// rules decide how risky it is. Scripts a hook points to are scanned as
// files of their own.
func autoRun(rel, text, rule string, kind scope, message, value string) []Finding {
	line := lineOf(text, jsonFragment(value))
	out := []Finding{{
		Rule: rule, Category: "auto-run", Severity: Low, File: rel, Line: line,
		Message: message, Snippet: snippet(value, 0, min(len(value), 2*_snippetPad)),
	}}
	for _, f := range scanText(rel, value, kind) {
		f.Line = line
		if f.Rule == "runtime-package" {
			f.Severity = Medium // fetched and run on every session, unreviewed
		}
		out = append(out, f)
	}
	return out
}

// jsonFragment is s as it appears encoded in a JSON file, for finding its
// line. The whole value: commands often share a long prefix.
func jsonFragment(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	frag := strings.TrimSpace(b.String())
	return frag[1 : len(frag)-1]
}

func keyAfter(keys []string, k string) (string, bool) {
	i := slices.Index(keys, k)
	if i < 0 || i+1 >= len(keys) {
		return "", false
	}
	return keys[i+1], true
}

func stringsIn(v any) []string {
	items, _ := v.([]any)
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
