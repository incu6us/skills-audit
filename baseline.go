package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// baseline holds the fingerprints of findings already reviewed and accepted.
type baseline map[string]bool

type baselineFile struct {
	Version  int      `json:"version"`
	Findings []string `json:"findings"`
}

func loadBaseline(path string) (baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file baselineFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	b := make(baseline, len(file.Findings))
	for _, f := range file.Findings {
		b[f] = true
	}
	return b, nil
}

// saveBaseline writes the unique fingerprints and returns how many.
func saveBaseline(path string, fingerprints []string) (int, error) {
	slices.Sort(fingerprints)
	unique := slices.Compact(fingerprints)
	data, err := json.MarshalIndent(baselineFile{Version: 1, Findings: unique}, "", "  ")
	if err != nil {
		return 0, err
	}
	return len(unique), os.WriteFile(path, append(data, '\n'), 0o644)
}

// fingerprint identifies a finding across runs by rule, file and the code
// around it, not its line number, so edits elsewhere don't resurface it.
// A change to the flagged code itself does, and so does a new advisory ID.
func fingerprint(name string, f Finding) string {
	sum := sha256.Sum256([]byte(f.Rule + "\x00" + f.File + "\x00" + f.Snippet))
	fp := hex.EncodeToString(sum[:8])
	if name == "" {
		return fp
	}
	return name + ":" + fp
}

// fingerprints returns the report's findings worth accepting: all but info.
func (r *Report) fingerprints(name string) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity > Info {
			out = append(out, fingerprint(name, f))
		}
	}
	return out
}

// applyBaseline drops accepted findings and recomputes the verdict.
func (r *Report) applyBaseline(name string, b baseline) {
	if len(b) == 0 {
		return
	}
	kept := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Severity == Info || !b[fingerprint(name, f)] {
			kept = append(kept, f)
		}
	}
	if r.Baselined = len(r.Findings) - len(kept); r.Baselined > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d known findings hidden by the baseline", r.Baselined))
	}
	r.setFindings(kept)
}
