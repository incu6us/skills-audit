package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
)

const (
	verdictPass   = "PASS"
	verdictReview = "REVIEW"
	verdictBlock  = "BLOCK"
)

// Report is the result of one audit.
type Report struct {
	Target    string         `json:"target"`
	Commit    string         `json:"commit,omitempty"`
	Files     int            `json:"files_scanned"`
	Verdict   string         `json:"verdict"`
	Counts    map[string]int `json:"counts"`
	Findings  []Finding      `json:"findings"`
	Endpoints []Endpoint     `json:"endpoints"`
	Notes     []string       `json:"notes,omitempty"`
	History   []Commit       `json:"history,omitempty"`
}

// Endpoint is a host or email address the skill refers to.
type Endpoint struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func (r *Report) setFindings(findings []Finding) {
	if findings == nil {
		findings = []Finding{}
	}
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Rule, b.Rule),
		)
	})
	// The same rule can fire on a JSON line and on the command decoded from it.
	r.Findings = slices.CompactFunc(findings, func(a, b Finding) bool {
		return a.Rule == b.Rule && a.File == b.File && a.Line == b.Line && a.Severity == b.Severity &&
			(a.Severity != Info || a.Snippet == b.Snippet)
	})
	r.Counts = make(map[string]int)
	for _, f := range r.Findings {
		r.Counts[f.Severity.String()]++
	}
	r.Verdict = verdictFor(r.Findings)
	r.Endpoints = endpoints(r.Findings)
}

// verdictFor blocks on any critical finding, asks for review on medium or
// high ones, and passes the rest.
func verdictFor(findings []Finding) string {
	top := Info
	for _, f := range findings {
		top = max(top, f.Severity)
	}
	switch {
	case top == Critical:
		return verdictBlock
	case top >= Medium:
		return verdictReview
	}
	return verdictPass
}

func (r *Report) exitCode() int {
	switch r.Verdict {
	case verdictBlock:
		return exitBlock
	case verdictReview:
		return exitReview
	}
	return exitPass
}

func endpoints(findings []Finding) []Endpoint {
	counts := make(map[string]int)
	for _, f := range findings {
		switch f.Rule {
		case "url":
			if u, err := url.Parse(strings.TrimRight(f.Snippet, ".,;:!?*_")); err == nil && u.Hostname() != "" {
				counts[strings.ToLower(u.Hostname())]++
			}
		case "email":
			counts[strings.ToLower(f.Snippet)]++
		}
	}
	out := make([]Endpoint, 0, len(counts))
	for name, n := range counts {
		out = append(out, Endpoint{Name: name, Count: n})
	}
	slices.SortFunc(out, func(a, b Endpoint) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func (r *Report) writeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func (r *Report) writeText(w io.Writer, verbose bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "target:  %s\n", r.Target)
	if r.Commit != "" {
		fmt.Fprintf(&b, "commit:  %s  (pin installs to this SHA)\n", r.Commit)
	}
	fmt.Fprintf(&b, "files:   %d scanned\n", r.Files)

	hidden := 0
	for _, f := range r.Findings {
		if f.Severity == Info && !verbose {
			hidden++
			continue
		}
		fmt.Fprintf(&b, "\n%-8s  %s  %s\n          %s\n", f.Severity, f.Rule, f.location(), f.Message)
		if f.Snippet != "" {
			fmt.Fprintf(&b, "          │ %s\n", f.Snippet)
		}
	}

	if len(r.Endpoints) > 0 {
		names := make([]string, len(r.Endpoints))
		for i, e := range r.Endpoints {
			names[i] = fmt.Sprintf("%s ×%d", e.Name, e.Count)
		}
		fmt.Fprintf(&b, "\nendpoints: %s\n", strings.Join(names, ", "))
	}
	for _, s := range r.Notes {
		fmt.Fprintf(&b, "note:      %s\n", s)
	}
	if len(r.History) > 0 {
		b.WriteString("\nhistory:\n")
		for _, c := range r.History {
			fmt.Fprintf(&b, "  %s %s %-18s %s\n", c.Hash, c.Date, c.Author, c.Subject)
			if c.Shallow {
				b.WriteString("      (oldest fetched commit: history is cut off here)\n")
			}
			for _, f := range c.Files {
				fmt.Fprintf(&b, "      %s\n", f)
			}
		}
	}

	fmt.Fprintf(&b, "\nverdict: %s  (%d critical, %d high, %d medium, %d low", r.Verdict,
		r.Counts["CRITICAL"], r.Counts["HIGH"], r.Counts["MEDIUM"], r.Counts["LOW"])
	if hidden > 0 {
		fmt.Fprintf(&b, "; %d info hidden, -v to show", hidden)
	}
	b.WriteString(")\n")

	_, err := io.WriteString(w, b.String())
	return err
}
