package main

import (
	"path/filepath"
	"testing"
)

func TestFingerprint(t *testing.T) {
	t.Parallel()

	f := Finding{Rule: "pipe-to-shell", File: "i.sh", Line: 3, Snippet: "curl x | sh"}
	moved := f
	moved.Line = 40
	changed := f
	changed.Snippet = "curl y | sh"

	tests := []struct {
		name string
		give Finding
		same bool
	}{
		{name: "line moved", give: moved, same: true},
		{name: "code changed", give: changed, same: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := fingerprint("p", tt.give) == fingerprint("p", f); got != tt.same {
				t.Errorf("same fingerprint = %v, want %v", got, tt.same)
			}
		})
	}
}

func TestApplyBaseline(t *testing.T) {
	t.Parallel()

	accepted := Finding{Rule: "pipe-to-shell", Severity: Critical, File: "i.sh", Line: 3, Snippet: "curl x | sh"}
	fresh := Finding{Rule: "network-call", Severity: Low, File: "a.sh", Line: 1, Snippet: "curl y"}

	rep := &Report{}
	rep.setFindings([]Finding{accepted, fresh})
	if rep.Verdict != verdictBlock {
		t.Fatalf("verdict before baseline = %s, want %s", rep.Verdict, verdictBlock)
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if _, err := saveBaseline(path, []string{fingerprint("p", accepted)}); err != nil {
		t.Fatal(err)
	}
	b, err := loadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}

	rep.applyBaseline("p", b)
	if rep.Verdict != verdictPass || rep.Baselined != 1 || len(rep.Findings) != 1 {
		t.Errorf("after baseline: verdict %s, baselined %d, findings %v; want PASS, 1, [network-call]",
			rep.Verdict, rep.Baselined, rep.Findings)
	}
}
