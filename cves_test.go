package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestRequirementPins(t *testing.T) {
	t.Parallel()

	give := "requests==2.19.0\nurllib3[socks] == 1.24.1 ; python_version > '3'\nflask>=2\n# pinned==1.0\n"
	want := []nameVersion{{name: "requests", version: "2.19.0"}, {name: "urllib3", version: "1.24.1"}}
	if got := requirementPins(give); !slices.Equal(got, want) {
		t.Errorf("requirementPins = %v, want %v", got, want)
	}
}

func TestNPMLockPackages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want []nameVersion
	}{
		{
			name: "v3 flat packages",
			give: `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},` +
				`"node_modules/a":{"version":"1.2.3","dependencies":{"b":"^2"}},` +
				`"node_modules/a/node_modules/@s/b":{"version":"2.0.0"},` +
				`"node_modules/local":{"link":true}}}`,
			want: []nameVersion{{name: "@s/b", version: "2.0.0"}, {name: "a", version: "1.2.3"}},
		},
		{
			name: "v1 nested dependencies",
			give: `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},` +
				`"g":{"version":"github:o/r#abc"}}}`,
			want: []nameVersion{{name: "a", version: "1.0.0"}, {name: "b", version: "2.0.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := npmLockPackages([]byte(tt.give))
			if err != nil {
				t.Fatal(err)
			}
			slices.SortFunc(got, func(a, b nameVersion) int {
				if a.name < b.name {
					return -1
				}
				return 1
			})
			if !slices.Equal(got, tt.want) {
				t.Errorf("npmLockPackages = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOSVQuery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Queries []osvBatchQuery }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Queries) != 2 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{},{"vulns":[{"id":"GHSA-1"},{"id":"CVE-2"}]}]}`))
	}))
	defer srv.Close()

	pkgs := []pkgVersion{
		{file: "package-lock.json", ecosystem: "npm", name: "safe", version: "1.0.0"},
		{file: "requirements.txt", ecosystem: "PyPI", name: "requests", version: "2.19.0"},
	}
	got, err := osvQuery(t.Context(), srv.URL, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].File != "requirements.txt" || got[0].Snippet != "GHSA-1, CVE-2" {
		t.Errorf("osvQuery = %+v, want one finding for requests with both IDs", got)
	}
}
