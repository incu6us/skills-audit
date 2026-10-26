package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	_cveTimeout   = 3 * time.Minute
	_osvBatchURL  = "https://api.osv.dev/v1/querybatch"
	_osvBatchSize = 1000 // API limit per request
	_installOSV   = "brew install osv-scanner, or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"
)

var _requirementPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;#,=]+)`)

// pkgVersion is one pinned dependency found in a lockfile.
type pkgVersion struct {
	file, ecosystem, name, version string
}

// checkCVEs looks up dependencies in the OSV vulnerability database:
// through osv-scanner when installed (every ecosystem it knows), otherwise
// by sending pinned npm and PyPI versions to osv.dev directly.
func checkCVEs(ctx context.Context, root string, files []string, offline bool) ([]Finding, []string) {
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, []string{"dependency CVE check: needs a directory, not a single file"}
	}
	if offline {
		return nil, []string{"dependency CVE check skipped (--offline)"}
	}
	if _, err := exec.LookPath("osv-scanner"); err == nil {
		return osvScanner(ctx, root)
	}

	pkgs, notes := pinnedPackages(root, files)
	if len(pkgs) == 0 {
		return nil, notes
	}
	findings, err := osvQuery(ctx, _osvBatchURL, pkgs)
	if err != nil {
		return nil, append(notes, "osv.dev lookup failed: "+err.Error())
	}
	return findings, append(notes, fmt.Sprintf(
		"checked %d pinned npm/PyPI packages on osv.dev; for other ecosystems and lockfiles: %s", len(pkgs), _installOSV))
}

func osvScanner(ctx context.Context, root string) ([]Finding, []string) {
	ctx, cancel := context.WithTimeout(ctx, _cveTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "osv-scanner", "scan", "source", "--format", "json", "-r", root)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// osv-scanner exits non-zero when it finds vulnerabilities, so the exit
	// status only matters when the output doesn't decode.
	out, runErr := cmd.Output()
	var res struct {
		Results []struct {
			Source   struct{ Path string }
			Packages []struct {
				Package         struct{ Name, Version string }
				Vulnerabilities []struct{ ID string }
			}
		}
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, []string{fmt.Sprintf("osv-scanner failed: %v: %s", cmp.Or(runErr, err), lastLine(stderr.String()))}
	}

	var findings []Finding
	for _, r := range res.Results {
		for _, p := range r.Packages {
			ids := make([]string, 0, len(p.Vulnerabilities))
			for _, v := range p.Vulnerabilities {
				ids = append(ids, v.ID)
			}
			if len(ids) > 0 {
				findings = append(findings, vulnFinding(relPath(root, r.Source.Path), p.Package.Name, p.Package.Version, ids))
			}
		}
	}
	return findings, nil
}

// pinnedPackages collects exact versions from npm lockfiles and pip
// requirements. Ranges can't be looked up, so unpinned entries are left out.
func pinnedPackages(root string, files []string) ([]pkgVersion, []string) {
	var (
		pkgs  []pkgVersion
		notes []string
		seen  = make(map[pkgVersion]bool)
	)
	add := func(p pkgVersion) {
		if !seen[p] {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
	}

	for _, rel := range files {
		base := path.Base(rel)
		npm := base == "package-lock.json" || base == "npm-shrinkwrap.json"
		if !npm && !isRequirements(base) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			notes = append(notes, fmt.Sprintf("dependency CVE check: %v", err))
			continue
		}
		if !npm {
			for _, nv := range requirementPins(string(data)) {
				add(pkgVersion{file: rel, ecosystem: "PyPI", name: nv.name, version: nv.version})
			}
			continue
		}
		deps, err := npmLockPackages(data)
		if err != nil {
			notes = append(notes, fmt.Sprintf("dependency CVE check: %s does not parse: %v", rel, err))
			continue
		}
		for _, nv := range deps {
			add(pkgVersion{file: rel, ecosystem: "npm", name: nv.name, version: nv.version})
		}
	}
	return pkgs, notes
}

type nameVersion struct {
	name, version string
}

func requirementPins(text string) []nameVersion {
	var out []nameVersion
	for _, line := range strings.Split(text, "\n") {
		if m := _requirementPin.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			out = append(out, nameVersion{name: m[1], version: m[3]})
		}
	}
	return out
}

type npmV1Dep struct {
	Version      string
	Dependencies map[string]npmV1Dep
}

// npmLockPackages reads package-lock.json: the flat "packages" map of
// lockfile v2/v3, or the nested "dependencies" tree of v1.
func npmLockPackages(data []byte) ([]nameVersion, error) {
	var lock struct {
		Packages map[string]struct {
			Version string
			Link    bool
		}
		Dependencies map[string]npmV1Dep
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	const prefix = "node_modules/"
	var out []nameVersion
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, prefix)
			if i < 0 || p.Link || p.Version == "" {
				continue
			}
			out = append(out, nameVersion{name: key[i+len(prefix):], version: p.Version})
		}
		return out, nil
	}

	var walk func(map[string]npmV1Dep)
	walk = func(deps map[string]npmV1Dep) {
		for name, d := range deps {
			if d.Version != "" && !strings.Contains(d.Version, ":") { // skip git/file/URL sources
				out = append(out, nameVersion{name: name, version: d.Version})
			}
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out, nil
}

// osvQuery sends package versions to the osv.dev batch API.
func osvQuery(ctx context.Context, endpoint string, pkgs []pkgVersion) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, _cveTimeout)
	defer cancel()

	var findings []Finding
	for start := 0; start < len(pkgs); start += _osvBatchSize {
		batch := pkgs[start:min(start+_osvBatchSize, len(pkgs))]
		ids, err := osvBatch(ctx, endpoint, batch)
		if err != nil {
			return nil, err
		}
		for i, p := range batch {
			if len(ids[i]) > 0 {
				findings = append(findings, vulnFinding(p.file, p.name, p.version, ids[i]))
			}
		}
	}
	return findings, nil
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

// osvBatch returns the vulnerability IDs for each package, in order.
// ponytail: ignores next_page_token, so a package with very many advisories
// lists only the first page; one ID is enough to flag it.
func osvBatch(ctx context.Context, endpoint string, batch []pkgVersion) ([][]string, error) {
	queries := make([]osvBatchQuery, len(batch))
	for i, p := range batch {
		queries[i] = osvBatchQuery{Package: osvPackage{Name: p.name, Ecosystem: p.ecosystem}, Version: p.version}
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv.dev: %s", resp.Status)
	}

	var res struct {
		Results []struct {
			Vulns []struct{ ID string }
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&res); err != nil {
		return nil, fmt.Errorf("osv.dev: %w", err)
	}
	if len(res.Results) != len(batch) {
		return nil, fmt.Errorf("osv.dev: %d results for %d packages", len(res.Results), len(batch))
	}
	ids := make([][]string, len(batch))
	for i, r := range res.Results {
		for _, v := range r.Vulns {
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

func vulnFinding(file, name, version string, ids []string) Finding {
	return Finding{
		Rule: "known-vuln", Category: "dependency", Severity: High, File: file,
		Message: fmt.Sprintf("%s %s has known vulnerabilities", name, version),
		Snippet: strings.Join(ids, ", "),
	}
}
