package main

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	_npmInstallHooks = []string{"preinstall", "install", "postinstall", "prepare", "prepublish"}
	_customIndex     = regexp.MustCompile(`^(-i\s|--index-url|--extra-index-url|-f\s|--find-links|--trusted-host)`)
)

// depFindings checks package manifests for code that runs on install and
// for dependencies pulled from outside the registry.
func depFindings(rel, text string) []Finding {
	switch base := path.Base(rel); {
	case base == "package.json":
		return npmFindings(rel, text)
	case base == "setup.py":
		return []Finding{{
			Rule: "setup-py", Category: "dependency", Severity: Medium, File: rel, Line: 1,
			Message: "setup.py runs arbitrary code when the package is installed",
		}}
	case isRequirements(base):
		return requirementsFindings(rel, text)
	}
	return nil
}

func npmFindings(rel, text string) []Finding {
	var pkg struct {
		Scripts              map[string]string
		Dependencies         map[string]string
		DevDependencies      map[string]string
		OptionalDependencies map[string]string
	}
	if err := json.Unmarshal([]byte(text), &pkg); err != nil {
		return []Finding{{
			Rule: "npm-manifest", Category: "dependency", Severity: Low, File: rel,
			Message: "package.json does not parse: " + err.Error(),
		}}
	}

	// A bundled dependency is already installed: its hooks run only if
	// someone rebuilds or reinstalls it, so they are inventory, not a threat.
	hookSev, depSev, hookMsg := High, Medium, "npm runs the %q script on install"
	if strings.Contains("/"+rel, "/node_modules/") {
		hookSev, depSev, hookMsg = Low, Low, "bundled dependency's %q script: runs only on npm rebuild or reinstall"
	}

	var out []Finding
	for _, hook := range _npmInstallHooks {
		if cmd, ok := pkg.Scripts[hook]; ok {
			out = append(out, Finding{
				Rule: "install-hook", Category: "dependency", Severity: hookSev, File: rel,
				Line:    lineOf(text, `"`+hook+`"`),
				Message: fmt.Sprintf(hookMsg, hook),
				Snippet: escapeInvisible(cmd),
			})
		}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for name, spec := range deps {
			if strings.ContainsAny(spec, ":/") {
				out = append(out, Finding{
					Rule: "non-registry-dep", Category: "dependency", Severity: depSev, File: rel,
					Line:    lineOf(text, `"`+name+`"`),
					Message: fmt.Sprintf("%s comes from outside the npm registry", name),
					Snippet: escapeInvisible(spec),
				})
			}
		}
	}
	return out
}

func requirementsFindings(rel, text string) []Finding {
	var out []Finding
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		f := Finding{Category: "dependency", File: rel, Line: i + 1, Snippet: escapeInvisible(line)}
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case _customIndex.MatchString(line):
			f.Rule, f.Severity, f.Message = "custom-index", High, "installs from a custom package index (dependency confusion risk)"
		case strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "git+") || strings.Contains(line, "://"):
			f.Rule, f.Severity, f.Message = "non-registry-dep", Medium, "dependency from outside PyPI"
		case strings.HasPrefix(line, "-"):
			continue
		case !strings.Contains(line, "=="):
			f.Rule, f.Severity, f.Message = "unpinned-dep", Low, "unpinned: a later release could change what installs"
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

func isRequirements(base string) bool {
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

func lineOf(text, needle string) int {
	i := strings.Index(text, needle)
	if i < 0 {
		return 0
	}
	return 1 + strings.Count(text[:i], "\n")
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
