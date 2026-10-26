package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const _skillSearchDepth = 3 // skills/<name>, or nested like skills/synced/<id>/<name>

// _agentSkillDirs are other agents' skill folders, relative to home.
var _agentSkillDirs = []string{".cursor/skills", ".codex/skills", ".agents/skills"}

// target is one skill or plugin to audit.
type target struct {
	// Name is stable across plugin updates, so it keys the baseline.
	Name string `json:"name"`
	Path string `json:"path"`
}

// result is the audit of one target.
type result struct {
	target
	Report *Report `json:"report,omitempty"`
	Error  string  `json:"error,omitempty"`
}

func (r result) verdict() string {
	if r.Report == nil {
		return "ERROR"
	}
	return r.Report.Verdict
}

func (r result) exitCode() int {
	if r.Report == nil {
		return exitError
	}
	return r.Report.exitCode()
}

// installedTargets finds installed skills and plugins in every ~/.claude*
// config dir, CLAUDE_CONFIG_DIR, and other agents' skill folders.
func installedTargets(home, configDir string) ([]target, error) {
	roots, err := filepath.Glob(filepath.Join(home, ".claude*"))
	if err != nil {
		return nil, err
	}
	if configDir != "" {
		roots = append(roots, configDir)
	}

	var (
		out  []target
		seen = make(map[string]bool)
	)
	add := func(name, p string) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] {
			return
		}
		seen[real] = true
		out = append(out, target{Name: name, Path: real})
	}

	for _, root := range roots {
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			continue // ~/.claude.json and friends
		}
		label := strings.TrimPrefix(filepath.Base(root), ".")
		skills := filepath.Join(root, "skills")
		for _, dir := range findSkills(skills, _skillSearchDepth) {
			add(label+"/skills/"+relPath(skills, dir), dir)
		}
		plugins := pluginDirs(filepath.Join(root, "plugins"))
		for _, name := range sortedKeys(plugins) {
			add(label+"/plugins/"+name, plugins[name])
		}
	}
	for _, d := range _agentSkillDirs {
		base := filepath.Join(home, filepath.FromSlash(d))
		label := strings.TrimPrefix(strings.Split(d, "/")[0], ".")
		for _, dir := range findSkills(base, _skillSearchDepth) {
			add(label+"/skills/"+relPath(base, dir), dir)
		}
	}

	slices.SortFunc(out, func(a, b target) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

// findSkills returns the directories holding a SKILL.md, following symlinks.
func findSkills(dir string, depth int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil || depth == 0 {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(p, "SKILL.md")); err == nil {
			out = append(out, p)
			continue
		}
		out = append(out, findSkills(p, depth-1)...)
	}
	return out
}

// pluginDirs maps plugin@marketplace to its active install: from Claude
// Code's installed_plugins.json, or the newest cached version without it.
func pluginDirs(root string) map[string]string {
	out := make(map[string]string)
	if data, err := os.ReadFile(filepath.Join(root, "installed_plugins.json")); err == nil {
		var reg struct {
			Plugins map[string][]struct{ InstallPath string }
		}
		if json.Unmarshal(data, &reg) == nil && len(reg.Plugins) > 0 {
			for name, installs := range reg.Plugins {
				for i, in := range installs {
					key := name
					if i > 0 { // the same plugin installed in more than one scope
						key = fmt.Sprintf("%s#%d", name, i+1)
					}
					if in.InstallPath != "" {
						out[key] = in.InstallPath
					}
				}
			}
			return out
		}
	}

	versions, _ := filepath.Glob(filepath.Join(root, "cache", "*", "*", "*")) // pattern is valid
	for _, v := range versions {
		plugin := filepath.Base(filepath.Dir(v))
		market := filepath.Base(filepath.Dir(filepath.Dir(v)))
		key := plugin + "@" + market
		if cur, ok := out[key]; !ok || modTime(v) > modTime(cur) {
			out[key] = v
		}
	}
	return out
}

func modTime(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.ModTime().UnixNano()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// writeSummary prints one line per target that needs attention, worst
// first, with the command that shows its details.
func writeSummary(w io.Writer, results []result, verbose bool) error {
	results = slices.Clone(results)
	slices.SortStableFunc(results, func(a, b result) int { return cmp.Compare(b.exitCode(), a.exitCode()) })

	var (
		b         strings.Builder
		counts    = make(map[string]int)
		baselined int
	)
	fmt.Fprintf(&b, "%-7s %4s %4s %4s %4s  %s\n", "VERDICT", "CRIT", "HIGH", "MED", "LOW", "TARGET")
	for _, r := range results {
		v := r.verdict()
		counts[v]++
		if r.Report != nil {
			baselined += r.Report.Baselined
		}
		switch {
		case r.Report == nil:
			fmt.Fprintf(&b, "%-7s %24s  %s\n%33s %s\n", v, "", r.Name, "", r.Error)
		case v != verdictPass || verbose:
			c := r.Report.Counts
			fmt.Fprintf(&b, "%-7s %4d %4d %4d %4d  %s\n", v, c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], r.Name)
			if v != verdictPass {
				fmt.Fprintf(&b, "%33s skill-audit %q\n", "", r.Path)
			}
		}
	}

	fmt.Fprintf(&b, "\n%d targets: %d block, %d review, %d pass", len(results),
		counts[verdictBlock], counts[verdictReview], counts[verdictPass])
	if counts["ERROR"] > 0 {
		fmt.Fprintf(&b, ", %d error", counts["ERROR"])
	}
	if baselined > 0 {
		fmt.Fprintf(&b, "; %d known findings hidden by the baseline", baselined)
	}
	if !verbose && counts[verdictPass] > 0 {
		b.WriteString("; -v lists passing targets")
	}
	b.WriteString("\n")

	_, err := io.WriteString(w, b.String())
	return err
}
