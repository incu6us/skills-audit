package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const _skillSearchDepth = 3 // skills/<name>, or nested like skills/synced/<id>/<name>

var (
	// _agentSkillDirs are other agents' skill folders, relative to home.
	_agentSkillDirs = []string{".cursor/skills", ".codex/skills", ".agents/skills"}

	// _projectAgentFiles are files an agent loads from a repo on its own.
	_projectAgentFiles = map[string]bool{
		".mcp.json": true, "CLAUDE.md": true, "AGENTS.md": true, ".cursorrules": true, ".windsurfrules": true,
	}
	// _projectAgentDirs are agent config folders in a repo: rules, hooks, MCP, skills.
	_projectAgentDirs = map[string]bool{".cursor": true, ".claude": true}
	// _projectSkipDirs never hold a project's own agent config.
	_projectSkipDirs = map[string]bool{
		"node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
		"venv": true, "__pycache__": true,
	}
)

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

	// User config folders: one target per file, symlinks resolved here, since
	// these are the user's own files (scanning never follows links).
	addFiles := func(label, dir string) {
		for _, name := range entries(dir, false) {
			add(label+"/"+name, filepath.Join(dir, name))
		}
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
		for _, f := range []string{"settings.json", "settings.local.json"} { // hooks live here
			add(label+"/config/"+f, filepath.Join(root, f))
		}
		addFiles(label+"/commands", filepath.Join(root, "commands"))
		addFiles(label+"/agents", filepath.Join(root, "agents"))
	}

	// Cursor: built-in skills, user rules, commands, agents, plugins,
	// team-managed config, and the hooks and MCP servers it runs.
	cursor := filepath.Join(home, ".cursor")
	builtin := filepath.Join(cursor, "skills-cursor")
	for _, dir := range findSkills(builtin, _skillSearchDepth) {
		add("cursor/builtin/"+relPath(builtin, dir), dir)
	}
	for _, d := range []string{"rules", "commands", "agents"} {
		addFiles("cursor/"+d, filepath.Join(cursor, d))
	}
	for _, d := range []string{"plugins", "managed"} {
		for _, name := range entries(filepath.Join(cursor, d), true) {
			add("cursor/"+d+"/"+name, filepath.Join(cursor, d, name))
		}
	}
	for _, f := range []string{"hooks.json", "mcp.json"} {
		add("cursor/config/"+f, filepath.Join(cursor, f))
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

// entries lists a folder's visible files (dirs false) or subfolders (dirs
// true), following symlinks.
func entries(dir string, dirs bool) []string {
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range list {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err == nil && info.IsDir() == dirs && (dirs || info.Mode().IsRegular()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// projectTargets finds agent config in every project under root: .cursor
// and .claude folders, and files agents load on their own (.mcp.json,
// CLAUDE.md, AGENTS.md, .cursorrules). A cloned repo's rules load as soon
// as it's opened. Dependency and build folders, other hidden folders and
// symlinked folders are not entered.
func projectTargets(root string) ([]target, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	var out []target
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable folder: skip it, keep walking
		}
		name := d.Name()
		switch {
		case p == root:
		case d.IsDir() && _projectAgentDirs[name]:
			out = append(out, target{Name: "projects/" + relPath(root, p), Path: p})
			return filepath.SkipDir
		case d.IsDir() && (_projectSkipDirs[name] || strings.HasPrefix(name, ".")):
			return filepath.SkipDir
		case d.Type().IsRegular() && _projectAgentFiles[name]:
			out = append(out, target{Name: "projects/" + relPath(root, p), Path: p})
		}
		return nil
	})
	slices.SortFunc(out, func(a, b target) int { return cmp.Compare(a.Name, b.Name) })
	return out, err
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
				fmt.Fprintf(&b, "%33s skills-audit %q\n", "", r.Path)
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
