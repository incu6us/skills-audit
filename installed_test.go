package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInstalledTargets(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	mkSkill := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# s\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A fake home in a temp dir: the standard ~/.claude, plus a second config
	// dir passed as CLAUDE_CONFIG_DIR, the way people run separate profiles.
	mkSkill(filepath.Join(home, ".claude", "skills", "default-skill"))
	conf := filepath.Join(home, ".claude-work")
	mkSkill(filepath.Join(conf, "skills", "plain"))
	mkSkill(filepath.Join(conf, "skills", "synced", "abc123", "nested"))
	mkSkill(filepath.Join(home, "elsewhere", "linked"))
	if err := os.Symlink(filepath.Join(home, "elsewhere", "linked"), filepath.Join(conf, "skills", "linked")); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(conf, "plugins", "cache", "mkt", "tool", "2.0.0")
	mkSkill(filepath.Join(active, "skills", "inner"))
	mkSkill(filepath.Join(conf, "plugins", "cache", "mkt", "tool", "1.0.0", "skills", "inner"))
	write(filepath.Join(conf, "plugins", "installed_plugins.json"),
		`{"version":2,"plugins":{"tool@mkt":[{"scope":"user","installPath":"`+active+`"}]}}`)
	mkSkill(filepath.Join(home, ".cursor", "skills", "cur"))
	write(filepath.Join(home, ".claude.json"), "{}")
	write(filepath.Join(conf, "settings.json"), `{"hooks":{}}`)
	write(filepath.Join(conf, "commands", "deploy.md"), "# deploy")

	// Cursor: built-in skill, a rule symlinked from elsewhere, hooks, a plugin.
	cursor := filepath.Join(home, ".cursor")
	mkSkill(filepath.Join(cursor, "skills-cursor", "review"))
	write(filepath.Join(home, "repo", "rule.mdc"), "rule")
	if err := os.MkdirAll(filepath.Join(cursor, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "repo", "rule.mdc"), filepath.Join(cursor, "rules", "linked.mdc")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(cursor, "rules", ".hidden"), "x")
	write(filepath.Join(cursor, "hooks.json"), `{"hooks":{}}`)
	if err := os.MkdirAll(filepath.Join(cursor, "plugins", "local"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := installedTargets(home, conf) // conf also matches the .claude* glob: must not duplicate
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(got))
	for i, tg := range got {
		names[i] = tg.Name
	}
	want := []string{
		"claude-work/commands/deploy.md",
		"claude-work/config/settings.json",
		"claude-work/plugins/tool@mkt",
		"claude-work/skills/linked",
		"claude-work/skills/plain",
		"claude-work/skills/synced/abc123/nested",
		"claude/skills/default-skill",
		"cursor/builtin/review",
		"cursor/config/hooks.json",
		"cursor/plugins/local",
		"cursor/rules/linked.mdc",
		"cursor/skills/cur",
	}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	for _, tg := range got {
		if tg.Name == "claude-work/plugins/tool@mkt" && filepath.Base(tg.Path) != "2.0.0" {
			t.Errorf("plugin path = %s, want the active 2.0.0 install", tg.Path)
		}
		if tg.Name == "cursor/rules/linked.mdc" && filepath.Base(filepath.Dir(tg.Path)) != "repo" {
			t.Errorf("rule path = %s, want the symlink resolved to repo/rule.mdc", tg.Path)
		}
	}
}

func TestPluginDirsWithoutRegistry(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cache", "mkt", "tool", "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := pluginDirs(root); filepath.Base(got["tool@mkt"]) != "1.0.0" {
		t.Errorf("pluginDirs = %v, want tool@mkt from the cache", got)
	}
}

func TestProjectTargets(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, p := range []string{
		"api/.cursor/rules/style.mdc",
		"api/CLAUDE.md",
		"api/services/billing/AGENTS.md",
		"api/node_modules/pkg/CLAUDE.md", // dependency: skipped
		"api/.github/CLAUDE.md",          // other hidden folder: skipped
		"web/.claude/settings.json",
		"web/.mcp.json",
		"web/README.md", // not agent config
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := projectTargets(root)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(got))
	for i, tg := range got {
		names[i] = tg.Name
	}
	want := []string{
		"projects/api/.cursor",
		"projects/api/CLAUDE.md",
		"projects/api/services/billing/AGENTS.md",
		"projects/web/.claude",
		"projects/web/.mcp.json",
	}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}
