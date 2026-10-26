package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// _gitSafety keeps an audited repository from running code through git
// itself: no hooks, no fsmonitor, no signature programs, no ext:: or
// file:// transports, no pager.
var _gitSafety = []string{
	"--no-pager",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "log.showSignature=false",
	"-c", "protocol.ext.allow=never",
	"-c", "protocol.file.allow=never",
}

// _historyDepth is how many commits --history fetches before filtering
// them down to the ones that touched the skill.
const _historyDepth = 100

type source struct {
	root    string // file or directory to scan
	repo    string // git work tree holding root, empty if none
	commit  string
	cleanup func()
}

type remote struct {
	url, ref, sub string
}

// Commit is one recent commit that touched the skill.
type Commit struct {
	Hash    string   `json:"hash"`
	Date    string   `json:"date"`
	Author  string   `json:"author"`
	Subject string   `json:"subject"`
	Files   []string `json:"files,omitempty"`
	// Shallow marks the oldest fetched commit: git shows it as adding
	// every file, so its file list is dropped.
	Shallow bool `json:"shallow,omitempty"`
}

// resolve turns the target into files on disk: a local path as is, a git
// URL as a fresh shallow checkout that is never built or installed.
func resolve(ctx context.Context, target string, history int) (*source, error) {
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("invalid target %q", target)
	}
	if r, ok := parseRemote(target); ok {
		return fetchRemote(ctx, r, history)
	}
	return openLocal(ctx, target)
}

func parseRemote(target string) (remote, bool) {
	if strings.HasPrefix(target, "github.com/") {
		target = "https://" + target
	}
	if strings.HasPrefix(target, "git@") {
		return remote{url: target}, true
	}
	if !strings.HasPrefix(target, "https://") {
		return remote{}, false
	}
	u, err := url.Parse(target)
	if err != nil || u.Host != "github.com" {
		return remote{url: target}, true
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return remote{url: target}, true
	}
	r := remote{url: "https://github.com/" + parts[0] + "/" + strings.TrimSuffix(parts[1], ".git") + ".git"}
	// ponytail: assumes the ref is one path segment; for branches with "/" pass the plain repo URL.
	if len(parts) >= 4 && (parts[2] == "tree" || parts[2] == "blob") {
		r.ref, r.sub = parts[3], path.Join(parts[4:]...)
	}
	return r, true
}

func fetchRemote(ctx context.Context, r remote, history int) (_ *source, err error) {
	if strings.HasPrefix(r.ref, "-") || (r.sub != "" && !filepath.IsLocal(r.sub)) {
		return nil, fmt.Errorf("invalid ref or path for %s", r.url)
	}
	dir, err := os.MkdirTemp("", "skill-audit-")
	if err != nil {
		return nil, err
	}
	src := &source{cleanup: func() { _ = os.RemoveAll(dir) }}
	defer func() {
		if err != nil {
			src.cleanup()
		}
	}()

	fetch := []string{"-C", dir, "fetch", "--quiet", "--no-tags", "--depth", "1"}
	if history > 0 {
		// Trees without old file contents: enough for git log --name-only.
		fetch = []string{"-C", dir, "fetch", "--quiet", "--no-tags", "--filter=blob:none", "--depth", strconv.Itoa(_historyDepth)}
	}
	// init + fetch instead of clone: works the same for a branch, tag or SHA.
	steps := [][]string{
		{"init", "--quiet", dir},
		{"-C", dir, "remote", "add", "origin", r.url},
		append(fetch, "origin", cmp.Or(r.ref, "HEAD")),
		{"-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if _, err := git(ctx, args...); err != nil {
			return nil, err
		}
	}

	if src.repo, err = filepath.EvalSymlinks(dir); err != nil {
		return nil, err
	}
	src.root, err = filepath.EvalSymlinks(filepath.Join(src.repo, filepath.FromSlash(r.sub)))
	if err != nil || !within(src.repo, src.root) {
		return nil, fmt.Errorf("%q not found in %s", r.sub, r.url)
	}
	if src.commit, err = git(ctx, "-C", dir, "rev-parse", "HEAD"); err != nil {
		return nil, err
	}
	return src, nil
}

func openLocal(ctx context.Context, target string) (*source, error) {
	root, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, err
	}
	if root, err = filepath.Abs(root); err != nil {
		return nil, err
	}
	src := &source{root: root, cleanup: func() {}}

	dir := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		dir = filepath.Dir(root)
	}
	if top, err := git(ctx, "-C", dir, "rev-parse", "--show-toplevel"); err == nil {
		src.repo = top
		src.commit, _ = git(ctx, "-C", dir, "rev-parse", "HEAD")
	}
	return src, nil
}

// gitLog lists the last n commits that touched the skill.
func gitLog(ctx context.Context, src *source, n int) ([]Commit, error) {
	if src.repo == "" {
		return nil, errors.New("not a git repository")
	}
	out, err := git(ctx, "-C", src.repo, "log", "-n", strconv.Itoa(n), "--date=short", "--name-only",
		"--format=%x1e%H%x1f%ad%x1f%an%x1f%s", "--", src.root)
	if err != nil {
		return nil, err
	}
	shallow, _ := os.ReadFile(filepath.Join(src.repo, ".git", "shallow")) // absent in full clones

	var commits []Commit
	for _, rec := range strings.Split(out, "\x1e") {
		lines := strings.Split(strings.TrimSpace(rec), "\n")
		head := strings.Split(lines[0], "\x1f")
		if len(head) != 4 {
			continue
		}
		c := Commit{Hash: head[0][:min(len(head[0]), 12)], Date: head[1], Author: escapeInvisible(head[2]), Subject: escapeInvisible(head[3])}
		if c.Shallow = bytes.Contains(shallow, []byte(head[0])); c.Shallow {
			commits = append(commits, c)
			continue
		}
		for _, f := range lines[1:] {
			if f = strings.TrimSpace(f); f != "" {
				c.Files = append(c.Files, escapeInvisible(f))
			}
		}
		commits = append(commits, c)
	}
	return commits, nil
}

func git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append(_gitSafety[:len(_gitSafety):len(_gitSafety)], args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git: %w: %s", err, gitReason(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// gitReason picks git's "fatal:" line; the last stderr line is often advice.
func gitReason(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "fatal:") {
			return line
		}
	}
	return lastLine(stderr)
}
