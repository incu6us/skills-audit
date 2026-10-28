# skills-audit

Static security check for AI agent skills, plugins and agent config (Claude
Code, Cursor, Codex, ...). It reads files and never runs any of their code.

## Install

With Homebrew (macOS and Linux):

```sh
brew install incu6us/homebrew-tap/skills-audit
```

Or download a binary for Linux, macOS or Windows from the
[releases page](https://github.com/incu6us/skills-audit/releases). With Go:

```sh
go install github.com/incu6us/skills-audit@latest   # Go 1.27.2+, no dependencies
# or, from a clone:
go build -o skills-audit .
```

`skills-audit -version` prints the installed version.

## Usage

```
skills-audit [flags] <target>                       # one skill, plugin or repo
skills-audit [flags] -installed [-projects <dir>]   # everything installed, and/or every repo under dir
skills-audit [flags] -projects <dir>
```

**Flags go before the target.** Go's flag parsing stops at the first non-flag
argument: in `skills-audit ./x -json`, the `-json` is ignored.

### Targets

| Form | Example |
|---|---|
| Local folder or single file | `~/.claude/skills/pdf`, `./SKILL.md` |
| GitHub repo | `https://github.com/owner/repo`, `github.com/owner/repo` |
| Folder or file in a repo, at a ref | `https://github.com/owner/repo/tree/main/skills/pdf`, `…/blob/v1.2/SKILL.md` |
| Any git remote | `https://git.example.com/x.git`, `git@github.com:owner/repo.git` |

Remote targets are fetched shallowly into a temp dir and deleted afterwards
(see [What it checks](#what-it-checks)). The ref in a `tree/` or `blob/` URL
must be one path segment: for a branch with `/` in its name, pass the plain
repo URL.

### Flags

| Flag | Meaning |
|---|---|
| `-installed` | Audit everything installed: see [Installed targets](#installed-targets). Can't be combined with a target. |
| `-projects <dir>` | Audit the agent config of every repo under `<dir>`: see [Projects](#projects). Combines with `-installed`. |
| `-json` | Print JSON instead of text: see [Output](#output). |
| `-v` | Also print info findings (every URL and email). With `-installed` or `-projects`, also list passing targets. |
| `-offline` | Skip the dependency CVE lookup, the only network call besides fetching a remote target. |
| `-history <N>` | List the last N commits that touched the target, with authors and files. Single targets only; ignored with `-installed`/`-projects`. |
| `-baseline <file>` | Hide findings already accepted in `<file>`. |
| `-write-baseline <file>` | Accept every current finding: save their fingerprints to `<file>`. Still prints the report and exits with the real verdict. |
| `-version` | Print the version and exit. |
| `-h` | Show usage. |

### Examples

```sh
./skills-audit ~/.claude/skills/some-skill
./skills-audit https://github.com/owner/repo/tree/main/skills/some-skill
./skills-audit -history 10 -json github.com/owner/repo
./skills-audit -offline ./local-skill                 # no CVE lookup

./skills-audit -installed                             # one line per target needing attention
./skills-audit -installed -v                          # ...and the passing ones
./skills-audit -projects ~/workspace                  # agent config in every repo
./skills-audit -installed -projects ~/workspace -json > audit.json
```

### Baselines: only what's new

```sh
./skills-audit -installed -write-baseline ~/.skills-audit-baseline.json   # after reviewing: accept
./skills-audit -installed -baseline ~/.skills-audit-baseline.json         # later: only new findings
```

A baseline entry is the target's name, rule, file and the flagged code, not
the line number. Edits elsewhere and plugin version bumps don't resurface
accepted findings; a change to the flagged code or a new advisory does.
Baselines for single targets are per target. The file is JSON (a sorted list
of fingerprints), safe to commit: it holds hashes, not code.

### Output

**Text** (default): the target, the commit SHA for remote or git targets (pin
installs to it), then each finding as severity, rule, `file:line`, message and
a snippet, then the endpoints the target refers to, notes (skipped checks,
CVE lookup summary, baseline), and the verdict. Info findings are counted but
hidden unless `-v`.

With `-installed`/`-projects`, one line per target that needs attention,
worst first, with the command that shows its details:

```
VERDICT CRIT HIGH  MED  LOW  TARGET
REVIEW     0    2    1   15  claude/skills/terraform-skill
                                  skills-audit "/Users/you/.claude/skills/terraform-skill"

49 targets: 0 block, 1 review, 48 pass; -v lists passing targets
```

**JSON** (`-json`): for a single target, one report object:

```json
{
  "target": "…", "commit": "…", "files_scanned": 12, "verdict": "REVIEW",
  "counts": {"HIGH": 1, "LOW": 3},
  "findings": [{"rule": "pipe-to-shell", "category": "remote-exec", "severity": "HIGH",
                "file": "SKILL.md", "line": 41, "message": "…", "snippet": "…"}],
  "endpoints": [{"name": "github.com", "count": 2}],
  "notes": ["…"], "baselined": 0, "history": [{"hash": "…", "date": "…", "author": "…", "subject": "…", "files": ["…"]}]
}
```

With `-installed`/`-projects`, an array of `{"name", "path", "report"}`, or
`{"name", "path", "error"}` for a target that couldn't be audited.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS: nothing above low |
| `1` | REVIEW: a medium or high finding |
| `2` | BLOCK: a critical finding |
| `3` | Error (bad usage, unreadable target, failed fetch) |

With `-installed`/`-projects`, the worst result across all targets; any
target that errored makes it `3`.

## Installed targets

`-installed` covers:

- every `~/.claude*` config dir and `CLAUDE_CONFIG_DIR`: skills, each plugin's
  active install (from `installed_plugins.json`), `settings.json` (hooks),
  `commands/` and `agents/`
- Cursor: built-in skills (`skills-cursor`, shown as `cursor/builtin/…`),
  `rules/`, `commands/`, `agents/`, `plugins/`, team-managed config, and the
  hooks and MCP servers in `hooks.json` and `mcp.json`
- `~/.cursor/skills`, `~/.codex/skills` and `~/.agents/skills`

Symlinks in your own config folders (rules, commands) are resolved, so the
real file is scanned. Inside skills, scanning never follows symlinks.

## Projects

`-projects <dir>` finds `.cursor/` and `.claude/` folders and the files agents
load on their own (`.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`) in
every repo under `<dir>`, skipping dependency, build and other hidden folders.
Opening a cloned repo loads its rules, so this is where a booby-trapped repo
shows up.

## What it checks

1. **Fetch safely.** A shallow `git fetch` into a temp dir, with hooks, fsmonitor,
   `ext::`/`file://` transports and the pager turned off. It records the commit SHA
   for pinning and never installs or builds anything.
2. **Instructions.** Hidden Unicode (tag characters, decoded in the report; bidi
   overrides; zero-width characters), HTML comments, phrases that deceive the user,
   stealth actions, instructions to fetch and follow remote content,
   permission-bypass settings, and every URL and email (listed under
   `endpoints`). Request-capture and tunnel hosts are flagged. Cursor `.mdc`
   rules count as prose.
3. **Code.** Network calls, credential paths, environment dumps, `curl | sh`,
   decode-and-run, `eval`/`exec`, encoded blobs, minified scripts, binaries,
   persistence (cron, LaunchAgents, shell rc files), symlinks that escape the
   skill, and `.gitmodules` (submodule code is never fetched). A secret read and
   a network call in the same file raise the severity; on the same line the
   finding is critical.
   **Auto-run:** every hook (`command`, `prompt`, `url`) and MCP server in
   `hooks.json`, `settings.json`, `plugin.json` and `.mcp.json` is listed, decoded
   from JSON and scanned again, so JSON escapes can't hide a command. `npx`/`uvx`
   inside them is medium: that package is fetched and run on every session.
4. **Dependencies.** npm install hooks, non-registry dependencies, `setup.py`,
   custom pip indexes and unpinned requirements. Known CVEs come from the OSV
   database: through `osv-scanner` when installed (every ecosystem it supports),
   otherwise skills-audit sends the pinned versions from `package-lock.json` and
   `requirements*.txt` to osv.dev itself, with nothing to install. Either way,
   package names and versions leave your machine; `-offline` turns the lookup off.
   For more lockfile formats (yarn, pnpm, poetry, Cargo, go.sum), install
   osv-scanner: `brew install osv-scanner`, or
   `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`.
5. **Report.** Severity and `file:line` for every finding, with snippets that
   show invisible characters escaped. Verdict: any critical → BLOCK, medium or
   high → REVIEW, otherwise PASS.

### Scoring

- Documentation and code comments that only *mention* a risky thing score one
  level lower than code that does it. `echo` lines are not exempt, since
  `echo ok; curl … | sh` would be a trivial bypass.
- Findings in test files (test folders, `*.test.*`, `*_test.*`, `test_*`) score
  one level lower: test data legitimately holds hostile strings. They're still
  shown, since a file named like a test can still be code.
- npm install hooks inside bundled `node_modules` are low: those packages are
  already installed, and their hooks run only on a rebuild.
- TypeScript declaration files (`*.d.ts`) are treated as documentation: they
  describe APIs and can't run.

### Secrets in reports

Snippets never carry credentials: auth headers, token/key/secret/password
fields, URL passwords and well-known key formats (AWS, GitHub, GitLab,
OpenAI-style, Slack, JWTs, private keys) are shown as `[redacted]`, and
encoded blobs as a short prefix and their length.

## Limits

- Pattern matching gives false positives and misses determined obfuscation:
  split strings (`cu""rl`, `${a}${b}`), runtime-built commands, and instructions
  that aren't in English. A PASS means nothing obvious was found, not that the
  skill is safe.
- An LLM reading the findings can be prompt-injected by the skill itself,
  so read flagged lines yourself.

## Development

```sh
go test ./...
go test -run '^$' -fuzz=FuzzScanFile -fuzztime=30s .
golangci-lint run ./...
```

`testdata/evil-skill` contains one example per trap and must stay BLOCK.
`testdata/clean-skill` must stay PASS.
