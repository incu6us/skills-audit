# skill-audit

Static security check for AI agent skills (Claude Code, Cursor, Codex, ...).
It reads a skill and never runs any of its code.

```sh
go build -o skill-audit .
./skill-audit ~/.claude/skills/some-skill
./skill-audit https://github.com/owner/repo/tree/main/skills/some-skill
./skill-audit -history 10 -json github.com/owner/repo
./skill-audit -offline ./local-skill    # no CVE lookup
```

For more lockfile formats (yarn, pnpm, poetry, Cargo, go.sum), install
osv-scanner: `brew install osv-scanner`, or
`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`.

Exit codes: `0` pass, `1` review, `2` block, `3` error.

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
   otherwise skill-audit sends the pinned versions from `package-lock.json` and
   `requirements*.txt` to osv.dev itself, with nothing to install. Either way,
   package names and versions leave your machine; `-offline` turns the lookup off.
5. **Report.** Severity and `file:line` for every finding, with snippets that
   show invisible characters escaped. Verdict: any critical → BLOCK, medium or
   high → REVIEW, otherwise PASS.

Documentation and code comments that only *mention* a risky thing score one
level lower than code that does it. `echo` lines are not exempt, since
`echo ok; curl … | sh` would be a trivial bypass.

## Limits

- Pattern matching gives false positives and misses determined obfuscation:
  split strings (`cu""rl`, `${a}${b}`), runtime-built commands, and instructions
  that aren't in English. A PASS means nothing obvious was found, not that the
  skill is safe.
- An LLM reading the findings can be prompt-injected by the skill itself,
  so read flagged lines yourself.
- `--history` assumes a single-segment ref in GitHub `tree/` URLs. For branches
  with `/` in the name, pass the plain repo URL.

## Development

```sh
go test ./...
go test -run '^$' -fuzz=FuzzScanFile -fuzztime=30s .
golangci-lint run ./...
```

`testdata/evil-skill` contains one example per trap and must stay BLOCK.
`testdata/clean-skill` must stay PASS.
