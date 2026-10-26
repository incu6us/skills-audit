package main

import (
	"fmt"
	"regexp"
)

// Severity ranks how much attention a finding needs.
type Severity int

// Severity levels, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var _severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("Severity(%d)", int(s))
	}
	return _severityNames[s]
}

// MarshalText renders the severity by name in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// scope limits a rule to prose the agent reads, to code, or to both.
type scope int

const (
	anyFile scope = iota
	docFile
	codeFile
)

func (s scope) covers(kind scope) bool { return s == anyFile || s == kind }

type rule struct {
	id       string
	category string
	severity Severity
	scope    scope
	re       *regexp.Regexp
	ignore   *regexp.Regexp // known-benign matches
	message  string

	// proseLower drops severity one level in prose: docs mostly describe
	// what scripts actually do.
	proseLower bool
}

func mustRe(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var _rules = []rule{
	// Hidden text: the agent reads these characters, people don't see them.
	{
		id: "unicode-tag", category: "hidden-text", severity: Critical,
		re:      mustRe(`[\x{E0000}-\x{E007F}]`),
		message: "invisible Unicode tag characters (hidden instructions)",
	},
	{
		id: "unicode-bidi", category: "hidden-text", severity: High,
		re:      mustRe(`[\x{202A}-\x{202E}\x{2066}-\x{2069}]`),
		message: "bidirectional override: the text shown differs from the text read",
	},
	// ponytail: U+200D (zero-width joiner) is left out, emoji sequences use it everywhere.
	{
		id: "unicode-zero-width", category: "hidden-text", severity: Medium,
		re:      mustRe(`[\x{00AD}\x{180E}\x{200B}\x{200C}\x{200E}\x{200F}\x{2060}-\x{2064}\x{FEFF}]`),
		message: "zero-width or invisible character",
	},

	// Instructions aimed at the agent.
	{
		id: "injection-phrase", category: "instruction", severity: High, scope: docFile,
		re: mustRe(`(?i)["“'(]?\b(ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|directions|rules)` +
			`|(do not|don't|never) (tell|inform|notify|alert) the user( to\b)?` +
			`|((never|not|n't|avoid)\b[^.]{0,80}?)?without (telling|informing|notifying|alerting) the user` +
			`|(hide|conceal) (this|it|that) from the user` +
			`|the user (must|should) not (know|see|notice))\b`),
		// Quoted attack examples, safety rules ("never X without telling the user")
		// and advice ("don't tell the user to ...") are benign.
		ignore:  mustRe(`(?i)^["“'(]|^(never|not|n't|avoid)\b| to$`),
		message: "tells the agent to deceive or bypass the user",
	},
	{
		id: "secrecy-phrase", category: "instruction", severity: Medium, scope: docFile,
		re:      mustRe(`(?i)\b(do not|don't|never) (mention|disclose|reveal|display|show) (this|that|these|it|the following|any of this)\b`),
		message: "asks the agent to keep something quiet",
	},
	{
		id: "stealth-action", category: "instruction", severity: High, scope: docFile,
		re:      mustRe(`(?i)\b((not|n't|never|no)\s+)?(silently|secretly|covertly|quietly|stealthily|discreetly)\s+(run|execute|send|upload|post|copy|install|add|append|modify|write|collect|exfiltrate|download|delete)\b`),
		ignore:  mustRe(`(?i)^(not|n't|never|no)\s`),
		message: "asks the agent to act without the user noticing",
	},
	{
		id: "stealth-word", category: "instruction", severity: Low, scope: docFile, // also covers "silently read"
		re:      mustRe(`(?i)\b(silently|secretly|covertly|stealthily)\b`),
		message: "stealth wording: check the context",
	},
	{
		id: "remote-instructions", category: "instruction", severity: Medium, scope: docFile,
		re: mustRe(`(?i)\b(fetch|download|read|load|retrieve|curl|get)\b[^.\n]{0,80}https?://\S+[^.\n]{0,80}\b(follow|obey|execute|apply|run)\b` +
			`|\b(follow|obey|execute|apply)\b[^.\n]{0,40}\b(instructions?|steps|commands?|rules)\b[^.\n]{0,20}\b(at|from|in)\s+<?https?://`),
		message: "tells the agent to follow instructions fetched at runtime: what you reviewed is not what runs",
	},
	{
		id: "pre-response-action", category: "instruction", severity: Low, scope: docFile,
		re:      mustRe(`(?i)\b(before|prior to) (responding|answering|replying)\b.{0,60}\b(run|execute|curl|wget|fetch|send|upload|post)\b`),
		message: "runs something before answering",
	},

	// Where data could go.
	{
		id: "exfil-endpoint", category: "endpoint", severity: Critical,
		re:      mustRe(`(?i)\b(webhook\.site|webhook\.cool|requestbin\.(com|net)|pipedream\.net|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator\.net|canarytokens\.com|beeceptor\.com|hookbin\.com|requestcatcher\.com)\b`),
		message: "request-capture service, a common drop for stolen data", proseLower: true,
	},
	{
		id: "tunnel-endpoint", category: "endpoint", severity: High,
		re:      mustRe(`(?i)//([\w-]+\.)*(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt|discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|file\.io|0x0\.st|temp\.sh)`),
		message: "tunnel, paste or chat-webhook endpoint that can receive data", proseLower: true,
	},
	{
		id: "raw-ip-url", category: "endpoint", severity: High,
		re:      mustRe(`(?i)\b(https?|ftp|wss?)://\d{1,3}(\.\d{1,3}){3}`),
		ignore:  mustRe(`://(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)`),
		message: "URL with a raw public IP address",
	},
	{
		id: "url", category: "endpoint", severity: Info,
		re:      mustRe(`(?i)\b(https?|wss?|ftp)://[^\s"'<>()\[\]{}\x60|\\]+`),
		message: "URL",
	},
	{
		id: "email", category: "endpoint", severity: Info,
		re:      mustRe(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`),
		ignore:  mustRe(`^git@|\.(png|jpe?g|gif|svg|webp)$`),
		message: "email address",
	},

	// Network and secrets.
	{
		id: "network-call", category: "network", severity: Low,
		re: mustRe(`(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|ncat|netcat|socat|scp|sftp)\b|\bnc\s+-` +
			`|\brequests\.(get|post|put|patch|request|session)\b|\burllib\b|\bhttpx\.|\baiohttp\b|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b` +
			`|\bhttp\.(Get|Post|PostForm|NewRequest)\b|\bnet\.Dial|\bsocket\.(socket|connect|create_connection)\b|/dev/(tcp|udp)/|\bnew WebSocket\b`),
		message: "network access",
	},
	{
		id: "secret-file", category: "secret", severity: Medium,
		re: mustRe(`(?i)(\.ssh(/(id_\w*|config|authorized_keys|\*)|/?([\s"'\x60),;]|$))|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.aws/(credentials|config)|\.config/gcloud|application_default_credentials` +
			`|\.azure/|\.kube/config|\.docker/config\.json|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|\.gnupg|\bkeychain\b` +
			`|\bsecurity\s+(find|dump)-(generic-password|internet-password|keychain)|(?-i:Login Data|Local State)|Cookies\.binarycookies|/Cookies\b` +
			`|wallet\.dat|\.(bash|zsh)_history)`),
		message: "touches credentials or private data", proseLower: true,
	},
	{
		id: "dotenv", category: "secret", severity: Low,
		re:      mustRe(`(^|[^\w.])\.env(\.[a-z]+)?\b`),
		message: "reads a .env file",
	},
	{
		id: "env-dump", category: "secret", severity: Medium,
		re:      mustRe(`(?i)\b(json\.dumps|str|repr|dict)\(\s*os\.environ\s*\)|JSON\.stringify\(\s*process\.env\s*\)|\bprintenv\b|(^|[;&|]\s*)env\s*($|[|>])`),
		message: "dumps every environment variable (API keys live there)", proseLower: true,
	},

	// Code execution and obfuscation.
	{
		id: "pipe-to-shell", category: "remote-exec", severity: Critical,
		re: mustRe(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b` +
			`|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\s*(-\s*)?($|[;&|)'"])` +
			`|\b(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b` +
			`|\b(ba|z)?sh\s+<\(\s*(curl|wget)\b` +
			`|\beval\s+["']?\$\(\s*(curl|wget)\b` +
			`|\b(iex|invoke-expression)\b.*\b(downloadstring|iwr|invoke-webrequest)\b`),
		message:    "downloads code and runs it: what you reviewed is not what runs",
		proseLower: true,
	},
	{
		id: "runtime-package", category: "remote-exec", severity: Low, // raised to Medium in hook and MCP commands
		re:         mustRe(`\b(npx|bunx|uvx|pnpm\s+dlx|yarn\s+dlx|pipx\s+run)\b`),
		message:    "downloads and runs a package at runtime: that code is not in this audit",
		proseLower: true,
	},
	{
		id: "decode-and-run", category: "obfuscation", severity: High,
		re:      mustRe(`(?i)\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(exec|eval)\s*\(\s*([\w.]+\.)?(b64decode|atob|decode)\s*\(`),
		message: "decodes hidden code and runs it",
	},
	{
		id: "eval-exec", category: "exec", severity: Medium,
		re:      mustRe(`(^|[^.\w])(eval|exec)\s*\(|\bnew\s+Function\s*\(|\b__import__\s*\(|\bpickle\.loads?\b|\bmarshal\.loads\b`),
		message: "dynamic code execution", proseLower: true,
	},
	{
		id: "shell-exec", category: "exec", severity: Low,
		re:      mustRe(`\bsubprocess\.|\bos\.(system|popen)\b|\bchild_process\b|\bexecSync\b|\bexec\.Command\b|Runtime\.getRuntime\(\)\.exec|\bshell\s*=\s*True\b`),
		message: "runs shell commands",
	},
	{
		id: "base64-decode", category: "obfuscation", severity: Low,
		re:      mustRe(`(?i)\bbase64\s+(-d|--decode)\b|\bb64decode\b|\batob\s*\(|Buffer\.from\([^)]*["']base64["']|\bbase64\.(Std|URL|RawStd|RawURL)Encoding\.DecodeString|FromBase64String`),
		message: "decodes base64 at runtime",
	},
	{
		id: "encoded-blob", category: "obfuscation", severity: Medium,
		re:      mustRe(`[A-Za-z0-9+/]{200,}={0,2}`),
		message: "long encoded blob",
	},
	{
		id: "char-escapes", category: "obfuscation", severity: Medium,
		re:      mustRe(`(\\x[0-9a-fA-F]{2}){16,}|(\\u[0-9a-fA-F]{4}){16,}|String\.fromCharCode\(\s*\d+(\s*,\s*\d+){10,}|(chr\(\d+\)\s*\+\s*){5,}`),
		message: "string built from escapes or char codes",
	},

	// Persistence and agent settings.
	{
		id: "persistence", category: "persistence", severity: High,
		re:      mustRe(`\bcrontab\b|/LaunchAgents\b|/LaunchDaemons\b|\blaunchctl\s+(load|bootstrap|submit)\b|\bsystemctl\s+(--user\s+)?enable\b|/etc/systemd/|\bauthorized_keys\b|/etc/sudoers`),
		message: "installs something that survives a restart or grants access",
	},
	{
		id: "shell-rc", category: "persistence", severity: Medium,
		re:         mustRe(`\.(bashrc|zshrc|bash_profile|zprofile|zshenv|zlogin)\b|(~|HOME\}?)/\.profile\b`),
		message:    "touches shell startup files",
		proseLower: true,
	},
	{
		id: "agent-config", category: "agent-config", severity: Medium,
		re:      mustRe(`\bbypassPermissions\b|--dangerously-skip-permissions|\bdangerouslyDisableSandbox\b|\.claude/settings(\.local)?\.json|\.claude\.json\b|\bclaude_desktop_config\.json\b|\.cursor/(mcp|cli-config)\.json|\.codex/config\.toml|\bskipDangerousModePermissionPrompt\b`),
		message: "touches AI agent settings or permission bypasses", proseLower: true,
	},
}

// match returns the rule's findings on one line: every match for
// inventory rules, the first non-ignored one otherwise.
func (r rule) match(file string, kind scope, line int, text string) []Finding {
	sev := r.severity
	if r.proseLower && kind == docFile {
		sev = max(Info, sev-1)
	}
	var out []Finding
	for _, loc := range r.re.FindAllStringIndex(text, -1) {
		m := text[loc[0]:loc[1]]
		if r.ignore != nil && r.ignore.MatchString(m) {
			continue
		}
		f := Finding{
			Rule:     r.id,
			Category: r.category,
			Severity: sev,
			File:     file,
			Line:     line,
			Message:  r.message,
			Snippet:  snippet(text, loc[0], loc[1]),
		}
		switch {
		case r.severity == Info:
			f.Snippet = escapeInvisible(m)
		case r.id == "encoded-blob": // may itself be a credential
			f.Snippet = escapeInvisible(m[:8]) + fmt.Sprintf("… (%d chars)", len(m))
		case r.id == "unicode-tag":
			f.Message += fmt.Sprintf(", decoded: %q", decodeTags(text))
		}
		out = append(out, f)
		if r.severity != Info {
			break
		}
	}
	return out
}
