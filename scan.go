package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	_maxFileSize = 20 << 20 // 20 MiB; regexp is linear, the cap only stops absurd files
	_maxLineLen  = 1000
	_docWindow   = 5 // max lines between a secret and a network call in prose
	_snippetPad  = 60
)

var (
	_docExts   = map[string]bool{".md": true, ".mdx": true, ".mdc": true, ".markdown": true, ".txt": true, ".rst": true}
	_mediaExts = map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".bmp": true,
		".pdf": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".mp3": true, ".mp4": true, ".wav": true,
	}
	_execMagic = [][]byte{
		{0x7f, 'E', 'L', 'F'},
		{'M', 'Z'},
		{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
	}
	_htmlComment       = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	_commentImperative = regexp.MustCompile(`(?i)\b(run|execute|curl|wget|send|upload|fetch|ignore|instructions?|assistant)\b|https?://`)
	_scriptExts        = map[string]bool{
		".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".py": true,
		".sh": true, ".bash": true, ".zsh": true, ".rb": true, ".pl": true, ".php": true, ".ps1": true, ".lua": true,
	}
)

// Finding is one suspicious spot in the audited skill.
type Finding struct {
	Rule     string   `json:"rule"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Message  string   `json:"message"`
	Snippet  string   `json:"snippet,omitempty"`
}

func (f Finding) location() string {
	if f.Line == 0 {
		return f.File
	}
	return f.File + ":" + strconv.Itoa(f.Line)
}

// scanTree checks every file under root, which may also be a single file.
// It returns the findings and the scanned files, relative to root.
func scanTree(root string) ([]Finding, []string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	base := root
	if !info.IsDir() {
		base = filepath.Dir(root)
	}

	var (
		findings []Finding
		files    []string
	)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := relPath(base, p)
		switch {
		case d.IsDir() && d.Name() == ".git":
			return filepath.SkipDir
		case d.IsDir():
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			findings = append(findings, checkSymlink(base, p, rel)...)
			return nil
		case !d.Type().IsRegular():
			return nil
		}

		files = append(files, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() > _maxFileSize {
			findings = append(findings, Finding{
				Rule: "large-file", Category: "file", Severity: Medium, File: rel,
				Message: fmt.Sprintf("%d bytes: too large to scan, review by hand", fi.Size()),
			})
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		findings = append(findings, scanFile(rel, data)...)
		return nil
	})
	return findings, files, err
}

func checkSymlink(base, p, rel string) []Finding {
	target, err := os.Readlink(p)
	if err != nil {
		return nil
	}
	resolved := target
	if !filepath.IsAbs(target) {
		resolved = filepath.Join(filepath.Dir(p), target)
	}
	if within(base, resolved) {
		return nil
	}
	return []Finding{{
		Rule: "symlink-escape", Category: "file", Severity: Medium, File: rel,
		Message: "symlink points outside the skill", Snippet: escapeInvisible(target),
	}}
}

// scanFile checks one file. Its extension picks the rule set: prose
// (.md, .txt, ...) gets the instruction rules, everything else the code rules.
func scanFile(rel string, data []byte) []Finding {
	if filepath.Base(rel) == ".gitignore" { // ponytail: lists paths, can't run anything
		return nil
	}
	ext := strings.ToLower(filepath.Ext(rel))
	binary := bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0
	if binary {
		for _, magic := range _execMagic {
			if bytes.HasPrefix(data, magic) {
				return []Finding{{
					Rule: "executable-binary", Category: "file", Severity: High, File: rel,
					Message: "compiled executable: cannot be reviewed, find its source",
				}}
			}
		}
	}
	switch {
	case _mediaExts[ext]:
		return nil
	case binary:
		return []Finding{{
			Rule: "binary-file", Category: "file", Severity: Medium, File: rel,
			Message: "binary file: cannot be reviewed",
		}}
	}

	kind := codeFile
	if _docExts[ext] {
		kind = docFile
	}
	text := strings.TrimPrefix(string(data), "\uFEFF")
	findings := scanText(rel, text, kind)
	findings = append(findings, depFindings(rel, text)...)
	switch {
	case ext == ".json":
		findings = append(findings, autoRunFindings(rel, text)...)
	case filepath.Base(rel) == ".gitmodules":
		findings = append(findings, Finding{
			Rule: "submodule", Category: "file", Severity: Medium, File: rel,
			Message: "git submodules: their code is not fetched or scanned, audit each one",
		})
	}
	return findings
}

func scanText(rel, text string, kind scope) []Finding {
	var (
		findings  []Finding
		longest   int
		longestAt int
	)
	for i, line := range strings.Split(text, "\n") {
		if len(line) > longest {
			longest, longestAt = len(line), i+1
		}
		lineKind := kind
		if kind == codeFile && isComment(line) {
			lineKind = docFile
		}
		for _, r := range _rules {
			if r.scope.covers(lineKind) {
				findings = append(findings, r.match(rel, lineKind, i+1, line)...)
			}
		}
	}

	if kind == docFile {
		findings = append(findings, htmlComments(rel, text)...)
	} else if longest > _maxLineLen && isScript(rel) {
		findings = append(findings, Finding{
			Rule: "minified-code", Category: "obfuscation", Severity: Medium, File: rel, Line: longestAt,
			Message: fmt.Sprintf("%d-character line: minified or generated code is hard to review", longest),
		})
	}
	return append(findings, correlate(rel, kind, findings)...)
}

// htmlComments flags comments in prose: the agent reads them, rendered
// Markdown hides them from people.
func htmlComments(rel, text string) []Finding {
	var out []Finding
	for _, loc := range _htmlComment.FindAllStringSubmatchIndex(text, -1) {
		body := strings.Join(strings.Fields(text[loc[2]:loc[3]]), " ")
		if body == "" {
			continue
		}
		f := Finding{
			Rule: "html-comment", Category: "instruction", Severity: Low, File: rel,
			Line:    1 + strings.Count(text[:loc[0]], "\n"),
			Message: "HTML comment: hidden when rendered, read by the agent",
			Snippet: snippet(body, 0, min(len(body), 2*_snippetPad)),
		}
		if _commentImperative.MatchString(body) {
			f.Severity, f.Message = Medium, "hidden HTML comment with instructions or links"
		}
		out = append(out, f)
	}
	return out
}

// correlate flags secrets and network calls that appear together: in code
// anywhere in the file, in prose within a few lines. On the same line it is
// almost certainly exfiltration.
func correlate(rel string, kind scope, findings []Finding) []Finding {
	var secrets, nets []Finding
	for _, f := range findings {
		switch {
		case f.Category == "secret" && f.Rule != "dotenv":
			secrets = append(secrets, f)
		case f.Category == "network", f.Category == "endpoint" && f.Severity >= High:
			nets = append(nets, f)
		}
	}

	var best *Finding
	for _, s := range secrets {
		for _, n := range nets {
			gap := abs(s.Line - n.Line)
			switch {
			case gap == 0:
				return []Finding{{
					Rule: "secret-exfil", Category: "exfiltration", Severity: Critical, File: rel, Line: s.Line,
					Message: "reads secrets and sends them over the network on the same line",
					Snippet: s.Snippet,
				}}
			case best == nil && (kind == codeFile || gap <= _docWindow):
				best = &Finding{
					Rule: "secret-and-network", Category: "exfiltration", Severity: High, File: rel, Line: s.Line,
					Message: fmt.Sprintf("reads secrets here and calls the network at line %d: check where the data goes", n.Line),
					Snippet: s.Snippet,
				}
			}
		}
	}
	if best == nil {
		return nil
	}
	return []Finding{*best}
}

// snippet returns the match with some context, invisible characters escaped.
func snippet(line string, start, end int) string {
	lo, hi := max(0, start-_snippetPad), min(len(line), end+_snippetPad)
	for lo > 0 && !utf8.RuneStart(line[lo]) {
		lo--
	}
	for hi < len(line) && !utf8.RuneStart(line[hi]) {
		hi++
	}
	s := escapeInvisible(strings.TrimSpace(line[lo:hi]))
	if lo > 0 {
		s = "…" + s
	}
	if hi < len(line) {
		s += "…"
	}
	return s
}

// escapeInvisible makes hidden characters and terminal escapes visible,
// so a finding can't hide itself in the report. Runs of tag characters
// collapse to a count; the unicode-tag finding decodes them.
func escapeInvisible(s string) string {
	var b strings.Builder
	tags := 0
	for _, r := range s {
		if isTag(r) {
			tags++
			continue
		}
		if tags > 0 {
			fmt.Fprintf(&b, "[%d hidden tag chars]", tags)
			tags = 0
		}
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == ' ' || unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u{%X}`, r)
		}
	}
	if tags > 0 {
		fmt.Fprintf(&b, "[%d hidden tag chars]", tags)
	}
	return b.String()
}

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// decodeTags reveals the ASCII text smuggled in Unicode tag characters.
func decodeTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	return b.String()
}

// isComment reports whether a code line is a comment: it never runs, so it
// is scored like prose. Strings (echo "...") are not exempt, since
// "echo ok; curl ... | sh" would be a trivial bypass.
func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "* ") ||
		(strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!"))
}

// isScript limits the minified check to code; data and markup files
// (XML, JSON, type declarations) have long lines legitimately.
func isScript(rel string) bool {
	return _scriptExts[strings.ToLower(filepath.Ext(rel))] && !strings.HasSuffix(rel, ".d.ts")
}

func relPath(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

func within(base, p string) bool {
	r, err := filepath.Rel(base, p)
	return err == nil && filepath.IsLocal(r)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
