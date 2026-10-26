// Command skill-audit statically checks an AI agent skill for hidden
// instructions, data exfiltration, remote code execution and risky
// dependencies. It never runs the skill's code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
)

const (
	exitPass = iota
	exitReview
	exitBlock
	exitError
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("skill-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print the report as JSON")
	verbose := flags.Bool("v", false, "also print info findings (every URL and email); with -installed, list passing targets")
	history := flags.Int("history", 0, "list the last `N` commits that touched the skill")
	offline := flags.Bool("offline", false, "skip the dependency CVE lookup, the only network call besides fetching a remote target")
	installed := flags.Bool("installed", false, "audit every installed skill and plugin (~/.claude*, CLAUDE_CONFIG_DIR, ~/.cursor, ~/.codex, ~/.agents)")
	baselinePath := flags.String("baseline", "", "hide findings already accepted in this `file`")
	writeBaseline := flags.String("write-baseline", "", "accept every current finding: save their fingerprints to this `file`")
	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, "usage: skill-audit [flags] <path | https://github.com/owner/repo[/tree/ref/dir]>\n"+
			"       skill-audit [flags] -installed\n\n"+
			"exit codes: 0 pass, 1 review, 2 block, 3 error\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitError
	}
	if *installed == (flags.NArg() == 1) || flags.NArg() > 1 {
		flags.Usage()
		return exitError
	}

	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, "skill-audit:", err)
		return exitError
	}
	targets := []target{{Path: flags.Arg(0)}}
	if *installed {
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(err)
		}
		if targets, err = installedTargets(home, os.Getenv("CLAUDE_CONFIG_DIR")); err != nil {
			return fail(err)
		}
		*history = 0
	}
	var accepted baseline
	if *baselinePath != "" {
		var err error
		if accepted, err = loadBaseline(*baselinePath); err != nil {
			return fail(err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	results := make([]result, len(targets))
	var fingerprints []string
	for i, t := range targets {
		results[i].target = t
		rep, err := audit(ctx, t.Path, *history, *offline)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		fingerprints = append(fingerprints, rep.fingerprints(t.Name)...)
		rep.applyBaseline(t.Name, accepted)
		results[i].Report = rep
	}

	if !*installed && results[0].Error != "" {
		return fail(errors.New(results[0].Error))
	}
	if *writeBaseline != "" {
		n, err := saveBaseline(*writeBaseline, fingerprints)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(stderr, "skill-audit: accepted %d findings into %s\n", n, *writeBaseline)
	}

	var err error
	switch {
	case *installed && *asJSON:
		err = writeJSON(stdout, results)
	case *installed:
		err = writeSummary(stdout, results, *verbose)
	case *asJSON:
		err = writeJSON(stdout, results[0].Report)
	default:
		err = results[0].Report.writeText(stdout, *verbose)
	}
	if err != nil {
		return fail(err)
	}

	code := exitPass
	for _, r := range results {
		code = max(code, r.exitCode())
	}
	return code
}

func audit(ctx context.Context, target string, history int, offline bool) (*Report, error) {
	src, err := resolve(ctx, target, history)
	if err != nil {
		return nil, err
	}
	defer src.cleanup()

	findings, files, err := scanTree(src.root)
	if err != nil {
		return nil, err
	}
	vulns, notes := checkCVEs(ctx, src.root, files, offline)

	rep := &Report{Target: target, Commit: src.commit, Files: len(files), Notes: notes}
	if history > 0 {
		if rep.History, err = gitLog(ctx, src, history); err != nil {
			rep.Notes = append(rep.Notes, "history: "+err.Error())
		}
	}
	rep.setFindings(append(findings, vulns...))
	return rep, nil
}
