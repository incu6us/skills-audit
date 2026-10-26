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
	verbose := flags.Bool("v", false, "also print info findings (every URL and email)")
	history := flags.Int("history", 0, "list the last `N` commits that touched the skill")
	offline := flags.Bool("offline", false, "skip the dependency CVE lookup, the only network call besides fetching a remote target")
	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, "usage: skill-audit [flags] <path | https://github.com/owner/repo[/tree/ref/dir]>\n\n"+
			"exit codes: 0 pass, 1 review, 2 block, 3 error\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass
		}
		return exitError
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rep, err := audit(ctx, flags.Arg(0), *history, *offline)
	if err == nil {
		if *asJSON {
			err = rep.writeJSON(stdout)
		} else {
			err = rep.writeText(stdout, *verbose)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "skill-audit:", err)
		return exitError
	}
	return rep.exitCode()
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
