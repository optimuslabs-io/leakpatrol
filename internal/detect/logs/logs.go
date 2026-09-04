// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package logs is the egress tier. It reads whatever the operator can export --
// firewall, proxy, DNS resolver, VPC flow logs, a provisioner's own stdout -- as
// lines, from files or stdin, plain or gzipped, in any format, and looks for the
// exfil endpoint. It is the only tier that can say data LEFT rather than that it
// could have.
package logs

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

// maxEvidence bounds the evidence rows kept per finding. The count in the title
// is always the true total; a flow log with a million hits does not need a
// million rows to make its point.
const maxEvidence = 1000

type Detector struct{}

func New() *Detector { return &Detector{} }

func (*Detector) Name() string { return "logs" }

func (*Detector) Describe() string {
	return "egress logs (firewall / proxy / DNS / flow, any format) for the exfil domain, IP, URL path and header, and provisioner output for the sentinel"
}

func (*Detector) Ready(env *engine.Env) string {
	if len(env.Logs) == 0 {
		return "no --logs given (files, .gz, or `-` for stdin)"
	}
	return ""
}

// Material: an absent flow-log export is coverage information, not a verdict change.
func (*Detector) Material() bool { return false }

func (d *Detector) Run(ctx context.Context, env *engine.Env) engine.Result {
	var res engine.Result
	egress := &model.Finding{
		ID: "logs.egress_hit", Detector: d.Name(), Severity: model.SevCritical, Path: model.PathEgress,
		Title: "Traffic to the exfil endpoint in egress logs",
		Detail: "The lookalike domain, rogue IP, exfil URL path or exfil header appears in a log you exported. " +
			"Credentials reachable from the source of that traffic left the network.",
	}
	sentinel := &model.Finding{
		ID: "logs.sentinel_hit", Detector: d.Name(), Severity: model.SevCritical, Path: model.PathExecuted,
		Title:  "Terraform sentinel in provisioner output -- the harvester ran",
		Detail: "The external data source the tampered module added was evaluated by a provisioner whose logs you exported.",
	}
	egressN, sentinelN, lines := 0, 0, 0

	for _, src := range env.Logs {
		if ctx.Err() != nil {
			break
		}
		r, closer, err := open(src, env.Stdin)
		if err != nil {
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Path: src, Message: err.Error(), Material: true})
			continue
		}
		disp := src
		if src == "-" {
			disp = "stdin"
		} else {
			disp = hostfs.Display(src, env.Home)
		}
		fileLines := 0
		err = scan.ScanLines(r, scan.TextMarkers(), func(h scan.Hit) bool {
			if h.Line > fileLines {
				fileLines = h.Line
			}
			ev := model.Evidence{Source: disp, SourceLine: h.Line, Note: h.Marker.Label}
			if h.Marker.Egress {
				egressN++
				if len(egress.Evidence) < maxEvidence {
					egress.Evidence = append(egress.Evidence, ev)
				}
			} else {
				sentinelN++
				if len(sentinel.Evidence) < maxEvidence {
					sentinel.Evidence = append(sentinel.Evidence, ev)
				}
			}
			return ctx.Err() == nil
		})
		closer()
		lines += fileLines
		if err != nil {
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "parse", Path: disp, Message: err.Error(), Material: true})
		}
		env.Pulse(d.Name(), fmt.Sprintf("%s · %d egress hits · %d sentinel hits", disp, egressN, sentinelN))
	}

	if egressN > 0 {
		egress.Title = fmt.Sprintf("%s -- %s", egress.Title, engine.Plural(egressN, "matching line"))
		res.Findings = append(res.Findings, *egress)
	}
	if sentinelN > 0 {
		sentinel.Title = fmt.Sprintf("%s -- %s", sentinel.Title, engine.Plural(sentinelN, "matching line"))
		res.Findings = append(res.Findings, *sentinel)
	}
	switch {
	case egressN > 0 && sentinelN > 0:
		res.Summary = fmt.Sprintf("%s: %d egress, %d sentinel", engine.Plural(len(env.Logs), "source"), egressN, sentinelN)
	case egressN > 0:
		res.Summary = fmt.Sprintf("%s: %s to the exfil endpoint", engine.Plural(len(env.Logs), "source"), engine.Plural(egressN, "hit"))
	case sentinelN > 0:
		res.Summary = fmt.Sprintf("%s: %s", engine.Plural(len(env.Logs), "source"), engine.Plural(sentinelN, "sentinel hit"))
	default:
		res.Summary = fmt.Sprintf("%s, nothing found", engine.Plural(len(env.Logs), "source"))
	}
	res.Limitations = append(res.Limitations,
		"Egress evidence is only as complete as your log retention over 2026-08-31 07:35 UTC onward. "+
			"A clean logs tier over logs that start later proves nothing.",
		"Lines are matched as text. A log that stores the destination only as an encoded field, or that "+
			"records DNS answers without the queried name, will not match.")
	return res
}

// open returns a line source for a path or stdin, transparently gunzipping.
func open(src string, stdin io.Reader) (io.Reader, func(), error) {
	var raw io.Reader
	closer := func() {}
	if src == "-" {
		if stdin == nil {
			stdin = os.Stdin
		}
		raw = stdin
	} else {
		f, err := hostfs.OpenRead(src)
		if err != nil {
			return nil, nil, err
		}
		raw = f
		closer = func() { f.Close() }
	}
	br := bufio.NewReaderSize(raw, 64*1024)
	if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			closer()
			return nil, nil, err
		}
		// gzip.Reader handles concatenated members (rotated logs joined with cat).
		return gz, closer, nil
	}
	return br, closer, nil
}
