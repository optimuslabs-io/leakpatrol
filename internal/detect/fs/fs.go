// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package fs is the on-host tier: it walks provisioner hosts, workspaces and
// laptops for the harvester itself, the tampered Terraform module, and the traces
// the harvester leaves when it runs.
//
// It runs in two passes, because the two things it hunts for have very different
// costs and confidence:
//
//   - PASS 1 (always) reads only files whose NAME or LOCATION already justifies
//     it: the harvester's own filename, a Terraform file (checked for the
//     telemetry block), a shell history, or anywhere Terraform actually caches
//     fetched modules (inspect.EagerRead). Every one of those is HIGH or CRITICAL
//     if it fires at all -- an operator who gets a hit here already has the
//     verdict, and everything else on the disk is extra location, not extra
//     answer. On a real host this touches a few hundred files, not hundreds of
//     thousands, so it finishes in well under a second.
//   - PASS 2 (only if pass 1 found nothing HIGH or above) reads everything else:
//     remaining text files for the domain/IP/header markers, and any leftover
//     file small enough to plausibly BE a renamed script, hashed regardless of
//     whether it looks like text. This is the slow, exhaustive sweep, and it only
//     runs when it is the only thing standing between a clean disk and a false
//     CLEAN -- never when pass 1 already answered the question.
package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/optimuslabs-io/leakpatrol/internal/detect/inspect"
	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

const DefaultMaxFileSize = 8 << 20

// sniffBytes is how much of a file is read before deciding what to do with the
// rest. None of the indicators live inside a compiled binary, so a file that
// fails this sniff and is not eligible for the size-band hash below is dropped
// without a full read -- which is most of the bytes on any real host.
const sniffBytes = 8192

// hashSizeBand bounds a full read+hash of a file that is neither text nor
// harvester-named. It exists for exactly one reason: pass 2's job is to catch a
// RENAMED payload, and a renamed copy of a few-KB shell script might have been
// re-encoded, padded, or otherwise made to fail the text sniff without changing
// what it does. 256 KiB is generous headroom over any plausible script size and
// cheap to hash outright, so this closes that gap rather than trusting the name.
const hashSizeBand = 256 << 10

type Detector struct{}

func New() *Detector { return &Detector{} }

func (*Detector) Name() string { return "fs" }

func (*Detector) Describe() string {
	return "harvester scripts by SHA-256 and name, the telemetry data block in Terraform, exfil indicators in shell histories and module caches"
}

func (*Detector) Ready(*engine.Env) string { return "" }

// Material: fs always runs, so this is moot; unreadable roots are reported as
// material ScanErrors instead.
func (*Detector) Material() bool { return false }

// Scope says what an fs run over the given roots actually covers. Default roots
// on an operator's laptop are that laptop -- not the provisioner -- and the
// preflight and header say so rather than letting a CLEAN imply host coverage.
func Scope(roots []string) string {
	if len(roots) == 0 {
		return "default roots on THIS machine (histories, Terraform + Coder caches, tmp) -- a provisioner scan means running `fs /` on the provisioner host or pod"
	}
	return "scanning " + strings.Join(roots, ", ")
}

// workers bounds parallel file reads AND the directory-walk fan-out. Each file is
// read once and then CPU-scanned (NUL sniff, per-line marker match, maybe a hash),
// so with a warm page cache the work is CPU-bound, not the pure IO the old cap of 8
// assumed -- a live benchmark over ~145k files was walk-starved at 8. Use one
// reader per core with a floor of 4; the walk applies backpressure through the
// 256-slot job channel, so this does not stampede a slow disk.
func workers() int {
	n := runtime.NumCPU()
	if n < 4 {
		n = 4
	}
	return n
}

type job struct {
	path string
	size int64
}

func (d *Detector) Run(ctx context.Context, env *engine.Env) engine.Result {
	var res engine.Result
	roots := env.Roots
	if len(roots) == 0 {
		roots = hostfs.DefaultRoots(env.Home)
	}
	maxSize := env.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}

	// The running binary is skipped by path. It cannot match anyway -- its markers
	// are stored reversed -- but skipping it by identity is cheaper than proving that
	// on every run, and keeps the file count honest.
	self, _ := os.Executable()

	col := &inspect.Collector{Tier: d.Name()}
	var (
		total, denied, skippedBinary atomic.Int64
		errMu                        sync.Mutex
	)
	report := func(p string, err error) {
		material := true
		kind := "io"
		if errors.Is(err, fs.ErrPermission) {
			kind = "permission"
			denied.Add(1)
			// macOS TCC denies ~/Library/* and the Documents/Desktop/Downloads trio on
			// every un-entitled terminal. Degrading every Mac to INDETERMINATE for that
			// would make CLEAN unreachable, so those are recorded but immaterial.
			if runtime.GOOS == "darwin" && tccPath(p, env.Home) {
				material = false
			}
		}
		errMu.Lock()
		res.Errors = append(res.Errors, model.ScanError{
			Detector: d.Name(), Kind: kind, Path: hostfs.Display(p, env.Home), Message: err.Error(), Material: material,
		})
		errMu.Unlock()
	}

	// PASS 1: walk once. Files whose name or location alone justify a read
	// (inspect.EagerRead) are inspected immediately, in parallel. Everything else
	// is only recorded -- path and size -- into deferred, for pass 2 to decide
	// whether it is even needed.
	var (
		deferredMu sync.Mutex
		deferred   []job
	)
	runPass(ctx, env, d.Name(), col, report, &total, &skippedBinary, func(add func(job)) error {
		// One parallel walk over all roots, fanning out across subdirectories so the
		// inspection pool below stays fed instead of starving behind a single-goroutine
		// getdents loop. visit runs on many goroutines: add is a channel send, and the
		// deferred slice is mutex-guarded, so both are safe.
		walker := &hostfs.Walker{OnError: report}
		walker.WalkParallel(ctx, roots, workers(), func(p string, de fs.DirEntry) {
			if p == self {
				return
			}
			info, err := de.Info()
			if err != nil {
				return
			}
			j := job{path: p, size: info.Size()}
			if inspect.EagerRead(p) {
				add(j)
			} else {
				deferredMu.Lock()
				deferred = append(deferred, j)
				deferredMu.Unlock()
			}
		})
		return nil
	}, maxSize)

	pass2Ran := false
	skipReason := ""
	switch {
	case ctx.Err() != nil:
		skipReason = "interrupted before pass 1 finished"
	case col.MaxSeverity() >= model.SevHigh:
		skipReason = fmt.Sprintf("pass 1 already found a %s indicator", strings.ToUpper(col.MaxSeverity().String()))
	default:
		pass2Ran = true
		runPass(ctx, env, d.Name(), col, report, &total, &skippedBinary, func(add func(job)) error {
			for _, j := range deferred {
				add(j)
			}
			return nil
		}, maxSize)
	}

	res.Findings = col.Findings()
	var shown []string
	for _, r := range roots {
		shown = append(shown, hostfs.Display(r, env.Home))
	}
	res.Limitations = append(res.Limitations,
		"fs scanned: "+strings.Join(shown, ", ")+". A provisioner that runs elsewhere (another host, a pod, a Windows daemon) must be scanned there too.",
		fmt.Sprintf("Text files over %d MiB were not hashed unless named like the harvester; other files over %d KiB were not read unless eager (see pass note below).", maxSize>>20, hashSizeBand>>10),
	)
	if pass2Ran {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"pass 2 ran: %s outside the fast-path locations were also read, because pass 1 found nothing HIGH or above.", engine.Plural(len(deferred), "file")))
	} else if len(deferred) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"pass 2 skipped (%s): %s -- %s outside the fast-path locations were not read. The verdict already stands; pass 2 only exists to rule the module out, not in.",
			skipReason, ternary(ctx.Err() != nil, "the scan was interrupted", "the module is already confirmed present or executed"), engine.Plural(len(deferred), "file")))
	}
	res.Summary = summary(int(total.Load()), int(skippedBinary.Load()), col, int(denied.Load()), pass2Ran, len(deferred))
	return res
}

func ternary(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

// runPass drains whatever produce hands it through a worker pool that reads and
// judges each file, feeding col. produce is either the pass-1 walk (which also
// calls add for every eager file it finds) or a simple iteration over the pass-2
// deferred list; either way the reading and judging logic is identical, because
// pass 1 and pass 2 differ only in WHICH files are visited, never in how a
// visited file is read.
func runPass(ctx context.Context, env *engine.Env, tier string, col *inspect.Collector, report func(string, error), total, skippedBinary *atomic.Int64, produce func(add func(job)) error, maxSize int64) {
	queue := make(chan job, 256)
	var wg sync.WaitGroup
	for i := 0; i < workers(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				if ctx.Err() != nil {
					continue
				}
				n := total.Add(1)
				if n%2000 == 0 {
					env.Pulse(tier, fmt.Sprintf("%d files · %d hits · %s", n, col.HitCount(), hostfs.Display(filepath.Dir(j.path), env.Home)))
				}
				content, truncated, skipped, text, err := readForInspection(j.path, j.size, maxSize)
				if err != nil {
					report(j.path, err)
					continue
				}
				if skipped {
					skippedBinary.Add(1)
					continue
				}
				if ms := inspect.File(j.path, content, truncated, text); len(ms) > 0 {
					col.Add(hostfs.Display(j.path, env.Home), ms, j.size)
				}
			}
		}()
	}

	_ = produce(func(j job) {
		select {
		case queue <- j:
		case <-ctx.Done():
		}
	})
	close(queue)
	wg.Wait()
}

// readForInspection decides, cheaply, whether a file is worth reading in full,
// and returns the bytes to judge if so. The same rule serves both passes:
//
//   - named like the harvester, or text-classified by an 8 KiB sniff: read up to
//     maxSize -- these are exactly the files a text/telemetry/history scan or a
//     hash check needs full content for.
//   - otherwise (binary-looking, unnamed): read up to hashSizeBand anyway, IF the
//     file is small enough to fit -- closing the "renamed and re-encoded payload"
//     gap -- and skip only when it is both large AND gives no other reason to look.
//
// The returned text flag is the NUL-sniff classification (scan.IsText over the
// first 8 KiB, which is all scan.IsText ever looks at), passed on to inspect.File
// so it does not re-sniff the same bytes.
func readForInspection(path string, size, maxSize int64) (content []byte, truncated, skipped, text bool, err error) {
	f, err := hostfs.OpenRead(path)
	if err != nil {
		return nil, false, false, false, err
	}
	defer f.Close()

	head := make([]byte, sniffBytes)
	n, rerr := io.ReadFull(f, head)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return nil, false, false, false, rerr
	}
	head = head[:n]
	named := scan.IsScriptName(path)
	text = scan.IsText(head)

	limit := maxSize
	if !named && !text {
		if size > hashSizeBand {
			return nil, false, true, false, nil
		}
		limit = hashSizeBand
	}

	if size <= int64(n) {
		// The whole file fit inside the sniff: head already IS the full content.
		return head, false, false, text, nil
	}
	rest, err := io.ReadAll(io.LimitReader(f, limit-int64(n)))
	if err != nil {
		return nil, false, false, false, err
	}
	content = append(head, rest...)
	return content, int64(len(content)) < size, false, text, nil
}

func summary(files, binaries int, col *inspect.Collector, denied int, pass2Ran bool, deferredN int) string {
	s := engine.Plural(files, "file") + " read"
	if !pass2Ran && deferredN > 0 {
		s += fmt.Sprintf(" (pass 1 only; %d more deferred)", deferredN)
	}
	if binaries > 0 {
		s += fmt.Sprintf(" (%d skipped as large binaries)", binaries)
	}
	if h := col.HitCount(); h > 0 {
		s += ", " + engine.Plural(h, "hit")
	} else {
		s += ", nothing found"
	}
	if denied > 0 {
		s += fmt.Sprintf(" (%d unreadable)", denied)
	}
	return s
}

// tccPath recognises the macOS-protected locations whose EPERM is noise, not a
// blind spot for THIS incident: the harvester ran in a provisioner, not in
// ~/Photos.
func tccPath(p, home string) bool {
	if home == "" {
		return false
	}
	rel, err := filepath.Rel(home, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	for _, prefix := range []string{"Library", "Documents", "Desktop", "Downloads", "Pictures", "Movies", "Music"} {
		if rel == prefix || strings.HasPrefix(rel, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
