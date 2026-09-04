// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package image scans container images for the same indicators the fs tier looks
// for on a host. It reads an image TAR -- whatever produced it: `docker save`,
// `podman save`, `nerdctl save`, `crane export`, `skopeo copy` -- so it works on any
// platform without talking to a daemon. A bare image reference is accepted too,
// and handed to whichever container CLI is on PATH to `save` into a stream.
package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/optimuslabs-io/leakpatrol/internal/detect/inspect"
	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

// maxNesting bounds recursion into tars-within-tars: docker-save is one level
// (<id>/layer.tar), OCI is one level (blobs/sha256/<digest> as gzipped tar). Two
// covers both with margin; deeper nesting is a tar bomb, not an image.
const maxNesting = 2

// CLIs are the container runtimes tried, in order, when an argument is not a
// file. All three speak `save <ref>` to stdout.
var CLIs = []string{"docker", "podman", "nerdctl"}

type Detector struct{}

func New() *Detector { return &Detector{} }

func (*Detector) Name() string { return "image" }

func (*Detector) Describe() string {
	return "container image layers for the harvester (by hash and name), the telemetry block, and exfil indicators"
}

func (*Detector) Ready(env *engine.Env) string {
	if len(env.Images) == 0 {
		return "no --image given (a `docker save` tar, `-` for stdin, or an image reference)"
	}
	return ""
}

// Material: an absent image tar is coverage information, not a verdict change.
func (*Detector) Material() bool { return false }

func (d *Detector) Run(ctx context.Context, env *engine.Env) engine.Result {
	var res engine.Result
	col := &inspect.Collector{Tier: d.Name()}
	maxSize := env.MaxFileSize
	if maxSize <= 0 {
		maxSize = 8 << 20
	}
	scanned, failed := 0, 0
	for _, img := range env.Images {
		r, closer, err := open(ctx, img, env.Stdin)
		if err != nil {
			failed++
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Path: img, Message: err.Error(), Material: true})
			continue
		}
		label := img
		if img == "-" {
			label = "stdin"
		}
		files := 0
		err = scanTar(ctx, r, label, 0, maxSize, func(name string, content []byte, truncated bool, size int64) {
			files++
			if files%500 == 0 {
				env.Pulse(d.Name(), fmt.Sprintf("%s · %d files · %d hits", label, files, col.Hits))
			}
			// The image tier reads each tar entry whole, so it classifies here rather
			// than from a sniff; scan.IsText only inspects the first 8 KiB either way.
			if ms := inspect.File(name, content, truncated, scan.IsText(content)); len(ms) > 0 {
				col.Add(label+":"+name, ms, size)
			}
		})
		cerr := closer()
		if err != nil {
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "parse", Path: img, Message: err.Error(), Material: true})
		} else if cerr != nil {
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Path: img, Message: cerr.Error(), Material: true})
		}
		scanned++
	}
	res.Findings = col.Findings()
	switch {
	case failed > 0 && scanned == 0:
		res.Summary = fmt.Sprintf("%s could not be opened; nothing was scanned", engine.Plural(failed, "image"))
	case col.Hits > 0:
		res.Summary = fmt.Sprintf("%s scanned, %s", engine.Plural(scanned, "image"), engine.Plural(col.Hits, "hit"))
	default:
		res.Summary = fmt.Sprintf("%s scanned, nothing found", engine.Plural(scanned, "image"))
	}
	if failed > 0 && scanned > 0 {
		res.Summary += fmt.Sprintf(" (%d could not be opened)", failed)
	}
	res.Limitations = append(res.Limitations,
		"Image scanning reads layers as shipped; files deleted in a later layer (whiteouts) are still reported, which is the honest reading for a payload that was present at any point.")
	return res
}

// open returns a stream for an image argument: stdin, a tar on disk, or the
// stdout of `<cli> save <ref>`. The returned closer reports the CLI's exit status.
func open(ctx context.Context, arg string, stdin io.Reader) (io.Reader, func() error, error) {
	if arg == "-" {
		if stdin == nil {
			stdin = os.Stdin
		}
		return stdin, func() error { return nil }, nil
	}
	if fi, err := os.Stat(arg); err == nil {
		if fi.IsDir() {
			return nil, nil, fmt.Errorf("%s is a directory; give a tar, - for stdin, or an image reference", arg)
		}
		f, err := hostfs.OpenRead(arg)
		if err != nil {
			return nil, nil, err
		}
		return f, f.Close, nil
	}
	// Something that LOOKS like a file path must not silently become `docker save
	// <typo>`: a mistyped tar would turn into a daemon error counted as a scanned
	// image. Only a bare image reference falls through to a container CLI.
	if looksLikePath(arg) {
		return nil, nil, fmt.Errorf("%s: no such file", arg)
	}
	for _, cli := range CLIs {
		path, err := exec.LookPath(cli)
		if err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, path, "save", arg)
		var stderr bytes.Buffer
		cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, nil, err
		}
		closer := func() error {
			if err := cmd.Wait(); err != nil {
				return fmt.Errorf("%s save %s: %v: %s", cli, arg, err, strings.TrimSpace(stderr.String()))
			}
			return nil
		}
		return out, closer, nil
	}
	return nil, nil, errors.New("not a file, and no docker/podman/nerdctl on PATH to save the image with")
}

// LooksLikePath: a path separator, a leading dot, or an archive suffix. An OCI
// reference can contain "/" too (ghcr.io/coder/coder), so a slash alone only
// counts when the argument also carries a tar-ish suffix or starts like a path.
// Exported so main can refuse a missing tar before any tier runs.
func LooksLikePath(arg string) bool { return looksLikePath(arg) }

func looksLikePath(arg string) bool {
	low := strings.ToLower(arg)
	for _, suf := range []string{".tar", ".tar.gz", ".tgz", ".oci"} {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "~") || strings.Contains(arg, "\\") || (len(arg) > 1 && arg[1] == ':')
}

// scanTar walks one tar stream. Entries that are themselves tars (plain or
// gzipped) are descended into; everything else is handed to visit with its bytes.
func scanTar(ctx context.Context, r io.Reader, prefix string, depth int, maxSize int64, visit func(name string, content []byte, truncated bool, size int64)) error {
	tr := tar.NewReader(r)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := hdr.Name
		br := bufio.NewReaderSize(tr, 64*1024)
		head, _ := br.Peek(512)

		if depth < maxNesting {
			if isGzip(head) {
				gz, err := gzip.NewReader(br)
				if err == nil {
					// Only a gzipped TAR is a layer; a gzipped text file is just a file.
					pr := bufio.NewReaderSize(gz, 64*1024)
					if h2, _ := pr.Peek(512); isTar(h2) {
						if err := scanTar(ctx, pr, prefix, depth+1, maxSize, nested(name, visit)); err != nil {
							return fmt.Errorf("%s: %w", name, err)
						}
						continue
					}
					// Not a tar inside: fall through and scan the decompressed bytes as a file.
					content, truncated := readCapped(pr, maxSize)
					visit(name, content, truncated, hdr.Size)
					continue
				}
			}
			if isTar(head) {
				if err := scanTar(ctx, br, prefix, depth+1, maxSize, nested(name, visit)); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				continue
			}
		}
		content, truncated := readCapped(br, maxSize)
		if scan.IsScriptName(name) && truncated {
			// A harvester-named file bigger than the cap: hash the whole thing anyway,
			// streaming the remainder. The advisory's payloads are a few KB; this is
			// belt and braces so a padded copy cannot hide behind the size cap.
			h := sha256.New()
			h.Write(content)
			_, _ = io.Copy(h, br)
			if _, ok := scan.MatchPayload(hex.EncodeToString(h.Sum(nil))); ok {
				// Hand inspect the bytes it needs to re-derive the same digest is not
				// possible without buffering; report through the name path with a note.
				visit(name, content, true, hdr.Size)
			}
			continue
		}
		visit(name, content, truncated, hdr.Size)
	}
}

// nested prefixes file names with the layer they came from, so a report row reads
// "image.tar:<layer>/etc/x" and the reader can find the layer again.
func nested(layer string, visit func(string, []byte, bool, int64)) func(string, []byte, bool, int64) {
	short := layer
	if i := strings.LastIndex(layer, "/"); i >= 0 && strings.HasSuffix(layer, "/layer.tar") {
		short = layer[:i]
	}
	if len(short) > 12 && strings.HasPrefix(short, "blobs/sha256/") {
		short = "blob:" + short[len("blobs/sha256/"):][:12]
	} else if len(short) > 12 && !strings.Contains(short, "/") {
		short = short[:12]
	}
	return func(name string, content []byte, truncated bool, size int64) {
		visit(short+"/"+strings.TrimPrefix(name, "./"), content, truncated, size)
	}
}

func readCapped(r io.Reader, max int64) ([]byte, bool) {
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return buf, true
	}
	if int64(len(buf)) > max {
		return buf[:max], true
	}
	return buf, false
}

func isGzip(head []byte) bool {
	return len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b
}

// isTar checks the ustar magic at offset 257. A tar without it (a v7 tar) is
// scanned as a plain file, which for an image layer never happens in practice.
func isTar(head []byte) bool {
	return len(head) >= 262 && string(head[257:262]) == "ustar"
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	l.n -= len(p)
	_, err := l.w.Write(p)
	return len(p), err
}
