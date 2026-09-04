// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package hostfs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Walker traverses a tree read-only.
//
// It never follows symlinks -- that one rule kills traversal cycles, mount escapes
// and cloud-storage download storms together -- and it does not leave the
// filesystem it started on. It has no prune list either: directory traversal is a
// getdents loop, and the expense in this tool is content reading, which the caller
// gates by size and type.
type Walker struct {
	// CrossFilesystem, off by default, lets the walk descend into other mounts. Off
	// because a network share under /home would turn a scan into an hours-long one.
	CrossFilesystem bool

	// OnError is called for every unreadable directory or file (macOS TCC denies
	// ~/Documents; a pod's /proc entries vanish mid-walk). It must record and
	// continue: an EPERM has to degrade the verdict, never abort the walk.
	OnError func(path string, err error)
}

// Visit is called for each entry. Return fs.SkipDir to skip a directory's
// contents; any other error aborts the walk.
type Visit func(path string, d fs.DirEntry) error

// Walk traverses root. A root that does not exist is NOT an error: the default
// roots are a list of plausible locations, most absent on any given host, and
// reporting each absence would downgrade every clean host to INDETERMINATE.
func (w *Walker) Walk(ctx context.Context, root string, visit Visit) error {
	fi, err := os.Lstat(root)
	if err != nil {
		if !os.IsNotExist(err) {
			w.reportErr(root, err)
		}
		return nil
	}
	rootDev, haveRootDev := deviceID(fi)

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			w.reportErr(path, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never even stat it
		}
		if d.IsDir() && path != root && !w.CrossFilesystem {
			fi, ferr := os.Lstat(path)
			if ferr != nil {
				w.reportErr(path, ferr)
				return fs.SkipDir
			}
			// Windows has no st_dev; the best available barrier is the reparse point
			// attribute, which covers junctions and mounted volumes.
			if isMountBarrier(fi) {
				return fs.SkipDir
			}
			if dev, ok := deviceID(fi); ok && haveRootDev && dev != rootDev {
				return fs.SkipDir
			}
		}
		return visit(path, d)
	})
}

// VisitFile is called for each regular file the parallel walk finds. Unlike
// Visit it returns nothing: the walk owns directory traversal, and a file is only
// ever handed off (to an inspection queue), never used to prune. It may be called
// concurrently from many goroutines, so it must be safe for concurrent use.
type VisitFile func(path string, d fs.DirEntry)

// WalkParallel walks every root concurrently, fanning out across subdirectories
// with a bounded pool, and calls visit for each regular file. It exists because a
// single-goroutine filepath.WalkDir over a large tree (a whole provisioner root)
// spends its time in serial getdents+stat while the inspection pool starves; a
// parallel getdents loop keeps that pool fed.
//
// It preserves every invariant of the serial Walk: symlinks are never followed or
// even statted; a subdirectory on a different device (or, on Windows, behind a
// reparse point) is not descended unless CrossFilesystem is set; an unreadable
// directory is reported and skipped, never fatal; a missing root is not an error.
// It does NOT honour an fs.SkipDir signal from the caller (there is no Visit
// return) -- the only caller gates by size and type when it reads a file, not by
// pruning directories, exactly as the serial walk's callers do.
//
// workers bounds the number of concurrent directory readers. When the pool is
// saturated a subdirectory is walked inline on the current goroutine, so traversal
// never blocks waiting for a slot and goroutine count stays bounded.
func (w *Walker) WalkParallel(ctx context.Context, roots []string, workers int, visit VisitFile) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	var walkDir func(dir string, rootDev uint64, haveDev bool)
	walkDir = func(dir string, rootDev uint64, haveDev bool) {
		defer wg.Done()
		if ctx.Err() != nil {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			w.reportErr(dir, err)
			return
		}
		for _, e := range entries {
			if ctx.Err() != nil {
				return
			}
			p := filepath.Join(dir, e.Name())
			if e.Type()&fs.ModeSymlink != 0 {
				continue // never even stat it
			}
			switch {
			case e.IsDir():
				if !w.CrossFilesystem {
					fi, ferr := os.Lstat(p)
					if ferr != nil {
						w.reportErr(p, ferr)
						continue
					}
					if isMountBarrier(fi) {
						continue
					}
					if dev, ok := deviceID(fi); ok && haveDev && dev != rootDev {
						continue
					}
				}
				wg.Add(1)
				select {
				case sem <- struct{}{}:
					go func(p string) { defer func() { <-sem }(); walkDir(p, rootDev, haveDev) }(p)
				default:
					walkDir(p, rootDev, haveDev) // pool saturated: recurse inline
				}
			case e.Type().IsRegular():
				visit(p, e)
			}
		}
	}

	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		fi, err := os.Lstat(root)
		if err != nil {
			if !os.IsNotExist(err) {
				w.reportErr(root, err)
			}
			continue
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if !fi.IsDir() {
			if fi.Mode().IsRegular() {
				visit(root, fs.FileInfoToDirEntry(fi))
			}
			continue
		}
		rootDev, haveDev := deviceID(fi)
		wg.Add(1)
		walkDir(root, rootDev, haveDev)
	}
	wg.Wait()
}

func (w *Walker) reportErr(path string, err error) {
	if w.OnError != nil {
		w.OnError(path, err)
	}
}
