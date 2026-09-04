// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package hostfs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
)

// collect runs WalkParallel and returns the visited regular-file paths (sorted)
// and any reported errors, gathered concurrency-safely.
func collect(t *testing.T, w *Walker, roots []string) ([]string, []string) {
	t.Helper()
	var (
		mu    sync.Mutex
		files []string
		errs  []string
	)
	w.OnError = func(p string, err error) {
		mu.Lock()
		errs = append(errs, p)
		mu.Unlock()
	}
	w.WalkParallel(context.Background(), roots, 8, func(p string, _ os.DirEntry) {
		mu.Lock()
		files = append(files, p)
		mu.Unlock()
	})
	sort.Strings(files)
	return files, errs
}

func TestWalkParallelFindsEveryRegularFileOnce(t *testing.T) {
	dir := t.TempDir()
	want := []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "sub", "b.txt"),
		filepath.Join(dir, "sub", "deep", "c.txt"),
	}
	mustWrite(t, want...)

	got, errs := collect(t, &Walker{}, []string{dir})
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if !equal(got, want) {
		t.Errorf("files:\n got %v\nwant %v", got, want)
	}
}

func TestWalkParallelNeverFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real", "x.txt")
	mustWrite(t, real)
	// A symlink to the sibling dir, and a dangling one. Neither may be followed or
	// emitted, and the dangling one must not be an error (we never stat it).
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nope"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	got, errs := collect(t, &Walker{}, []string{dir})
	if len(errs) != 0 {
		t.Errorf("a symlink must never be statted or reported: %v", errs)
	}
	if len(got) != 1 || got[0] != real {
		t.Errorf("the symlinked tree must not be entered: got %v", got)
	}
}

func TestWalkParallelMissingRootIsNotAnError(t *testing.T) {
	got, errs := collect(t, &Walker{}, []string{filepath.Join(t.TempDir(), "does-not-exist")})
	if len(got) != 0 || len(errs) != 0 {
		t.Errorf("a missing root must be silent: files=%v errs=%v", got, errs)
	}
}

func TestWalkParallelReportsPermissionDeniedAndContinues(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 000 is not a barrier for root or on Windows")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "readable", "ok.txt")
	mustWrite(t, good)
	denied := filepath.Join(dir, "denied")
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(denied, "secret.txt"))
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	got, errs := collect(t, &Walker{}, []string{dir})
	if len(got) != 1 || got[0] != good {
		t.Errorf("the readable file must still be found: got %v", got)
	}
	if len(errs) != 1 || errs[0] != denied {
		t.Errorf("the unreadable dir must be reported exactly once: %v", errs)
	}
}

func TestWalkParallelIsRaceFreeUnderLoad(t *testing.T) {
	dir := t.TempDir()
	var want []string
	for i := 0; i < 12; i++ {
		sub := filepath.Join(dir, "d", "e", "f", string(rune('a'+i)))
		p := filepath.Join(sub, "f.txt")
		want = append(want, p)
		for j := 0; j < 20; j++ {
			want = append(want, filepath.Join(sub, string(rune('0'+j%10))+"-"+string(rune('a'+j))+".txt"))
		}
	}
	mustWrite(t, want...)
	sort.Strings(want)
	got, _ := collect(t, &Walker{}, []string{dir})
	if !equal(got, want) {
		t.Errorf("under a wide tree the walk lost or duplicated files: got %d want %d", len(got), len(want))
	}
}

func mustWrite(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	c := append([]string(nil), b...)
	sort.Strings(c)
	for i := range a {
		if a[i] != c[i] {
			return false
		}
	}
	return true
}
