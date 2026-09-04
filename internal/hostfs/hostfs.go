// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package hostfs is the only package in leakpatrol that touches the host
// filesystem. Every read funnels through OpenRead, which is the enforcement
// point for the read-only invariant: there is no function here that creates,
// writes, renames, chmods or removes anything.
package hostfs

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// OpenRead is the ONLY way leakpatrol opens a host file. O_RDONLY, no create
// flag, no truncate flag, mode 0 (unused without O_CREATE).
func OpenRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// ReadFileCapped reads at most max bytes. Every caller reads a file whose size it
// has already stat'd and bounded, so an unbounded ReadFile never appears -- a
// 40 GB file must not become a 40 GB allocation.
func ReadFileCapped(path string, max int64) ([]byte, error) {
	f, err := OpenRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 32*1024)
	for int64(len(buf)) < max {
		n, err := f.Read(tmp)
		if n > 0 {
			remaining := max - int64(len(buf))
			if int64(n) > remaining {
				n = int(remaining)
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // io.EOF or a read error: return what we got
		}
	}
	return buf, nil
}

// Home resolves the user's home directory. os.UserHomeDir is used rather than
// os/user because the latter pulls in cgo, which would break CGO_ENABLED=0
// cross-compilation and put a C dependency in a security tool.
func Home(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	return os.UserHomeDir()
}

// Display renders a path home-relative (~/work/foo). It is free privacy hygiene,
// it makes golden tests stable across machines, and it is what a reader wants to
// look at.
func Display(path, home string) string {
	if home == "" || path == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(os.PathSeparator) + path[len(prefix):]
	}
	return path
}

// DefaultRoots are the NARROW set of places the tampered module, the harvester,
// and the traces of its run land on a host: shell histories, Terraform data and
// plugin caches, Coder's own directories, and the temp dirs a provisioner unpacks
// templates into. Deliberately NOT the whole home directory -- on an operator's
// laptop that is node_modules-scale, takes minutes, and is not a provisioner scan
// however long it runs. A root that does not exist is silently skipped; scanning a
// provisioner host or pod means passing `/` (or its work dir) explicitly.
func DefaultRoots(home string) []string {
	var roots []string
	add := func(p string) {
		if p != "" {
			roots = append(roots, p)
		}
	}
	if home != "" {
		for _, h := range HistoryNames() {
			add(filepath.Join(home, h))
		}
		add(filepath.Join(home, ".local", "share", "fish", "fish_history"))
		add(filepath.Join(home, ".terraform.d"))
		add(filepath.Join(home, ".terraform"))
		add(filepath.Join(home, ".cache", "coder"))
		add(filepath.Join(home, ".config", "coderv2"))
	}
	add(os.Getenv("TF_PLUGIN_CACHE_DIR"))
	add(os.Getenv("TF_DATA_DIR"))
	add(os.Getenv("CODER_CACHE_DIRECTORY"))
	switch runtime.GOOS {
	case "windows":
		add(os.Getenv("TEMP"))
		if v := os.Getenv("APPDATA"); v != "" {
			add(filepath.Join(v, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
			add(filepath.Join(v, "terraform.d"))
			add(filepath.Join(v, "coderv2"))
		}
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			add(filepath.Join(v, "coder"))
		}
	default:
		add("/tmp")
		add("/var/tmp")
		add("/home/coder")
		add("/opt/coder")
		add("/var/lib/coder")
		add("/var/cache/coder")
		add("/root/.bash_history")
	}
	return dedupe(roots)
}

// HistoryNames are the shell history files whose contents prove the harvester
// RAN here rather than merely being present. A hit in one of these is CRITICAL.
func HistoryNames() []string {
	return []string{
		".bash_history", ".zsh_history", ".sh_history", ".history",
		"fish_history", "ConsoleHost_history.txt",
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}
