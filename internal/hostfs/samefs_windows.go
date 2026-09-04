// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hostfs

import (
	"os"
	"syscall"
)

// deviceID has no Windows equivalent: there is no st_dev. Reporting ok=false is
// honest rather than silently wrong; the walker falls back to isMountBarrier and
// the report states the limitation.
func deviceID(os.FileInfo) (uint64, bool) { return 0, false }

// isMountBarrier reports whether a directory is a reparse point: junctions,
// mounted volumes and OneDrive-style placeholders.
func isMountBarrier(fi os.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return false
	}
	return d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
