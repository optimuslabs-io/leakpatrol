// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hostfs

import (
	"os"
	"syscall"
)

// deviceID returns the filesystem device number, which lets the walker refuse to
// cross a mount point.
func deviceID(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// isMountBarrier is a Windows-only concept; on Unix the device check is exact.
func isMountBarrier(os.FileInfo) bool { return false }
