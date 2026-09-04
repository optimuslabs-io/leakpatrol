// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package deploy

import "os"

func writeAll(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
