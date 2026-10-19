//go:build !windows

package savebackup

import (
	"fmt"
	"os"
	"path/filepath"
)

func getSteamPath() (string, error) {
	p := os.Getenv("HOME")
	if p == "" {
		return "", fmt.Errorf("can't get HOME variable")
	}

	return filepath.Join(p, ".steam", "steam"), nil
}
