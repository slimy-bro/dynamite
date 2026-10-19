//go:build windows

package savebackup

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// Steam may be installed on any drive, userdata is always in Steam directory
func getSteamPath() (string, error) {
	if p, err := getRegistryString(registry.CURRENT_USER, `Software\Valve\Steam`, "SteamPath"); err == nil && p != "" {
		return filepath.Clean(p), nil
	}

	if p, err := getRegistryString(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Valve\Steam`, "InstallPath"); err == nil && p != "" {
		return filepath.Clean(p), nil
	}

	p := os.Getenv("PROGRAMFILES(X86)")
	if p == "" {
		return "", fmt.Errorf("can't get Program Files path")
	}

	return filepath.Join(p, "Steam"), nil
}

func getRegistryString(root registry.Key, path string, name string) (string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(name)

	return v, err
}
