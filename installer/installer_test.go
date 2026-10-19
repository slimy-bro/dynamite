package installer

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckGameVersion(t *testing.T) {
	defer func(v string) { gameExe = v }(gameExe)

	tests := []struct {
		file    string
		wantErr string
	}{
		{file: "version_1_0_15_3.exe"},
		{file: "version_1_0_15_4.exe", wantErr: "game version 1.0.15.4 is not supported"},
		// unreadable version is not treated as unsupported
		{file: "noversion.exe"},
		{file: "missing.exe"},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			gameExe = filepath.Join("..", "util", "testdata", tt.file)
			err := checkGameVersion()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkGameVersion() error = %v, want nil", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkGameVersion() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
