package util

import (
	"path/filepath"
	"testing"
)

// testdata executables are empty programs with a VERSIONINFO resource (FILEVERSION 1,0,15,x; PRODUCTVERSION 9,9,9,9):
//
//	x86_64-w64-mingw32-windres version.rc -O coff -o version.res
//	x86_64-w64-mingw32-gcc -nostdlib -e start -s -Os empty.c version.res -o version_1_0_15_x.exe
func TestGetExeVersion(t *testing.T) {
	tests := []struct {
		file    string
		want    ExeVersion
		wantErr bool
	}{
		{file: "version_1_0_15_3.exe", want: ExeVersion{1, 0, 15, 3}},
		{file: "version_1_0_15_4.exe", want: ExeVersion{1, 0, 15, 4}},
		{file: "noversion.exe", wantErr: true},
		{file: "missing.exe", wantErr: true},
		{file: "../exeversion.go", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := GetExeVersion(filepath.Join("testdata", tt.file))
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetExeVersion() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("GetExeVersion() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestExeVersionString(t *testing.T) {
	if got := (ExeVersion{1, 0, 15, 3}).String(); got != "1.0.15.3" {
		t.Errorf("String() = %s, want 1.0.15.3", got)
	}
}
