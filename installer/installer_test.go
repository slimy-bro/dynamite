package installer

import (
	"crypto/md5"
	"dynamite/util"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unknown321/datfpk/qar"
)

func TestCheckGameVersion(t *testing.T) {
	defer func(v string) { gameExe = v }(gameExe)
	defer func(v util.ExeVersion) { gameVersion = v }(gameVersion)

	tests := []struct {
		file        string
		wantVersion util.ExeVersion
		wantErr     string
	}{
		{file: "version_1_0_15_3.exe", wantVersion: util.ExeVersion{1, 0, 15, 3}},
		{file: "version_1_0_15_4.exe", wantVersion: util.ExeVersion{1, 0, 15, 4}},
		{file: "version_1_0_15_5.exe", wantErr: "game version 1.0.15.5 is not supported, dynamite works only with 1.0.15.3, 1.0.15.4"},
		// unreadable version is not treated as unsupported
		{file: "noversion.exe", wantVersion: util.ExeVersion{1, 0, 15, 3}},
		{file: "missing.exe", wantVersion: util.ExeVersion{1, 0, 15, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			gameExe = filepath.Join("..", "util", "testdata", tt.file)
			gameVersion = supportedGameVersions[0]
			err := checkGameVersion()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkGameVersion() error = %v, want nil", err)
				}

				if gameVersion != tt.wantVersion {
					t.Fatalf("gameVersion = %s, want %s", gameVersion, tt.wantVersion)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkGameVersion() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

var (
	v153 = util.ExeVersion{1, 0, 15, 3}
	v154 = util.ExeVersion{1, 0, 15, 4}
)

// writes qar with given entries, returns its path
func writeQar(t *testing.T, dir string, name string, entries ...string) string {
	t.Helper()
	q := qar.Qar{Flags: 3150304, Version: 1}
	for _, e := range entries {
		q.Entries = append(q.Entries, qar.Entry{Header: qar.EntryHeader{FilePath: e}, Data: []byte("data " + e)})
	}

	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err = q.Write(f, "", false); err != nil {
		t.Fatal(err)
	}

	return p
}

// sets stock 00.dat of 1.0.15.3 to file at path
func setStock153(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	old := stock00
	stock00 = map[util.ExeVersion]string{v153: fmt.Sprintf("%x", md5.Sum(data))}
	t.Cleanup(func() { stock00 = old })
}

func TestCheck00(t *testing.T) {
	defer func(v util.ExeVersion) { gameVersion = v }(gameVersion)

	dir := t.TempDir()
	stock153 := writeQar(t, dir, "stock153.dat", "/Assets/tpp/script/lib/Tpp.lua")
	stock154 := writeQar(t, dir, "stock154.dat", "/Assets/tpp/script/lib/Tpp.lua", "/Assets/tpp/script/lib/TppMain.lua")
	modded := writeQar(t, dir, "modded.dat", "/Assets/tpp/script/lib/Tpp.lua", coopEssentials)
	garbage := filepath.Join(dir, "garbage.dat")
	if err := os.WriteFile(garbage, []byte("not a qar"), 0666); err != nil {
		t.Fatal(err)
	}
	setStock153(t, stock153)

	tests := []struct {
		name    string
		version util.ExeVersion
		path    string
		want    datStatus
	}{
		{"1.0.15.3 stock", v153, stock153, datValid},
		{"1.0.15.3 other file", v153, stock154, datInvalid},
		{"1.0.15.3 missing file", v153, filepath.Join(dir, "missing.dat"), datInvalid},
		{"1.0.15.4 stock of 1.0.15.3", v154, stock153, datOtherVersion},
		// checksum of 1.0.15.4 00.dat is not known
		{"1.0.15.4 unknown file", v154, stock154, datValid},
		{"1.0.15.4 modified by dynamite", v154, modded, datInvalid},
		{"1.0.15.4 not a qar", v154, garbage, datInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gameVersion = tt.version
			if got := check00(tt.path); got != tt.want {
				t.Fatalf("check00() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBackupVendor(t *testing.T) {
	defer func(v util.ExeVersion) { gameVersion = v }(gameVersion)

	src := t.TempDir()
	stock153 := writeQar(t, src, "stock153.dat", "/Assets/tpp/script/lib/Tpp.lua")
	stock154 := writeQar(t, src, "stock154.dat", "/Assets/tpp/script/lib/Tpp.lua", "/Assets/tpp/script/lib/TppMain.lua")
	modded := writeQar(t, src, "modded.dat", "/Assets/tpp/script/lib/Tpp.lua", coopEssentials)
	setStock153(t, stock153)

	copyFile := func(from string, to string) {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}

		if err = os.WriteFile(to, data, 0666); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name       string
		version    util.ExeVersion
		plain      string
		vendor     string // empty: no vendor
		wantErr    bool
		wantVendor string
	}{
		{name: "1.0.15.3 first install", version: v153, plain: stock153, wantVendor: stock153},
		{name: "1.0.15.3 reinstall", version: v153, plain: modded, vendor: stock153, wantVendor: stock153},
		{name: "1.0.15.3 modified 00.dat", version: v153, plain: modded, wantErr: true},
		{name: "1.0.15.4 first install", version: v154, plain: stock154, wantVendor: stock154},
		{name: "1.0.15.4 after game update", version: v154, plain: stock154, vendor: stock153, wantVendor: stock154},
		{name: "1.0.15.4 reinstall", version: v154, plain: modded, vendor: stock154, wantVendor: stock154},
		{name: "1.0.15.4 modified 00.dat", version: v154, plain: modded, wantErr: true},
		{name: "1.0.15.4 with 1.0.15.3 00.dat", version: v154, plain: stock153, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.MkdirAll(filepath.Dir(plain00), 0755); err != nil {
				t.Fatal(err)
			}

			copyFile(tt.plain, plain00)
			if tt.vendor != "" {
				copyFile(tt.vendor, vendor00)
			}

			gameVersion = tt.version
			err := backupVendor()
			if (err != nil) != tt.wantErr {
				t.Fatalf("backupVendor() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			got, err := os.ReadFile(vendor00)
			if err != nil {
				t.Fatal(err)
			}

			want, _ := os.ReadFile(tt.wantVendor)
			if string(got) != string(want) {
				t.Fatalf("00.dat.vendor is not %s", filepath.Base(tt.wantVendor))
			}
		})
	}
}
