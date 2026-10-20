package main

import (
	"os"
	"testing"
)

func TestDynamitePortInSync(t *testing.T) {
	java, err := os.ReadFile("DynamitePort.java")
	if err != nil {
		t.Fatal(err)
	}

	want, err := Render("../src", string(java))
	if err != nil {
		t.Fatal(err)
	}

	if want != string(java) {
		t.Errorf("DynamitePort.java is out of date, run go run hook/ghidra/generate.go")
	}
}

func TestTextBlock(t *testing.T) {
	got := textBlock("a\\0 \"\"\"\r\nb\n\n")
	want := "\"\"\"\na\\\\0 \\\"\"\"\nb\n\"\"\""
	if got != want {
		t.Errorf("textBlock() = %q, want %q", got, want)
	}
}
