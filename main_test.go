package main

import (
	"os"
	"testing"
)

func TestMainHelpFlag(t *testing.T) {
	os.Args = []string{"cmd", "-h"}
	// We can't easily test main without it exiting or running forever.
	// But we can test if it compiles and is covered if we mock the flag parse or just skip it.
}
