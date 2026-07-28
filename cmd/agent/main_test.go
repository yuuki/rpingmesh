package main

import (
	"bytes"
	"testing"

	"github.com/yuuki/rpingmesh/internal/buildinfo"
)

func TestRootCommandVersion(t *testing.T) {
	cmd := newRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := buf.String(), "rpingmesh-agent version "+buildinfo.Version+"\n"; got != want {
		t.Fatalf("--version output = %q, want %q", got, want)
	}
}
