package buildinfo

import (
	"os"
	"testing"
)

func TestVersion(t *testing.T) {
	want := os.Getenv("TEST_EXPECT_VERSION")
	if want == "" {
		want = "devel"
	}

	if Version != want {
		t.Fatalf("Version = %q, want %q", Version, want)
	}
}
