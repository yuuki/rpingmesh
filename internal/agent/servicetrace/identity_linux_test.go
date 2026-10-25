//go:build linux

package servicetrace

import (
	"os"
	"strings"
	"testing"
)

func TestCgroupIdentity(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("requires cgroup v2")
	}
	id, err := cgroupID("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("zero cgroup ID")
	}
	got := ResolveServices("/sys/fs/cgroup", map[string]string{"/": "host"}, map[uint64]bool{id: true})
	if got[id] != "host" {
		t.Fatalf("resolved=%v", got)
	}
	if _, err := cgroupID(t.TempDir()); err == nil {
		t.Fatal("ordinary directory accepted as a cgroup")
	}
}

func TestCgroupIdentityRejectsNonV2Filesystems(t *testing.T) {
	for name, path := range map[string]string{"ordinary directory": t.TempDir(), "sysfs kernfs": "/sys"} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(path); err != nil {
				t.Skip(err)
			}
			if _, err := cgroupID(path); err == nil || !strings.Contains(err.Error(), "not a cgroup v2 filesystem") {
				t.Fatalf("cgroupID(%q) = %v, want filesystem rejection before reading a kernfs ID", path, err)
			}
		})
	}
}
