package servicetrace

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveServices(t *testing.T) {
	root := t.TempDir()
	paths := []string{"system.slice/train.service", "system.slice/train.service/worker", "system.slice/train.service-extra", "kubepods.slice/pod123/container", "system.slice/unreadable"}
	ids := make(map[string]uint64)
	for i, p := range paths {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
		ids[p] = uint64(i + 1)
	}
	// A symlink must not allow a mapped subtree to escape the mount.
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "external")); err != nil {
		t.Fatal(err)
	}
	mapping := map[string]string{"/system.slice": "system", "/system.slice/train.service": "training", "/kubepods.slice/pod123": "namespace/job"}
	wanted := map[uint64]bool{1: true, 2: true, 3: true, 4: true, 5: true, 999: true}
	idOf := func(p string) (uint64, error) {
		if p == filepath.Join(root, paths[4]) {
			return 0, fmt.Errorf("permission denied")
		}
		return ids[p], nil
	}
	want := map[uint64]string{1: "training", 2: "training", 3: "system", 4: "namespace/job"}
	if got := resolveServices(root, mapping, wanted, idOf); !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved = %v, want %v", got, want)
	}
	if err := os.RemoveAll(filepath.Join(root, paths[0])); err != nil {
		t.Fatal(err)
	}
	delete(want, 1)
	delete(want, 2)
	if got := resolveServices(root, mapping, wanted, idOf); !reflect.DeepEqual(got, want) {
		t.Fatalf("after removal = %v, want %v", got, want)
	}
	if got := resolveServices(root, nil, wanted, func(string) (uint64, error) { t.Fatal("disabled resolver read cgroup IDs"); return 0, nil }); len(got) != 0 {
		t.Fatal(got)
	}
	if got := resolveServices(filepath.Join(root, "missing"), mapping, wanted, idOf); len(got) != 0 {
		t.Fatal(got)
	}
}
