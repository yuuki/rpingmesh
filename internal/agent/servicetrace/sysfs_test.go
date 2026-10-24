package servicetrace

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUverbsDevices(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "class/infiniband_verbs/uverbs0/dev"), "231:192\n")
	writeFile(t, filepath.Join(root, "class/infiniband_verbs/uverbs0/ibdev"), "mlx5_0\n")
	writeFile(t, filepath.Join(root, "class/infiniband_verbs/uverbs1/dev"), "231:193\n")
	writeFile(t, filepath.Join(root, "class/infiniband_verbs/uverbs1/ibdev"), "mlx5_1\n")
	// An abi_version entry is a file, not a node: it has no dev attribute.
	writeFile(t, filepath.Join(root, "class/infiniband_verbs/abi_version"), "6\n")

	devs, err := UverbsDevices(root)
	if err != nil {
		t.Fatalf("UverbsDevices: %v", err)
	}
	want := map[uint32]string{MakeDev(231, 192): "mlx5_0", MakeDev(231, 193): "mlx5_1"}
	if len(devs) != len(want) {
		t.Fatalf("got %v, want %v", devs, want)
	}
	for dev, name := range want {
		if devs[dev] != name {
			t.Errorf("dev %#x = %q, want %q", dev, devs[dev], name)
		}
	}
	if MakeDev(231, 192) != 0xe7000c0 {
		t.Errorf("MakeDev(231,192) = %#x, want 0xe7000c0", MakeDev(231, 192))
	}
}

func TestUverbsDevicesMissingClass(t *testing.T) {
	if _, err := UverbsDevices(t.TempDir()); err == nil {
		t.Fatal("expected an error without the infiniband_verbs class")
	}
}

func TestPortGID(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "class/infiniband/mlx5_0/ports/1/gids/3"), "0000:0000:0000:0000:0000:ffff:c0a8:0116\n")
	gid, err := PortGID(root, "mlx5_0", 1, 3)
	if err != nil {
		t.Fatalf("PortGID: %v", err)
	}
	want := [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 168, 14: 1, 15: 22}
	if gid != want {
		t.Fatalf("PortGID = %x, want %x", gid, want)
	}
	if _, err := PortGID(root, "mlx5_0", 1, 4); err == nil {
		t.Fatal("expected an error for a missing GID index")
	}
	writeFile(t, filepath.Join(root, "class/infiniband/mlx5_0/ports/1/gids/5"), "not-a-gid\n")
	if _, err := PortGID(root, "mlx5_0", 1, 5); err == nil {
		t.Fatal("expected a parse error")
	}
}
