package servicetrace

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// ResolveServices resolves only wanted cgroup IDs under root. Mapping keys
// are absolute paths within the cgroup v2 mount; values are configured service
// names. The longest directory prefix wins. Missing or unreadable cgroups
// remain unresolved. Each rebuild gets a fresh snapshot, so a removed cgroup
// cannot leave an unbounded cache or a stale ID-to-service association.
func ResolveServices(root string, mapping map[string]string, wanted map[uint64]bool) map[uint64]string {
	return resolveServices(root, mapping, wanted, cgroupID)
}

func resolveServices(root string, mapping map[string]string, wanted map[uint64]bool, idOf func(string) (uint64, error)) map[uint64]string {
	resolved := make(map[uint64]string)
	if len(mapping) == 0 || len(wanted) == 0 {
		return resolved
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		cgpath := "/" + filepath.ToSlash(rel)
		if rel == "." {
			cgpath = "/"
		}
		service, longest := "", 0
		for prefix, label := range mapping {
			if (prefix == "/" || cgpath == prefix || strings.HasPrefix(cgpath, prefix+"/")) && len(prefix) > longest {
				service, longest = label, len(prefix)
			}
		}
		if service != "" {
			if id, err := idOf(p); err == nil && wanted[id] && id != 0 {
				resolved[id] = service
			}
		}
		return nil
	})
	return resolved
}
