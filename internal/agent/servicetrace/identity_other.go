//go:build !linux

package servicetrace

import "fmt"

func cgroupID(string) (uint64, error) {
	return 0, fmt.Errorf("cgroup identity requires Linux")
}
