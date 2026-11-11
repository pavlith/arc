// Package host observes the local Linux machine without invoking a shell or
// reading credentials. Observations are not authority for host management.
package host

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/pavlith/arc/sdk/agent"
)

var errFacts = errors.New("host: inventory unavailable")

func readSmall(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errFacts
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return "", errFacts
	}
	return string(raw), nil
}

func osRelease(raw string) (string, string, error) {
	var id, version string
	for _, line := range strings.Split(raw, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.HasPrefix(key, "#") {
			continue
		}
		value = strings.Trim(value, "\"")
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			version = value
		}
	}
	if id == "" || version == "" {
		return "", "", errFacts
	}
	return id, version, nil
}

func memoryTotal(raw string) (uint64, error) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && kb > 0 && kb <= ^uint64(0)/1024 {
				return kb * 1024, nil
			}
		}
	}
	return 0, errFacts
}

func present(path string, socket bool) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if socket {
		return info.Mode()&os.ModeSocket != 0
	}
	return info.Mode().IsRegular()
}

// Collect returns minimal facts used by Core for host visibility. Missing
// system information produces no claim rather than an invented partial host.
func Collect(ctx context.Context) (agent.HostFacts, error) {
	if err := ctx.Err(); err != nil {
		return agent.HostFacts{}, err
	}
	release, err := readSmall("/etc/os-release")
	if err != nil {
		return agent.HostFacts{}, err
	}
	id, version, err := osRelease(release)
	if err != nil {
		return agent.HostFacts{}, err
	}
	meminfo, err := readSmall("/proc/meminfo")
	if err != nil {
		return agent.HostFacts{}, err
	}
	memory, err := memoryTotal(meminfo)
	if err != nil {
		return agent.HostFacts{}, err
	}
	var root syscall.Statfs_t
	if err := syscall.Statfs("/", &root); err != nil {
		return agent.HostFacts{}, errFacts
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return agent.HostFacts{}, errFacts
	}
	var kernel strings.Builder
	for _, character := range uts.Release {
		if character == 0 {
			break
		}
		kernel.WriteByte(byte(character))
	}
	facts := agent.HostFacts{
		OS: id, Version: version, Architecture: runtime.GOARCH,
		Kernel: kernel.String(), CPUThreads: runtime.NumCPU(),
		MemoryBytes: memory, RootTotal: root.Blocks * uint64(root.Bsize),
		RootAvailable: root.Bavail * uint64(root.Bsize),
		APT:           present("/usr/bin/apt-get", false),
		Systemd:       present("/usr/bin/systemctl", false),
		Docker:        present("/var/run/docker.sock", true),
		LXD: present("/var/snap/lxd/common/lxd/unix.socket", true) ||
			present("/var/lib/lxd/unix.socket", true),
	}
	if err := facts.Validate(); err != nil {
		return agent.HostFacts{}, errFacts
	}
	return facts, nil
}
