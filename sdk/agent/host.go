package agent

import "regexp"

// HostFacts are untrusted observations from an authenticated node. They never
// grant capabilities, affect approved templates, or authorize host operations.
type HostFacts struct {
	OS            string `json:"os"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	Kernel        string `json:"kernel"`
	CPUThreads    int    `json:"cpu_threads"`
	MemoryBytes   uint64 `json:"memory_bytes"`
	RootTotal     uint64 `json:"root_total_bytes"`
	RootAvailable uint64 `json:"root_available_bytes"`
	APT           bool   `json:"apt"`
	Systemd       bool   `json:"systemd"`
	Docker        bool   `json:"docker"`
	LXD           bool   `json:"lxd"`
}

var hostToken = regexp.MustCompile(`^[a-zA-Z0-9_.+:-]{1,128}$`)

func (f HostFacts) Validate() error {
	if !hostToken.MatchString(f.OS) || !hostToken.MatchString(f.Version) ||
		!hostToken.MatchString(f.Architecture) || !hostToken.MatchString(f.Kernel) ||
		f.CPUThreads < 1 || f.CPUThreads > 65536 ||
		f.MemoryBytes == 0 || f.RootTotal == 0 || f.RootAvailable > f.RootTotal {
		return ErrInvalid
	}
	return nil
}
