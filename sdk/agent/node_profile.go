package agent

import (
	"regexp"
	"strings"
)

// PackagePin is an exact version from a preconfigured trusted Ubuntu source.
// Names and versions are data; never transform them into shell expressions.
type PackagePin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type UpdatePolicy struct {
	Security string `json:"security"`
	Packages string `json:"packages"`
	Reboot   string `json:"reboot"`
}

// NodeProfile is an immutable administrator-approved declaration. It is not an
// executable instruction and is never accepted in lieu of a signed operation.
type NodeProfile struct {
	ID       string       `json:"id"`
	Revision int64        `json:"revision"`
	Ubuntu   []string     `json:"ubuntu"`
	Packages []PackagePin `json:"packages"`
	Docker   bool         `json:"docker"`
	LXD      bool         `json:"lxd"`
	Updates  UpdatePolicy `json:"updates"`
}

var profilePackage = regexp.MustCompile("^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$")
var profileVersion = regexp.MustCompile("^[0-9][a-zA-Z0-9.+:~_-]{0,127}$")

// Protected system components must be managed by dedicated, audited procedures
// with explicit recovery plans, not generic APT profile reconciliation.
func protectedPackage(name string) bool {
	switch name {
	case "apt", "dpkg", "systemd", "sudo", "openssh-server",
		"openssh-client", "ufw", "netplan.io", "docker.io", "containerd",
		"lxd", "snapd", "arc-agent", "nats-server":
		return true
	}
	return strings.HasPrefix(name, "linux-image-") ||
		strings.HasPrefix(name, "linux-headers-") ||
		strings.HasPrefix(name, "linux-generic")
}

// Validate rejects unbounded or ambiguous profiles and protects bootstrap
// dependencies. Package order is canonical and versions are mandatory.
func (p NodeProfile) Validate() error {
	if !ValidID(p.ID) || Bootstrap(p.ID) || p.Revision < 1 || p.Revision > maxRevision ||
		len(p.Ubuntu) == 0 || len(p.Ubuntu) > 4 || len(p.Packages) > 32 ||
		(p.Updates.Security != "manual" && p.Updates.Security != "unattended") ||
		p.Updates.Packages != "manual" || p.Updates.Reboot != "manual" {
		return ErrInvalid
	}
	prevRelease := ""
	for _, release := range p.Ubuntu {
		if release != "22.04" && release != "24.04" && release != "26.04" {
			return ErrInvalid
		}
		if release <= prevRelease {
			return ErrInvalid
		}
		prevRelease = release
	}
	prevPackage := ""
	for _, pkg := range p.Packages {
		if len(pkg.Name) > 128 || !profilePackage.MatchString(pkg.Name) ||
			protectedPackage(pkg.Name) || !profileVersion.MatchString(pkg.Version) ||
			pkg.Name <= prevPackage {
			return ErrInvalid
		}
		prevPackage = pkg.Name
	}
	return nil
}

func NodeProfileDigest(p NodeProfile) string {
	if p.Validate() != nil {
		return ""
	}
	return objectDigest(p)
}
