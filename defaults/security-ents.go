// +build linux
package defaults

import (
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"fmt"
	"syscall"
)

const (
	securityDomain = "security"
)

const (
	SecurityNoneEntFullId  = securityDomain + ".none"
	SecurityUserEntFullId  = securityDomain + ".user"
	SecurityProxyEntFullId = securityDomain + ".proxy"
	SecurityAdminEntFullId = securityDomain + ".admin"
)

func securityConfinedEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkNoneEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkNoneEntFullId)
	}

	capsToRemove := []string{"CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
		"CAP_SETPCAP", "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_FSETID", "CAP_SYS_MODULE",
		"CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.RemoveCaps(capsToRemove...)

	syscallsToBlock := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl"
		"madvise",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow :=  map[string][]specs.LinuxSeccompArg{
		"prctl": {
			{
				Index: 0,
				Value: syscall.PR_CAPBSET_DROP,
				Op: specs.OpNotEqual,
			},
			{
				Index: 0,
				Value: syscall.PR_CAPBSET_READ,
				Op: specs.OpNotEqual,
			},
		},
	}
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	/* FIXME: Add AppArmor rules to deny RW on sensitive FS directories */

	return ociProfile, nil
}

func securityViewEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkNoneEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkNoneEntFullId)
	}

	capsToRemove := []string{"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP",
		"CAP_SETFCAP", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_FSETID",
		"CAP_SYS_MODULE","CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_DAC_READ_SEARCH"}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToBlock := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl",
		"madvise",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow :=  map[string][]specs.LinuxSeccompArg{
		"prctl": {
			{
				Index: 0,
				Value: syscall.PR_CAPBSET_DROP,
				Op: specs.OpNotEqual,
			},
			{
				Index: 0,
				Value: syscall.PR_CAPBSET_READ,
				Op: specs.OpNotEqual,
			},
		},
	}
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	/* FIXME: Add AppArmor rules to RO on sensitive FS directories */

	return ociProfile, nil
}

func securityAdminEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkNoneEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkNoneEntFullId)
	}

	capsToAdd := []string{
		"CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
		"CAP_SETPCAP", "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_FSETID", "CAP_SYS_MODULE",
		"CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl",
		"madvise",
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	return ociProfile, nil
}

func securityMemoryLockEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkNoneEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkNoneEntFullId)
	}

	capsToAdd := []string{
		"CAP_IPC_LOCK",
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []string{
		"mlock", "munlock", "mlock2", "mlockall", "munlockall",
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	return ociProfile, nil
}