package testutils

import (
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"reflect"
)

func capListContains(capList []string, capability types.Capability) bool {
	capStr := string(capability)

	for _, capElt := range capList {
		if capElt == capStr {
			return true
		}
	}

	return false
}

// TestSpec is a test OCI struct with a default Seccomp profile
func TestSpec() *specs.Spec {
	s := &specs.Spec{
		Process: specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
		Linux: &specs.Linux{
			Seccomp:   &specs.LinuxSeccomp{},
			Resources: &specs.LinuxResources{},
			IntelRdt:  &specs.LinuxIntelRdt{},
		},
		Windows: &specs.Windows{
			Resources: &specs.WindowsResources{
				Memory:  &specs.WindowsMemoryResources{},
				CPU:     &specs.WindowsCPUResources{},
				Storage: &specs.WindowsStorageResources{},
				Network: &specs.WindowsNetworkResources{},
			},
		},
	}

	seccomp, err := getDefaultSeccompProfile()
	if err != nil {
		// In case we get an error before seccomp struct is fully updated from decoded json, we empty it manually.
		s.Linux.Seccomp = &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	} else {
		s.Linux.Seccomp = seccomp
	}

	s.Process.Capabilities.Bounding = getDefaultCapList()
	s.Process.Capabilities.Effective = getDefaultCapList()
	s.Process.Capabilities.Inheritable = getDefaultCapList()
	s.Process.Capabilities.Permitted = getDefaultCapList()

	return s
}

// SyscallArgsMatchSeccompRuleArgs checks that the seccomp rule's args match the provided syscall args
func SyscallArgsMatchSeccompRuleArgs(syscallArgsRule, syscallArgsSyscall []specs.LinuxSeccompArg) bool {
	if len(syscallArgsRule) < len(syscallArgsSyscall) ||
		(len(syscallArgsSyscall) == 0 && len(syscallArgsRule) != 0) {
		return false
	}

	for _, syscallArgFromSyscall := range syscallArgsSyscall {
		found := false

		for _, syscallArgsFromRule := range syscallArgsRule {
			if reflect.DeepEqual(syscallArgFromSyscall, syscallArgsFromRule) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// MatchSeccompRule checks that the seccomp rule matches the provided syscall and args
func MatchSeccompRule(seccompRule specs.LinuxSyscall, syscallName string, syscallArgs []specs.LinuxSeccompArg) bool {
	for _, name := range seccompRule.Names {
		if name == syscallName {
			if SyscallArgsMatchSeccompRuleArgs(seccompRule.Args, syscallArgs) {
				return true
			}
		}
	}

	return false
}

// SeccompSyscallWithArgsBlocked checks that the provided syscall and args are blocked by the seccomp profile
func SeccompSyscallWithArgsBlocked(seccompProfile specs.LinuxSeccomp, syscallName types.Syscall, syscallArgs []specs.LinuxSeccompArg) bool {
	syscallNameStr := string(syscallName)

	blocked := seccompProfile.DefaultAction == specs.ActErrno

	if blocked {
		// For each rule in the seccomp profile, make sure that no whitelisting rule contains this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActAllow {
				// If we match a whitelisting rule containing this syscall and those arguments, syscall is not blocked
				if MatchSeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return false
				}
			}
		}
	} else {
		// For each rule in the seccomp profile, make sure that at least one blacklisting rule contain this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActErrno {
				// If we match a blacklisting rule containing this syscall and those arguments, syscall is blocked
				if MatchSeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return true
				}
			}
		}
	}

	return blocked
}

// SeccompSyscallsWithArgsBlocked checks that the provided list of syscalls and args are blocked by the seccomp profile
func SeccompSyscallsWithArgsBlocked(seccompProfile specs.LinuxSeccomp, syscallsWithArgs map[types.Syscall][]specs.LinuxSeccompArg) bool {
	for syscallName, syscallArgs := range syscallsWithArgs {
		if !SeccompSyscallWithArgsBlocked(seccompProfile, syscallName, syscallArgs) {
			return false
		}
	}

	return true
}

// SeccompSyscallsBlocked checks that the provided syscalls are blocked by the seccomp profile
func SeccompSyscallsBlocked(seccompProfile specs.LinuxSeccomp, syscallNames []types.Syscall) bool {
	for _, syscallName := range syscallNames {
		if !SeccompSyscallWithArgsBlocked(seccompProfile, syscallName, []specs.LinuxSeccompArg{}) {
			return false
		}
	}

	return true
}

// SeccompSyscallWithArgsAllowed checks that the provided syscall and args are whitelisted by the seccomp profile
func SeccompSyscallWithArgsAllowed(seccompProfile specs.LinuxSeccomp, syscallName types.Syscall, syscallArgs []specs.LinuxSeccompArg) bool {
	return !SeccompSyscallWithArgsBlocked(seccompProfile, syscallName, syscallArgs)
}

// SeccompSyscallsWithArgsAllowed checks that the provided list of syscalls and args are whitelisted by the seccomp profile
func SeccompSyscallsWithArgsAllowed(seccompProfile specs.LinuxSeccomp, syscallsWithArgs map[types.Syscall][]specs.LinuxSeccompArg) bool {
	for syscallName, syscallArgs := range syscallsWithArgs {
		if !SeccompSyscallWithArgsAllowed(seccompProfile, syscallName, syscallArgs) {
			return false
		}
	}

	return true
}

// SeccompSyscallsAllowed checks that the provided syscalls are whitelisted by the seccomp profile
func SeccompSyscallsAllowed(seccompProfile specs.LinuxSeccomp, syscallNames []types.Syscall) bool {
	for _, syscallName := range syscallNames {
		if !SeccompSyscallWithArgsAllowed(seccompProfile, syscallName, []specs.LinuxSeccompArg{}) {
			return false
		}
	}

	return true
}

// CapBlocked checks that the provided capability is not allowed
func CapBlocked(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return !(capListContains(linuxCaps.Bounding, capability) || capListContains(linuxCaps.Permitted, capability) ||
		capListContains(linuxCaps.Inheritable, capability) || capListContains(linuxCaps.Effective, capability))
}

// CapsBlocked checks that capabilities in the provided cap list are not allowed
func CapsBlocked(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !CapBlocked(linuxCaps, capability) {
			return false
		}
	}

	return true
}

// CapAllowed checks that the provided capability is allowed
func CapAllowed(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return capListContains(linuxCaps.Bounding, capability) && capListContains(linuxCaps.Permitted, capability) &&
		capListContains(linuxCaps.Inheritable, capability) && capListContains(linuxCaps.Effective, capability)
}

// CapsAllowed checks that capabilities in the provided cap list are allowed
func CapsAllowed(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !CapAllowed(linuxCaps, capability) {
			return false
		}
	}

	return true
}

// capsListMatchRefSet checks that the cap list and the reference set contain the same capabilities
func capsListMatchRefSet(refWithConstraints map[types.Capability]bool, capList []string) bool {
	if len(refWithConstraints) != len(capList) {
		return false
	}

	refWithConstraintsStr := make(map[string]bool)
	for cap, val := range refWithConstraints {
		refWithConstraintsStr[string(cap)] = val
	}

	for _, cap := range capList {
		if _, ok := refWithConstraintsStr[cap]; !ok {
			return false
		}
	}

	return true
}

// capsListMatchRefWithConstraints checks that a provided list of capabilities matches exactly the content of
// the default capabilities plus a list of capabilities to add minus a list of capabilities to remove
func capsListMatchRefWithConstraints(capList []string, capsToAdd, capsToRemove []types.Capability) bool {
	refWithConstraints := getDefaultCapSet()

	for _, capToAdd := range capsToAdd {
		if _, ok := refWithConstraints[capToAdd]; !ok {
			refWithConstraints[capToAdd] = true
		}
	}

	for _, capToRemove := range capsToRemove {
		if _, ok := refWithConstraints[capToRemove]; ok {
			delete(refWithConstraints, capToRemove)
		}
	}

	return capsListMatchRefSet(refWithConstraints, capList)
}

// OCICapsMatchRefWithConstraints checks that all OCI capability lists match exactly the ref cap list with
// entitlement's constraints to apply.
func OCICapsMatchRefWithConstraints(capabilities specs.LinuxCapabilities, capsToAdd, capsToRemove []types.Capability) bool {
	capStrLists := [][]string{
		capabilities.Permitted,
		capabilities.Inheritable,
		capabilities.Effective,
		capabilities.Bounding,
	}

	match := true

	for _, capStrList := range capStrLists {
		match = match && capsListMatchRefWithConstraints(capStrList, capsToAdd, capsToRemove)
	}

	return match
}

// NamespaceActivated checks that the provided namespace is enabled
func NamespaceActivated(nsList []specs.LinuxNamespace, namespace specs.LinuxNamespaceType) bool {
	for _, ns := range nsList {
		if ns.Type == namespace {
			return true
		}
	}

	return false
}

// NamespacesActivated checks that the namespaces in the provided ns list are enabled
func NamespacesActivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if !NamespaceActivated(nsList, namespace) {
			return false
		}
	}

	return true
}

// NamespacesDeactivated checks that the namespaces in the provided ns list are disabled
func NamespacesDeactivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if NamespaceActivated(nsList, namespace) {
			return false
		}
	}

	return true
}
