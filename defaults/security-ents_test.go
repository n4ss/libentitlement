package defaults

import (
	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/docker/libentitlement/testutils"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecurityConfinedEntitlementEnforce(t *testing.T) {
	entitlementID := SecurityConfinedEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{
		osdefs.CapMacAdmin, osdefs.CapMacOverride, osdefs.CapDacOverride, osdefs.CapDacReadSearch, osdefs.CapSetpcap, osdefs.CapSetfcap, osdefs.CapSetuid, osdefs.CapSetgid,
		osdefs.CapSysPtrace, osdefs.CapFsetid, osdefs.CapSysModule, osdefs.CapSyslog, osdefs.CapSysRawio, osdefs.CapSysAdmin, osdefs.CapLinuxImmutable,
	}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, nil, capsToRemove))

	syscallsToBlock := []types.Syscall{
		osdefs.SysPtrace, osdefs.SysArchPrctl, osdefs.SysPersonality, osdefs.SysMadvise,
	}
	require.True(t, testutils.SeccompSyscallsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsToBlock))

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		osdefs.SysPrctl: {
			{
				Index: 0,
				Value: osdefs.PrCapbsetDrop,
				Op:    specs.OpNotEqual,
			},
			{
				Index: 0,
				Value: osdefs.PrCapbsetRead,
				Op:    specs.OpNotEqual,
			},
		},
	}
	require.True(t, testutils.SeccompSyscallsWithArgsAllowed(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToAllow))
}

func TestSecurityViewEntitlementEnforce(t *testing.T) {
	entitlementID := SecurityViewEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{
		osdefs.CapSysAdmin, osdefs.CapSysPtrace,
		osdefs.CapSetuid, osdefs.CapSetgid, osdefs.CapSetpcap, osdefs.CapSetfcap,
		osdefs.CapMacAdmin, osdefs.CapMacOverride, osdefs.CapAuditRead,
		osdefs.CapDacOverride, osdefs.CapFsetid, osdefs.CapSysModule, osdefs.CapSyslog, osdefs.CapSysRawio, osdefs.CapLinuxImmutable,
	}
	capsToAdd := []types.Capability{osdefs.CapDacReadSearch}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, capsToAdd, capsToRemove))

	syscallsToBlock := []types.Syscall{
		osdefs.SysPtrace,
		osdefs.SysPersonality,
		osdefs.SysMadvise,
	}
	require.True(t, testutils.SeccompSyscallsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsToBlock))

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		osdefs.SysPrctl: {
			{
				Index: 0,
				Value: osdefs.PrCapbsetDrop,
				Op:    specs.OpNotEqual,
			},
		},
	}
	require.True(t, testutils.SeccompSyscallsWithArgsAllowed(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToAllow))
}

func TestSecurityAdminEntitlementEnforce(t *testing.T) {
	entitlementID := SecurityAdminEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToAdd := []types.Capability{
		osdefs.CapMacAdmin, osdefs.CapMacOverride, osdefs.CapDacOverride, osdefs.CapDacReadSearch, osdefs.CapSetpcap, osdefs.CapSetfcap, osdefs.CapSetuid, osdefs.CapSetgid,
		osdefs.CapSysPtrace, osdefs.CapFsetid, osdefs.CapSysModule, osdefs.CapSyslog, osdefs.CapSysRawio, osdefs.CapSysAdmin, osdefs.CapLinuxImmutable, osdefs.CapSysBoot,
		osdefs.CapSysNice, osdefs.CapSysPacct, osdefs.CapSysTtyConfig, osdefs.CapSysTime, osdefs.CapWakeAlarm, osdefs.CapAuditRead, osdefs.CapAuditWrite, osdefs.CapAuditControl,
	}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, capsToAdd, nil))

	syscallsToAllow := []types.Syscall{
		osdefs.SysPtrace, osdefs.SysArchPrctl, osdefs.SysPersonality, osdefs.SysSetuid, osdefs.SysSetgid, osdefs.SysPrctl, osdefs.SysMadvise, osdefs.SysMount, osdefs.SysInitModule,
		osdefs.SysFinitModule, osdefs.SysSetns, osdefs.SysClone, osdefs.SysUnshare,
	}
	require.True(t, testutils.SeccompSyscallsAllowed(*newOCIProfile.OCI.Linux.Seccomp, syscallsToAllow))

	require.Empty(t, ociProfile.OCI.Linux.ReadonlyPaths)
}

func TestSecurityMemoryLockEntitlementEnforce(t *testing.T) {
	entitlementID := SecurityMemoryLockFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToAdd := []types.Capability{
		osdefs.CapIpcLock,
	}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, capsToAdd, nil))

	syscallsToAllow := []types.Syscall{
		osdefs.SysMlock, osdefs.SysMunlock, osdefs.SysMlock2, osdefs.SysMlockall, osdefs.SysMunlockall,
	}
	require.True(t, testutils.SeccompSyscallsAllowed(*newOCIProfile.OCI.Linux.Seccomp, syscallsToAllow))
}
