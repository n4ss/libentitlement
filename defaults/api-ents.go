package defaults

import (
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"strings"
	"fmt"
)

const (
	apiDomain = "api"

	APIEntFullID = apiDomain
)

var (
	apiEntitlement  = entitlement.NewStringEntitlement(APIEntFullID, apiEntitlementEnforce)
)

func apiEntitlementEnforce(profile secprofile.Profile, apiSubsetAndAccess string) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, NetworkNoneEntFullID)
	if err != nil {
		return nil, err
	}

	apiSubsetAndAccessFields := strings.Split(apiSubsetAndAccess, ":")
	if len(apiSubsetAndAccessFields) != 3 {
		return nil, fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\"")
	}

	apiID := apiSubsetAndAccessFields[0]
	apiSubset := apiSubsetAndAccessFields[1]
	access := apiSubsetAndAccessFields[2]
	if access != string(secprofile.Access) && access != string(secprofile.Deny) {
		return nil, fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\"")
	}

	if ociProfile.APIAccess == nil {
		return nil, fmt.Errorf("OCI profile's APIAccess field nil")
	}

	apiIDSubsets := ociProfile.APIAccess.APIRights[secprofile.APIID(apiID)]
	apiIDSubsets[secprofile.APISubsetId(apiSubset)] = secprofile.APIAccess(access)

	return ociProfile, nil
}