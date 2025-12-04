package eoepca.resourceregistration.registrationapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[registrationapi policy] START")
    claims := verified_claims
    print("[registrationapi policy] Claims: ", claims)
    claims != null
    claims.resource_access != null
}
