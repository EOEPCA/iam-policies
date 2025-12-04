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

    rr := object.get(claims.resource_access, "resource_registration", null)
    rc := object.get(claims.resource_access, "resource-catalogue", null)

    roles := object.get(rr, "roles", []) ++ object.get(rc, "roles", [])

    "records_editor" in roles
}
