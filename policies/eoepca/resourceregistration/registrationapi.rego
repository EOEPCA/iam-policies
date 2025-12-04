package eoepca.resourceregistration.registrationapi

import rego.v1
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[registrationapi policy1] START")
    claims := verified_claims
    print("[registrationapi policy1] Claims: ", claims)
    claims != null

    rr := object.get(claims.resource_access, "resource_registration", {})
    roles := object.get(rr, "roles", [])

    "records_editor" in roles
}

allow if {
    print("[registrationapi policy2] START")
    claims := verified_claims
    print("[registrationapi policy2] Claims: ", claims)
    claims != null

    rc := object.get(claims.resource_access, "resource-catalogue", {})
    roles := object.get(rc, "roles", [])

    "records_editor" in roles
}
