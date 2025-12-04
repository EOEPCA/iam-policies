package eoepca.resourceregistration.registrationapi

import rego.v1
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[registrationapi policy] START")
    claims := verified_claims
    print("[registrationapi policy] Claims: ", claims)
    claims != null

    # safe extraction
    rr := object.get(claims.resource_access, "resource_registration", {})
    rc := object.get(claims.resource_access, "resource-catalogue", {})

    rr_roles := object.get(rr, "roles", [])
    rc_roles := object.get(rc, "roles", [])

    roles := concat(rr_roles, rc_roles)
    print("[registrationapi policy] Roles: ", roles)

    "records_editor" in roles
}
