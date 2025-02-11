package eoepca.dataaccess.eoapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[eoapi policy] START1")
    request.method == "GET"
    count([x | x = "/stac/collections/"; x in request.path]) > 0
    not count([x | x = "123"; x in request.path]) > 0  # for testing check if path does not contain "123"
}

allow if {
    print("[eoapi policy] START2")
    claims := verified_claims
    print("[eoapi policy] Claims: ", claims)
    claims != null
    "stac_editor" in claims.resource_access[eoepca].roles
}
