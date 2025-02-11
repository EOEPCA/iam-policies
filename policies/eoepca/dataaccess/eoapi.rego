package eoepca.dataaccess.eoapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[eoapi policy] START1")
    request.method == "GET"
    startswith(request.path, "/stac/collections/")
    not contains(request.path, "123") # for testing
}

allow if {
    print("[eoapi policy] START2")
    claims := verified_claims
    print("[eoapi policy] Claims: ", claims)
    claims != null
    "stac_editor" in claims.resource_access[eoepca].roles
}
