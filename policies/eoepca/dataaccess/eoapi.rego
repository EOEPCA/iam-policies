package eoepca.dataaccess.eoapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[eoapi policy] START1")
    request.method == "GET"
    path_contains(request.path, "/stac/collections/")
    not path_contains(request.path, "123")
}

path_contains(path, substring) {
    count([x | x = substring; x in path]) > 0
}

allow if {
    print("[eoapi policy] START2")
    claims := verified_claims
    print("[eoapi policy] Claims: ", claims)
    claims != null
    "stac_editor" in claims.resource_access[eoapi].roles
}
