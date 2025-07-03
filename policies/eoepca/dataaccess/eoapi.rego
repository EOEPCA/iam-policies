package eoepca.dataaccess.eoapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[eoapi policy] START1")

    request.method == "GET"

    startswith(request.path, "/stac/collections/")
    
    path_parts := split(request.path, "/")
    some i
    path_parts[i] == "collections"
    collection := path_parts[i+1]
    
    not contains(collection, ".")
    
    print("[eoapi policy] Access granted for public collection ", collection)    
}

allow if {
    print("[eoapi policy] START2")

    startswith(request.path, "/stac/collections/")

    path_parts := split(request.path, "/")
    some i
    path_parts[i] == "collections"
    collection := path_parts[i+1]

    segments := split(collection, ".")
    count(segments) > 1

    claims := verified_claims
    print("[eoapi policy] Claims: ", claims)
    claims != null
    
    "ws_access" in claims.resource_access[segments[0]].roles

    print("[eoapi policy] Access granted for private collection ", collection)    
}

allow if {
    print("[eoapi policy] START3")

    claims := verified_claims
    print("[eoapi policy] Claims: ", claims)
    claims != null

    "stac_editor" in claims.resource_access["eoapi"].roles
}
