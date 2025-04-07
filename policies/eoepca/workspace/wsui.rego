package eoepca.workspace.wsui

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[wsui policy] START1")
    print("[wsui policy] Path: ", request.path)
    path := split(request.path, "/")
    count(path) > 1
    "" == path[0]
    "share" == path[1]
}

allow if {
    print("[wsui policy] START2")
    print("[wsui policy] Path: ", request.path)
    path := split(request.path, "/")
    count(path) > 2
    "" == path[0]
    "api" == path[1]
    "public" == path[2]
}

allow if {
    print("[wsui policy] START3")
    print("[wsui policy] Path: ", request.path)
    path := split(request.path, "/")
    count(path) > 2
    "" == path[0]
    "api" == path[1]
    "login" == path[2]
}

allow if {
    print("[wsui policy] START4")
    print("[wsui policy] Host: ", request.host)
    host_parts := split(request.host, ".")
    wsName := host_parts[0]
    claims := verified_claims
    claims != null
    print("[wsui policy] Claims: ", claims)
    "ws_access" in claims.resource_access[wsName].roles
}
