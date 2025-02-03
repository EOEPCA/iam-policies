package eoepca.workspace.wsui

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[wsui policy] START")
    print("[wsui policy] Host: ", request.host)´
    host_parts := split(request.host, ".")
    wsName := host_parts[0]
    claims := verified_claims
    claims != null
    print("[wsui policy] Claims: ", claims)
    "ws_access" in claims.resource_access[wsName].roles
}
