package eoepca.workspace.wsui

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    print("[wsui policy] START")
    claims := verified_claims
    claims != null

    print("[wsui policy] URL: ", request.url)
    print("[wsui policy] Claims: ", claims)
    url := request.url
    host_parts := split(url, "/")
    print("[wsui policy] host_parts: ", host_parts)
    domain := host_parts[2]
    ws_parts := split(domain, ".")
    print("[wsui policy] ws_parts: ", ws_parts)
    wsName := ws_parts[0]
    "ws_access" in claims.resource_access[wsName].roles
}
