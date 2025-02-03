package eoepca.workspace.wsui

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    claims := verified_claims
    claims != null

    url := request.url
    host_parts := split(url, "/")
    domain := host_parts[2]
    ws_parts := split(domain, ".")
    wsName := ws_parts[0]
    "ws_access" in claims.resource_access[wsName].roles
}
