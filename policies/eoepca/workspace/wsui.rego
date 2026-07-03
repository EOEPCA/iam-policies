# in use with eoepca-demo cluster anymore (Q2/2026)
#
# Example decoded access-token claims:
#
# Allowed for https://ws-alice-default.lab.develop.eoepca.org:
# {
#   "azp": "workspace-api",
#   "aud": ["workspace-api"],
#   "resource_access": {
#     "ws-alice": {
#       "roles": ["ws_access"]
#     }
#   }
# }
#
# Also allowed:
# {
#   "azp": "workspace-api",
#   "aud": "workspace-api",
#   "resource_access": {
#     "ws-alice": {
#       "roles": ["ws_admin"]
#     }
#   }
# }
#
# Denied because ws_api is not sufficient:
# {
#   "azp": "workspace-api",
#   "aud": ["workspace-api"],
#   "resource_access": {
#     "ws-alice": {
#       "roles": ["ws_api"]
#     }
#   }
# }
#
# Denied because the token was issued for the workspace client, not workspace-api:
# {
#   "azp": "ws-alice",
#   "aud": ["workspace-api"],
#   "resource_access": {
#     "ws-alice": {
#       "roles": ["ws_access"]
#     }
#   }
# }

package eoepca.workspace.wsui

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

claims := verified_claims

host_label := label if {
    host_parts := split(request.host, ".")
    count(host_parts) > 0
    label := host_parts[0]
    label != ""
}

workspace_client := client if {
    label := normalized_host_label
    parts := split(label, "-default")
    count(parts) > 1
    client := parts[0]
    client != ""
    claims.resource_access[client] != null
}

normalized_host_label := label if {
    label := trim_host_affixes(host_label)
}

trim_host_affixes(label) := trimmed if {
    startswith(label, "editor-")
    trimmed := trim_host_suffix(substring(label, count("editor-"), -1))
}

trim_host_affixes(label) := trimmed if {
    startswith(label, "data-")
    trimmed := trim_host_suffix(substring(label, count("data-"), -1))
}

trim_host_affixes(label) := trimmed if {
    not startswith(label, "editor-")
    not startswith(label, "data-")
    trimmed := trim_host_suffix(label)
}

trim_host_suffix(label) := trimmed if {
    endswith(label, "-editor")
    trimmed := substring(label, 0, count(label) - count("-editor"))
}

trim_host_suffix(label) := trimmed if {
    endswith(label, "-data")
    trimmed := substring(label, 0, count(label) - count("-data"))
}

trim_host_suffix(label) := label if {
    not endswith(label, "-editor")
    not endswith(label, "-data")
}

workspace_api_token if {
    claims != null
    claims.azp == "workspace-api"
    audience_includes("workspace-api")
}

audience_includes(audience) if {
    claims.aud == audience
}

audience_includes(audience) if {
    audience in claims.aud
}

has_workspace_role(client, role) if {
    claims != null
    claims.resource_access != null
    claims.resource_access[client] != null
    role in claims.resource_access[client].roles
}

has_workspace_access(client) if {
    has_workspace_role(client, "ws_access")
}

has_workspace_access(client) if {
    has_workspace_role(client, "ws_admin")
}

allow if {
    workspace_api_token
    client := workspace_client
    has_workspace_access(client)
}
