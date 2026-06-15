# Copyright 2024 Werum Software & Systems AG (Germany)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# OPA Policy for Workspace UI Protection

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
    claims != null
    client := claims.azp
    client != ""
    host_matches_client(host_label, client)
}

host_matches_client(host, client) if {
    host == client
}

host_matches_client(host, client) if {
    startswith(host, concat("", [client, "-"]))
}

host_matches_client(host, client) if {
    startswith(host, concat("", ["editor-", client, "-"]))
}

host_matches_client(host, client) if {
    startswith(host, concat("", ["data-", client, "-"]))
}

is_workspace_api_admin if {
    claims != null
    claims.resource_access != null
    claims.resource_access["workspace-api"] != null
    "admin" in claims.resource_access["workspace-api"].roles
}

has_workspace_role(client, role) if {
    claims != null
    claims.resource_access != null
    claims.resource_access[client] != null
    role in claims.resource_access[client].roles
}

allow if {
    print("[wsui policy] START1 workspace-api:admin")
    print("[wsui policy] Host: ", request.host)
    is_workspace_api_admin
}

allow if {
    print("[wsui policy] START2 <ws-client>:ws_access")
    print("[wsui policy] Host: ", request.host)
    client := workspace_client
    print("[wsui policy] Client: ", client)
    print("[wsui policy] Claims: ", claims)
    has_workspace_role(client, "ws_access")
}

allow if {
    print("[wsui policy] START3 <ws-client>:ws_admin")
    print("[wsui policy] Host: ", request.host)
    client := workspace_client
    print("[wsui policy] Client: ", client)
    print("[wsui policy] Claims: ", claims)
    has_workspace_role(client, "ws_admin")
}
