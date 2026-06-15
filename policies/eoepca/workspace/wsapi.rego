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

# OPA Policy for Workspace API Protection

package eoepca.workspace.wsapi

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

claims := verified_claims

workspace_name := wsName if {
    path := split(request.path, "/")
    count(path) > 2
    "" == path[0]
    "workspaces" == path[1]
    wsName := path[2]
    wsName != ""
}

is_workspace_api_admin if {
    claims != null
    claims.resource_access != null
    claims.resource_access["workspace-api"] != null
    "admin" in claims.resource_access["workspace-api"].roles
}

has_workspace_role(wsName, role) if {
    claims != null
    claims.resource_access != null
    claims.resource_access[wsName] != null
    role in claims.resource_access[wsName].roles
}

allow if {
    print("[wsapi policy] START1 workspace-api:admin")
    print("[wsapi policy] Path: ", request.path)
    print("[wsapi policy] Method: ", request.method)
    is_workspace_api_admin
}

allow if {
    print("[wsapi policy] START2 <ws-client>:ws_access")
    print("[wsapi policy] Path: ", request.path)
    print("[wsapi policy] Method: ", request.method)
    wsName := workspace_name
    print("[wsapi policy] Claims: ", claims)
    has_workspace_role(wsName, "ws_access")
}

allow if {
    print("[wsapi policy] START3 <ws-client>:ws_admin")
    print("[wsapi policy] Path: ", request.path)
    print("[wsapi policy] Method: ", request.method)
    wsName := workspace_name
    print("[wsapi policy] Claims: ", claims)
    has_workspace_role(wsName, "ws_admin")
}
