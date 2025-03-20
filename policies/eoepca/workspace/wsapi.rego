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

allow if {
    claims := verified_claims
    claims != null
    claims.resource_access != null
    claims.resource_access["workspace-api"] != null
    "admin" in claims.resource_access["workspace-api"].roles
}

allow if {
    claims := verified_claims
    claims != null
    claims.resource_access != null
    path := split(request.path, "/")
    "" == path[0]
    "workspaces" == path[1]
    wsName := path[2]    
    claims.resource_access[wsName] != null
    "ws_access" in claims.resource_access[wsName].roles
#    print("[wsapi policy] Path: ", request.path, " -> ", path)
#    print("[wsapi policy] Method: ", request.method)
#    print("[wsapi policy] Claims: ", claims)
}