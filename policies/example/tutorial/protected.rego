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

# Simple example OPA policy rules

package example.tutorial.protected

import rego.v1
import input.request
import data.eoepca.iam.util.verified_claims

default allow = false

allow if {
    claims := verified_claims
    claims != null
    claims.preferred_username == data.policies.example.privileged_users[_]
}
