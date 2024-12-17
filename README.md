# iam-policies

## Purpose

This repository contains example and default OPA policies of the EOEPCA project.
These policies are automatically loaded into OPA by the OPAL server if it is
configured accordingly.

This repository can also be used as a template for the policy repositories
of custom EOEPCA deployments.

## Directory Structure

Policies are stored under the `policies` directory of the repository, which
is divided into two subtrees.

The `example` directory contains a set of simple example policies that are
generic and not directly related to EOEPCA.

The `eoepca` directory contains policies that are related to EOEPCA.
For each BB that requires policies there should be a separate subdirectory
that may be subdivided further if necessary. Rego and `data.json` files may live
in the BB-specific directory and/ or its subdirectories.

## Package Structure

The package declared by a Rego file should reflect the directory structure
under the `policies` directory. Usually the last package path element should
be the name of the Rego file without the `.rego` extension. For example, the
file `policies/eoepca/iam/util.rego` constitutes the package
`eoepca.iam.util`.

As an exception to this rule, Rego files that are just a
collection of simple policies need not be included in the package path.
An example for this is the file `policies/example/policies.rego`, which
contributes directly to the package `example`.

## Policy Implementation Guide

### Policy Levels

Policies can be used for different purposes and on different abstraction
levels. Policies can be evaluated on the following three levels:
* Ingress level (APISIX): Policies are focused on HTTP requests. A JWT,
  if present, is encoded into the `Authorization` header field and must
  be verified and decoded explicitly if needed.
* Authorization level (Keycloak): Policies are focused on attributes of
  users, resources etc. The contents of the JWT are available in decoded
  form.
* Custom level (other BBs): Other BBs may leverage policies for their own
  purposes. This may require passing BB-specific information that is 
  neither HTTP- nor authorization-related and thus does not fit into the
  categories above.

These policy levels are described in more detail below. 

#### Policies Related To HTTP Requests

HTTP-related policies are typically used by APISIX on the ingress level.
They can also be used by other BBs if they have to make decisions directly
based on HTTP requests.

For consistency, they should adhere as much as
possible to the input and output formats used by the
[APISIX OPA plugin](https://apisix.apache.org/docs/apisix/plugins/opa/)
for this purpose. This primarily applies to the `type` attribute and the
`request` and `var` sections of the input document. The
[output document](https://apisix.apache.org/docs/apisix/plugins/opa/#opa-service-to-apisix)
of the APISIX OPA plugin allows specifying a desired HTTP response,
which may also be useful in other cases.

#### Authorization-Related Policies

Authorization-related policies can be used in Keycloak as part of the
authorization process. They can also be used by other BBs that need to
make authorization-related decisions at a point where detailed
attributes of users and resources are available.

The format is specified by the Keycloak-OPA plugin. For consistency,
other BBs should adhere to it as much as possible when defining
authorization-related policies. The format specification can be found
[here](https://eoepca.readthedocs.io/projects/iam/en/latest/api/opa-policy-api/#interface-between-keycloak-and-opa).

#### Custom Policies

In some cases, BBs may require policy decisions that do not fall into one
of the categories above or that do, but need additional information to
be included in the input document or returned in the output document.

In this case, they may define their own input and output document formats.
However, where possible these formats should be based on one of the
predefined formats and only extend them as necessary. Bespoke formats
should only be used for use cases that are completely beyond the
standard ones.

### Policy Types

Policies can be implemented in two ways depending on their complexity
and the output document they are expected to produce.

#### Simple Policies

Simple policies are implemented by a single policy rule and usually
only return a single (typically boolean) value. Multiple such
policies can share the same package. They are identified by
the package path + their rule name.

Examples of (very) simple policy rules can be found in the file
`policies/example/policies.rego`.

#### Package-based Policies

A package containing simple policy rules can also be evaluated as
a policy rule. In this case, each policy rule contained in
the package contributes to the output document, which allows
constructing a structured output document piece by piece,
without implementing a single complex rule.

A realistic example can be found
[here](https://apisix.apache.org/docs/apisix/plugins/opa/#using-custom-response).
It constructs the response expected by APISIX using four simple rules.

This is a simplified variant of the example referenced above,
using Rego V1 syntax:
```
default allow = false
allow if { input.request.method == "GET" }
reason = "Only GET is allowed!" if { not allow } 
```
It only allows `GET` requests and adds the reason attribute to the
result if it rejects it because another HTTP method was used.
The result in the latter case may look like this:
```
{
    "result": {
        "allow": false,
        "reason": "Only GET is allowed!"
    }
}
```
