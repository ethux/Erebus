"""Erebus enterprise server gateway (specs/007-server-gateway).

A multi-tenant gateway between an organization and the cloud AI providers. This
package is an architectural client of ``erebus.core`` (like ``erebus.proxy``) and
owns all server-side concerns: tenancy, per-scope crypto, the Postgres state
layer, governance, and provider routing. The per-machine shim/proxy are not used
on the server path.

Status: under construction. The per-scope crypto core (``erebus.gateway.crypto``)
is implemented and unit-tested; the FastAPI runtime and Postgres state layer are
not built yet.
"""
