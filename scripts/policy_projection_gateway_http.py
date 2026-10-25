"""Bounded ASGI HTTP authentication for the explicit reference gateway.

The registry and logical state are trusted host inputs. This is an in-process
HTTP/ASGI experiment, not a production network deployment or native Agent IAM.
No credential, authentication header or controller method is serialized.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import secrets
import time

from memory_migration_study.policy_projection_gateway import AuthenticatedPrincipal

VERSION = "policy_projection_authenticated_asgi_v1"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class GatewayHTTP:
    def __init__(self, gateway, principals, *, max_requests=112):
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        from fastapi.testclient import TestClient

        if type(max_requests) is not int or not 1 <= max_requests <= 112:
            raise ValueError("invalid_gateway_http_cap")
        self.gateway, self.max_requests = gateway, max_requests
        self.requests, self._tokens, identities = [], {}, {}
        for row in principals:
            if set(row) != {"principal_id", "user_id", "agent_id"} or row["principal_id"] in identities:
                raise ValueError("invalid_http_principal_registry")
            pair = AuthenticatedPrincipal(row["user_id"], row["agent_id"])
            if pair in identities.values():
                raise ValueError("duplicate_http_principal_tuple")
            identities[row["principal_id"]] = pair
            self._tokens[row["principal_id"]] = secrets.token_urlsafe(48)
        self._identities = identities
        binding = {self._tokens[key]: value for key, value in identities.items()}
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        def authenticate(request):
            value = request.headers.get("authorization", "")
            if not value.startswith("Bearer "):
                return None
            return binding.get(value[7:])

        # Request is imported locally: avoid postponed annotations resolving it
        # against module globals in FastAPI's dependency introspection.
        async def identity(request):
            caller = authenticate(request)
            if caller is None:
                return JSONResponse({"error": "authentication_required"}, status_code=401)
            return JSONResponse({"user_id": caller.user_id, "agent_id": caller.agent_id})

        async def memory(request):
            caller = authenticate(request)
            if caller is None:
                return JSONResponse({"error": "authentication_required"}, status_code=401)
            raw = await request.body()
            if len(raw) > 16384:
                return JSONResponse({"error": "request_body_too_large"}, status_code=413)
            # Preserve exact bytes for the core's duplicate-key/nonfinite and
            # closed-schema validation instead of silently flattening JSON.
            result = gateway.dispatch(caller, raw)
            status = result.get("http_status")
            if type(status) is not int or status not in {200, 400, 403, 409, 502}:
                return JSONResponse({"error": "invalid_gateway_receipt"}, status_code=502)
            return JSONResponse(result, status_code=status)

        identity.__annotations__["request"] = Request
        memory.__annotations__["request"] = Request
        app.add_api_route("/v1/identity", identity, methods=["GET"])
        app.add_api_route("/v1/memory", memory, methods=["POST"])
        self._context = TestClient(app, raise_server_exceptions=False)
        self._client = self._context.__enter__()

    def request(self, principal_id, body=None, *, identity=False, invalid_credential=False):
        if len(self.requests) >= self.max_requests:
            raise ValueError("gateway_http_budget_exhausted")
        if principal_id is not None and principal_id not in self._tokens:
            raise ValueError("unknown_gateway_credential_handle")
        token = secrets.token_urlsafe(48) if invalid_credential else self._tokens.get(principal_id)
        headers = {"Authorization": "Bearer " + token} if token else {}
        path, method = ("/v1/identity", "GET") if identity else ("/v1/memory", "POST")
        self._client.cookies.clear()
        started = time.perf_counter_ns()
        response = self._client.request(method, path, headers=headers, **({} if identity else {"json": body}))
        raw = response.content
        if any(secret.encode() in raw for secret in self._tokens.values()):
            raise ValueError("gateway_credential_in_response")
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeError):
            parsed = None
        row = {"index": len(self.requests), "method": method, "path": path,
            "credential_handle": "invalid" if invalid_credential else principal_id,
            "authenticated_header_present": bool(headers), "request_body": deepcopy(body),
            "request_body_sha256": digest(response.request.content),
            "status": response.status_code, "raw_body": raw.decode("utf-8"),
            "response_body_sha256": digest(raw), "parsed": parsed,
            "started_ns": started, "completed_ns": time.perf_counter_ns()}
        self.requests.append(row)
        return deepcopy(row)

    def close(self):
        if self._context is not None:
            self._context.__exit__(None, None, None)
            self._context = self._client = None
        self._tokens.clear()

