"""Real HTTP reference executor and the explicit evidence-contract HTTP adapter."""
from __future__ import annotations

import http.client
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


class ReferenceAPI:
    """Test-only backend. Tokens bind both user and executing agent on the server."""

    def __init__(self, case: dict, plan: dict, fault: str = "none", page_size: int = 2):
        if fault not in {"none", "error_body_leak", "list_bypass"}:
            raise ValueError("unknown artificial fault")
        self.case, self.plan, self.fault = case, plan, fault
        self.page_size = max(1, page_size)
        self.credentials = {a["actor_id"]: secrets.token_urlsafe(24) for a in case["actors"]}
        self.bindings = {self.credentials[a["actor_id"]]: dict(a, actor_id=case["actor_mapping"][a["actor_id"]]) for a in case["actors"]}
        self.objects = [dict(o, readers=[case["actor_mapping"][r] for r in o["readers"]]) for o in plan["objects"]]
        self.controls = {}
        for actor in case["actors"]:
            aid = actor["actor_id"]
            target = f"{plan['run_id']}/control/{quote(aid, safe='')}"
            text = f"positive-control:{secrets.token_hex(12)}"
            self.controls[aid] = {"target_id": target, "text_sha256": hashlib.sha256(text.encode()).hexdigest()}
            self.objects.append({"target_id": target, "source_id": "__positive_control__",
                                 "text": text, "readers": [case["actor_mapping"][aid]]})
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                actor = owner.bindings.get(token)
                path = urlsplit(self.path)
                if actor is None:
                    return self.reply(401, {"error": "invalid credential"})
                # Query/body identity claims are deliberately ignored.
                if path.path == "/whoami":
                    return self.reply(200, actor)
                if path.path == "/objects":
                    visible = [o for o in owner.objects if actor["actor_id"] in o["readers"] or owner.fault == "list_bypass"]
                    try:
                        offset = int(parse_qs(path.query).get("offset", ["0"])[0])
                        if offset < 0:
                            raise ValueError()
                    except ValueError:
                        return self.reply(400, {"error": "invalid offset"})
                    page = visible[offset:offset + owner.page_size]
                    next_offset = offset + owner.page_size
                    return self.reply(200, {"items": [owner.public(o) for o in page],
                                           "complete": next_offset >= len(visible),
                                           "next_offset": None if next_offset >= len(visible) else next_offset})
                if path.path.startswith("/objects/"):
                    target = unquote(path.path[len("/objects/"):])
                    found = next((o for o in owner.objects if o["target_id"] == target), None)
                    if found is None:
                        return self.reply(404, {"error": "missing"})
                    if actor["actor_id"] not in found["readers"]:
                        if owner.fault == "error_body_leak":
                            return self.reply(500, {"error": "artificial fault", "item": owner.public(found)})
                        return self.reply(403, {"error": "forbidden"})
                    return self.reply(200, {"item": owner.public(found)})
                return self.reply(404, {"error": "unregistered endpoint"})

            def reply(self, status, value):
                body = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @staticmethod
    def public(obj):
        return {key: obj[key] for key in ("target_id", "source_id", "text")}

    def __enter__(self):
        self.thread.start()
        host, port = self.server.server_address
        self.adapter = HTTPAdapter(f"http://{host}:{port}", self.credentials, self.case["actors"],
                                   self.controls, backend_kind="reference_backend", negative_contract=True,
                                   expected_target_actor_ids=self.case["actor_mapping"])
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class HTTPAdapter:
    """An explicit /whoami, /objects/{id}, paginated /objects JSON contract.

    Other product endpoints require a separately reviewed adapter. A successful
    response alone does not certify this contract or native product capability.
    """

    def __init__(self, base_url, credentials, actors, controls, *, backend_kind,
                 negative_contract=False, timeout=5, max_pages=100, expected_target_actor_ids=None):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("base_url requires HTTP(S) and no embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url cannot contain query or fragment")
        if backend_kind not in {"reference_backend", "native", "external_gated"}:
            raise ValueError("explicit backend_kind is required")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("remote credentials require HTTPS")
        self.base_url, self.url = base_url.rstrip("/"), parsed
        self.credentials, self.actors, self.controls = credentials, {a["actor_id"]: a for a in actors}, controls
        self.expected_target_actor_ids = expected_target_actor_ids or {a["actor_id"]: a["actor_id"] for a in actors}
        self.backend_kind, self.negative_contract = backend_kind, negative_contract
        self.timeout, self.max_pages = timeout, max_pages

    def _request(self, actor_id, path):
        credential = self.credentials.get(actor_id)
        cls = http.client.HTTPSConnection if self.url.scheme == "https" else http.client.HTTPConnection
        connection = cls(self.url.hostname, self.url.port, timeout=self.timeout)
        try:
            headers = {"Authorization": f"Bearer {credential}"} if credential else {}
            connection.request("GET", self.url.path.rstrip("/") + path, headers=headers)
            response = connection.getresponse()
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                return {"status": response.status, "raw_body": "", "execution_error": "response_too_large", "response_checked": False}
            body = raw.decode("utf-8", errors="replace")
            for secret in self.credentials.values():
                if secret:
                    body = body.replace(secret, "[REDACTED_CREDENTIAL]")
            return {"status": response.status, "raw_body": body, "execution_error": None, "response_checked": True}
        except (OSError, http.client.HTTPException) as exc:
            return {"status": None, "raw_body": "", "execution_error": type(exc).__name__, "response_checked": False}
        finally:
            connection.close()

    @staticmethod
    def parse(response):
        try:
            return json.loads(response["raw_body"])
        except (ValueError, TypeError):
            return None

    def identity(self, actor_id):
        response = self._request(actor_id, "/whoami")
        value = self.parse(response)
        expected = self.actors.get(actor_id)
        if expected is not None:
            expected = dict(expected, actor_id=self.expected_target_actor_ids.get(actor_id))
        valid = response["status"] == 200 and isinstance(value, dict) and expected is not None and all(value.get(k) == expected[k] for k in ("actor_id", "user_id", "agent_id"))
        return valid, response

    def read(self, actor_id, target_id):
        return self._request(actor_id, "/objects/" + quote(target_id, safe=""))

    def list_pages(self, actor_id):
        observations, seen, offset = [], set(), 0
        for _ in range(self.max_pages):
            response = self._request(actor_id, "/objects?offset=" + str(offset))
            observations.append(response)
            value = self.parse(response)
            if response["status"] != 200 or not isinstance(value, dict) or not isinstance(value.get("items"), list):
                return observations, False
            if value.get("complete") is True and value.get("next_offset") is None:
                return observations, True
            next_offset = value.get("next_offset")
            if type(next_offset) is not int or next_offset <= offset or next_offset in seen:
                return observations, False
            seen.add(next_offset)
            offset = next_offset
        return observations, False
