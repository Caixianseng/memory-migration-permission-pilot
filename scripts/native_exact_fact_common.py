"""New harness helpers; no production package changes or automatic execution."""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import traceback


def isolate_environment(state):
    keep = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE",
            "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"}
    for key in list(os.environ):
        if key.upper() not in keep:
            os.environ.pop(key, None)
    os.environ.update({"MEM0_TELEMETRY": "false", "ANONYMIZED_TELEMETRY": "false", "DO_NOT_TRACK": "1",
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
        "PYTHON_DOTENV_DISABLED": "1", "PYTHONDONTWRITEBYTECODE": "1", "POSTHOG_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true", "MEM0_DIR": str(Path(state)/"mem0_internal"),
        "TOKENIZERS_PARALLELISM": "false", "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2"})
    sys.dont_write_bytecode = True


def is_loopback(host):
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return str(host).lower() == "localhost"


class NetworkGuard:
    """Only the source worker's ephemeral loopback gateway may be contacted.

    IPv6/IPv4 loopback binds on port zero are observed, including urllib3's
    documented IPv6 capability probe. All external DNS/connect/sendto and the
    deliberately dead LLM endpoint are rejected. This is a local test guard,
    not process isolation against malicious native extensions.
    """
    def __init__(self):
        self.allowed_ports, self.events = set(), []
        self._socketpair_code = getattr(socket.socketpair, "__code__", None)

    def _stdlib_socketpair_frame(self):
        frame = sys._getframe(1)
        while frame is not None:
            if self._socketpair_code is not None and frame.f_code is self._socketpair_code:
                return True
            frame = frame.f_back
        return False

    def _stack(self):
        result = []
        frame = sys._getframe(1)
        while frame is not None and len(result) < 12:
            result.append({"file": frame.f_code.co_filename, "line": frame.f_lineno, "function": frame.f_code.co_name})
            frame = frame.f_back
        return result

    def __call__(self, event, args):
        if event == "socket.getaddrinfo":
            allowed = is_loopback(args[0])
            if not allowed:
                self.events.append({"event": event, "allowed": False, "host": str(args[0]), "stack": self._stack()})
                raise PermissionError("external_dns_blocked")
        elif event in {"socket.connect", "socket.bind", "socket.sendto"}:
            address = args[1] if event != "socket.sendto" else args[-1]
            if not isinstance(address, tuple) or len(address) < 2:
                self.events.append({"event": event, "allowed": False, "address_kind": type(address).__name__, "stack": self._stack()})
                raise PermissionError("non_loopback_network_blocked")
            host, port = address[:2]
            socketpair = event == "socket.connect" and port not in {9, 11435} and self._stdlib_socketpair_frame()
            allowed = is_loopback(host) and ((event == "socket.bind" and port == 0)
                or (event == "socket.connect" and (port in self.allowed_ports or socketpair)))
            observation = {"event": event, "allowed": allowed, "address": [str(host), port],
                "kind": "stdlib_socketpair_internal" if socketpair else "declared_loopback_or_probe"}
            if not allowed:
                observation["stack"] = self._stack()
            self.events.append(observation)
            if not allowed:
                raise PermissionError("unapproved_network_blocked")
        elif event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0]))
            if path.name.lower() in {".env", "credentials", "token", "tokens.json", "auth.json", ".webui_secret_key"}:
                self.events.append({"event": "credential_file_access", "allowed": False, "name": path.name})
                raise PermissionError("credential_file_access_blocked")


def serve_commands(handler):
    protocol = sys.stdout
    sys.stdout = sys.stderr  # Third-party diagnostics are never protocol or persisted credential logs.
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if not isinstance(request, dict) or set(request) != {"id", "command", "data"}:
                    raise ValueError("invalid_rpc_schema")
                result = handler(request["command"], request["data"])
                response = {"id": request["id"], "ok": True, "result": result}
            except Exception as error:
                response = {"id": request.get("id") if isinstance(locals().get("request"), dict) else None,
                    "ok": False, "error": {"type": type(error).__name__, "code": "native_worker_operation_failed",
                        "stage": getattr(handler, "stage", "unknown"),
                        "stack": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)[-5:]]}}
            protocol.write(json.dumps(response, ensure_ascii=False, allow_nan=False)+"\n")
            protocol.flush()
            if isinstance(locals().get("request"), dict) and request.get("command") == "close":
                break
    finally:
        handler.close()
