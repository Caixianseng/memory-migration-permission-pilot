"""Cognee 1.6.5 offline preserve-import / real-auth read probe.

Reviewed local execution probe pinned to the official 1.6.5 wheel.
Input files must be actual Mem0 get_all exports; the script does not pretend
that reading these files proves source authentication. Record source access
tests separately. Run only inside a dedicated venv and a NEW state directory.

The trusted migration process writes through the official SDK with a real User.
Independent users then read through the official ASGI routes using login JWTs.
No ACL, storage, authentication or import function is mocked.
Connection probes are disabled by Cognee's documented process-wide switch.
External socket connections are blocked; no paid inference or semantic search.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import sys
import re
from datetime import datetime, timezone


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unwrap_mem0(path: Path) -> list[dict]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(value, dict):
        value = next(
            (value[key] for key in ("results", "memories", "items")
             if isinstance(value.get(key), list) and value[key]), []
        )
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise ValueError("Expected an official Mem0 list/get_all JSON shape")
    if not value:
        raise ValueError("Empty export cannot establish import/read qualification")
    return value


def source_content(row):
    return next((row[k] for k in ('memory','text','data','content') if isinstance(row.get(k),str) and row[k]), None)


def content_observed_in_response(response, source_rows):
    text = response.content.decode('utf-8', errors='replace')
    try:
        text += '\n' + json.dumps(response.json(), ensure_ascii=False)
    except (ValueError, UnicodeDecodeError):
        pass
    markers = []
    for row in source_rows:
        content = source_content(row)
        if content:
            markers.append(content)
            markers.extend(re.findall(r'QUALIFICATION-[A-Z]+-[a-f0-9]+', content))
    return any(marker in text for marker in markers)


def configure_isolated_cognee(state, openssl_dll_dir=None):
    """Apply the reviewed offline settings before importing Cognee.

    Caller creates a NEW state root. Keep the returned DLL handle alive.
    """
    settings = {
        "ENABLE_BACKEND_ACCESS_CONTROL": "true",
        "REQUIRE_AUTHENTICATION": "true",
        "DATA_ROOT_DIRECTORY": str(state / "data"),
        "SYSTEM_ROOT_DIRECTORY": str(state / "system"),
        "CACHE_ROOT_DIRECTORY": str(state / "cache"),
        "COGNEE_LOGS_DIR": str(state / "logs"),
        "COGNEE_REPOS_DIR": str(state / "repos"),
        "DB_PROVIDER": "sqlite",
        "DB_PATH": str(state / "db"),
        "DB_NAME": "cognee_db",
        "GRAPH_DATABASE_PROVIDER": "ladybug",
        "GRAPH_DATABASE_SUBPROCESS_ENABLED": "false",
        "KUZU_NUM_THREADS": "2",
        "KUZU_BUFFER_POOL_SIZE": "67108864",
        "VECTOR_DB_PROVIDER": "lancedb",
        "TELEMETRY_DISABLED": "1",
        "COGNEE_TRACING_ENABLED": "false",
        "COGNEE_SKIP_CONNECTION_TEST": "true",
        "PYTHON_DOTENV_DISABLED": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LLM_API_KEY": "",
        "EMBEDDING_API_KEY": "",
    }
    for key in list(os.environ):
        if key.endswith('_API_KEY') or key in {'ANTHROPIC_AUTH_TOKEN','OPENAI_AUTH_TOKEN'}:
            os.environ.pop(key, None)
    os.environ.update(settings)
    native_dll_handle = None
    if openssl_dll_dir is not None:
        dll_dir = openssl_dll_dir.resolve()
        if not all((dll_dir / name).is_file() for name in ('libssl-3-x64.dll', 'libcrypto-3-x64.dll')):
            raise RuntimeError('Requested directory does not contain both existing OpenSSL 3 DLLs')
        native_dll_handle = os.add_dll_directory(str(dll_dir))
    for directory in ("data", "system", "cache", "logs", "repos", "db"):
        (state / directory).mkdir()

    egress_attempts: list[dict] = []

    def audit(event, event_args):
        if event != "socket.connect":
            return
        address = event_args[1]
        # Windows asyncio uses a loopback socketpair. No remote host is allowed.
        if isinstance(address, tuple) and address:
            host = str(address[0]).lower()
            if host not in ("127.0.0.1", "::1", "localhost"):
                egress_attempts.append({"host": host, "port": address[1]})
                raise PermissionError("Remote networking disabled for this offline probe")

    sys.addaudithook(audit)
    return settings, native_dll_handle, egress_attempts


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alice-export", type=Path, required=True)
    parser.add_argument("--bob-export", type=Path, required=True)
    parser.add_argument("--letta-export", type=Path)
    parser.add_argument("--state", type=Path, required=True,
                        help="New isolated directory; use an ASCII system-temp path on Windows")
    parser.add_argument("--openssl-dll-dir", type=Path,
                        help="Existing OpenSSL 3 DLL directory for older Windows CPython builds")
    args = parser.parse_args()
    if importlib.metadata.version("cognee") != "1.6.5":
        raise RuntimeError("This probe was reviewed only against Cognee 1.6.5")
    state = args.state.resolve()
    if state.exists():
        raise RuntimeError("State directory already exists; use a new directory")
    exports = {"alice": args.alice_export.resolve(), "bob": args.bob_export.resolve()}
    records = {name: unwrap_mem0(path) for name, path in exports.items()}
    state.mkdir(parents=True)

    settings, native_dll_handle, egress_attempts = configure_isolated_cognee(state, args.openssl_dll_dir)
    result = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "cognee_version": "1.6.5",
        "kind": "official_import_path_qualification_not_model_experiment",
        "source_authentication_proven_by_this_script": False,
        "importer": "trusted in-process migration code acting as registered target user",
        "reads": "official HTTP ASGI routes with independently issued login JWTs",
        "semantic_retrieval_tested": False,
        "native_openssl_directory": str(args.openssl_dll_dir) if args.openssl_dll_dir else None,
        "graph_worker_mode": "in_process_supported_configuration",
        "settings": {key: value for key, value in settings.items()
                     if not key.endswith("API_KEY")},
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path.read_bytes()),
                   "record_count": len(records[name])}
            for name, path in exports.items()
        },
        "requests": [], "identities": {}, "imports": {}, "checks": [], "target_data_inventory": {},
        "egress_attempts": egress_attempts,
    }

    def record_request(response, label):
        result["requests"].append({
            "label": label, "method": response.request.method,
            "path": response.request.url.path,
            "status_code": response.status_code,
            "cookie_present": 'cookie' in response.request.headers,
            "authorization_present": 'authorization' in response.request.headers,
            # Auth tokens and credentials are never included or hashed.
            **({"body_sha256": sha256(response.content)}
               if "/auth/" not in response.request.url.path else {}),
        })
        return response

    def check(label, condition, **details):
        result["checks"].append({"label": label, "passed": bool(condition), **details})

    try:
        import cognee
        from cognee.api.client import app
        from cognee.migration import LettaSource, Mem0Source
        from cognee.modules.users.methods import get_user_by_email
        from fastapi.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as client:
            headers = {}
            dataset_ids = {}
            dataset_names = {}
            emails = {}
            for name in ("alice", "bob", "carol"):
                emails[name] = f"migration-{name}-{secrets.token_hex(5)}@example.com"
                password = "Research-" + secrets.token_urlsafe(24)
                response = record_request(client.post(
                    "/api/v1/auth/register",
                    json={"email": emails[name], "password": password}), f"register_{name}")
                if response.status_code != 201:
                    raise RuntimeError(f"Registration failed for {name}: HTTP {response.status_code}")
                response = record_request(client.post(
                    "/api/v1/auth/login", data={"username": emails[name], "password": password}),
                    f"login_{name}")
                if response.status_code != 200:
                    raise RuntimeError(f"Login failed for {name}: HTTP {response.status_code}")
                headers[name] = {"Authorization": "Bearer " + response.json()["access_token"]}
                # Login may set a browser cookie. Every test below must use its
                # own explicit bearer and no shared cookie jar.
                client.cookies.clear()
                me = record_request(client.get("/api/v1/users/me", headers=headers[name]),
                                    f"identity_{name}")
                if me.status_code != 200:
                    raise RuntimeError(f"Identity read failed for {name}")
                identity = me.json()
                result["identities"][name] = {
                    "id": identity["id"], "email_matches": identity["email"] == emails[name],
                    "is_superuser": identity.get("is_superuser", identity.get("isSuperuser")),
                }
                check(f"registered_regular_identity_{name}",
                      result["identities"][name]["email_matches"] and
                      result["identities"][name]["is_superuser"] is False)
                dataset_names[name] = f"migration_{name}_{secrets.token_hex(5)}"
                ds = record_request(client.post(
                    "/api/v1/datasets", json={"name": dataset_names[name]},
                    headers=headers[name]), f"create_dataset_{name}")
                if ds.status_code != 200:
                    raise RuntimeError(f"Dataset create failed for {name}: HTTP {ds.status_code}")
                dataset_ids[name] = ds.json()["id"]

            check("ordinary_authenticated_users", all(v["is_superuser"] is False and v["email_matches"] for v in result["identities"].values()))
            check("independent_real_identities",
                  len({v['id'] for v in result['identities'].values()}) == len(result['identities']))

            async def import_one(name):
                user = await get_user_by_email(emails[name])
                if user is None or str(user.id) != result["identities"][name]["id"]:
                    raise RuntimeError("Registered identity mismatch at trusted import boundary")
                value = await cognee.remember(
                    Mem0Source(str(exports[name]), mode="preserve"),
                    dataset_name=dataset_names[name], user=user, run_in_background=False,
                    index_vectors=False,
                )
                return {"status": value.status, "items_processed": value.items_processed,
                        "items": value.items, "error": value.error}

            for name in ("alice", "bob"):
                result["imports"][name] = client.portal.call(import_one, name)
                check(f"import_{name}_completed", result["imports"][name]["status"] == "completed")

            for owner in ("alice", "bob"):
                ds_id = dataset_ids[owner]
                listing = record_request(client.get(
                    f"/api/v1/datasets/{ds_id}/data", headers=headers[owner]), f"owner_list_{owner}")
                if listing.status_code != 200:
                    raise RuntimeError(f"Owner listing failed: {owner} HTTP {listing.status_code}")
                rows = listing.json()
                result['target_data_inventory'][owner] = rows
                check(f"owner_record_count_{owner}", len(rows) == len(records[owner]),
                      actual=len(rows), expected=len(records[owner]))
                owner_contents = []
                for viewer in ("alice", "bob"):
                    if viewer != owner:
                        denied_listing = record_request(client.get(
                            f"/api/v1/datasets/{ds_id}/data", headers=headers[viewer]),
                            f"cross_list_{viewer}_to_{owner}")
                        check(f"cross_list_no_source_content_{viewer}_to_{owner}", not content_observed_in_response(denied_listing, records[owner]))
                        check(f"cross_list_blocked_{viewer}_to_{owner}",
                              denied_listing.status_code in (401, 403, 404) or
                              (denied_listing.status_code == 200 and denied_listing.json() == []))
                    for row in rows:
                        data_id = row["id"]
                        raw = record_request(client.get(
                            f"/api/v1/datasets/{ds_id}/data/{data_id}/raw", headers=headers[viewer]),
                            f"raw_{viewer}_to_{owner}_{data_id}")
                        if viewer == owner:
                            if raw.status_code == 200:
                                owner_contents.append(raw.content.decode("utf-8", errors="replace"))
                            check(f"owner_raw_read_{owner}_{data_id}",
                                  raw.status_code == 200 and bool(raw.content),
                                  byte_count=len(raw.content))
                            other = 'bob' if owner == 'alice' else 'alice'
                            check(f'owner_no_other_user_content_{owner}_{data_id}',not content_observed_in_response(raw,records[other]))
                        else:
                            check(f"cross_raw_no_source_content_{viewer}_to_{owner}_{data_id}", not content_observed_in_response(raw, records[owner]))
                            check(f"cross_raw_blocked_{viewer}_to_{owner}_{data_id}",
                                  raw.status_code in (401, 403, 404))
                for index, source_row in enumerate(records[owner]):
                    content = source_content(source_row)
                    check(f"source_content_present_{owner}_{index}",
                          bool(content) and any(content in text for text in owner_contents))

            if args.letta_export:
                af_raw = args.letta_export.read_bytes()
                af = json.loads(af_raw)
                canaries = sorted(set(re.findall(r'QUALIFICATION-AF-[a-f0-9]+', af_raw.decode('utf-8'))))
                if len(canaries) != 1:
                    raise RuntimeError('Letta fixture must contain exactly one known qualification canary')
                source_rows = [{'memory':canaries[0]}]
                ds_name = 'letta_org_' + secrets.token_hex(6)
                created = record_request(client.post('/api/v1/datasets', json={'name':ds_name}, headers=headers['alice']), 'create_letta_dataset')
                if created.status_code != 200:
                    raise RuntimeError('Letta destination dataset creation failed')
                dataset_id = created.json()['id']
                async def import_letta():
                    owner = await get_user_by_email(emails['alice'])
                    value = await cognee.remember(LettaSource(args.letta_export,mode='preserve'), dataset_name=ds_name,
                        user=owner,run_in_background=False,index_vectors=False)
                    return {'status':value.status,'items_processed':value.items_processed,'items':value.items,'error':value.error}
                result['imports']['letta'] = client.portal.call(import_letta)
                check('letta_import_completed',result['imports']['letta']['status']=='completed')
                grant = record_request(client.post(f"/api/v1/permissions/datasets/{result['identities']['bob']['id']}",
                    params={'permission_name':'read'},json=[dataset_id],headers=headers['alice']), 'grant_letta_org_read_to_bob')
                check('native_share_grant_succeeded',grant.status_code==200)
                owner_list = record_request(client.get(f'/api/v1/datasets/{dataset_id}/data',headers=headers['alice']), 'letta_owner_list')
                if owner_list.status_code != 200 or not isinstance(owner_list.json(),list) or not owner_list.json():
                    raise RuntimeError('Letta import has no readable target data')
                target_rows=owner_list.json()
                result['letta_path']={'path_class':'vendor_migration_guide_and_adapter', 'source':'Letta OSS 0.16.8 .af',
                    'target':'Cognee 1.6.5', 'source_sha256':sha256(af_raw), 'source_path':str(args.letta_export.resolve()),
                    'source_policy':'native organization group read by Alice and Bob; Carol excluded',
                    'mapping':'trusted importer explicitly creates Alice dataset and uses vendor-authorized share API to grant Bob read',
                    'automatic_acl_translation_claimed':False,'dataset_id':dataset_id,'matrix':{}}
                for viewer in ('alice','bob','carol'):
                    listing = record_request(client.get(f'/api/v1/datasets/{dataset_id}/data',headers=headers[viewer]),'letta_list_'+viewer)
                    observations=[]
                    for row in target_rows:
                        raw=record_request(client.get(f'/api/v1/datasets/{dataset_id}/data/{row["id"]}/raw',headers=headers[viewer]),'letta_raw_'+viewer+'_'+row['id'])
                        observations.append({'http':raw.status_code,'canary_observed':content_observed_in_response(raw,source_rows)})
                    found=any(o['canary_observed'] for o in observations)
                    result['letta_path']['matrix'][viewer]={'listing_http':listing.status_code,'reads':observations,'canary_observed':found}
                    if viewer in ('alice','bob'):
                        check('letta_authorized_content_'+viewer,listing.status_code==200 and found and all(o['http']==200 for o in observations))
                    else:
                        check('letta_unauthorized_no_content',not found and not content_observed_in_response(listing,source_rows))
                        check('letta_unauthorized_denied',listing.status_code in (401,403,404) and all(o['http'] in (401,403,404) for o in observations))

            client.cookies.clear()
            unauth = record_request(client.get("/api/v1/datasets"), "unauthenticated_list")
            check("unauthenticated_request_rejected", unauth.status_code in (401, 403))
            check('bearer_read_checks_have_no_cookies',all(not r['cookie_present'] and r['authorization_present']
                for r in result['requests'] if '/auth/' not in r['path'] and r['label']!='unauthenticated_list'))
            check('anonymous_check_has_no_implicit_credentials',not result['requests'][-1]['cookie_present'] and not result['requests'][-1]['authorization_present'])
            check("no_external_connection_attempts", not egress_attempts)
        result["status"] = "passed" if all(c["passed"] for c in result["checks"]) else "failed"
    except Exception as exc:
        result["status"] = "execution_error"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        # Keep execution failures in output; they are not an access denial result.
    finally:
        output = state / "probe_result.json"
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(json.dumps({"status": result["status"], "result_file": str(output)}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(run())
