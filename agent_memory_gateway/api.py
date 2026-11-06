"""Authenticated local HTTP API for Agent Memory Gateway."""

from __future__ import annotations

import secrets
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from experiments.persistent_exchange_v1 import store

from .service import GatewayService


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceCreate(RequestModel):
    source_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=100_000)
    version: int = Field(default=1, gt=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryCreate(RequestModel):
    memory_id: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=100_000)
    source_ids: list[str] = Field(default_factory=list, max_length=256)
    parent_memory_ids: list[str] = Field(default_factory=list, max_length=256)
    version: int = Field(default=1, gt=0)
    provenance: dict[str, Any] = Field(default_factory=dict)
    kind: Literal["raw", "derived"] = "derived"


class PermissionUpdate(RequestModel):
    allowed_source_ids: list[str] = Field(default_factory=list, max_length=4096)


class TransferPrepare(RequestModel):
    sender_id: str = Field(min_length=1, max_length=64)
    recipient_id: str = Field(min_length=1, max_length=64)
    memory_refs: list[str] = Field(min_length=1, max_length=256)
    batch_id: str | None = Field(default=None, max_length=128)


def _call(operation):
    try:
        return operation()
    except store.StoreError as exc:
        raise HTTPException(
            status_code=409, detail={"code": str(exc)}
        ) from None
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail={"code": "not_found"}
        ) from None
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422, detail={"code": "invalid_request"}
        ) from None
    except OSError:
        raise HTTPException(
            status_code=503, detail={"code": "local_storage_unavailable"}
        ) from None


def create_app(data_dir: str, token: str) -> FastAPI:
    """Create an app with an explicit bearer token; there is no default token."""
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("gateway_token_must_contain_at_least_32_characters")

    gateway = GatewayService(data_dir)
    app = FastAPI(
        title="Agent Memory Gateway",
        version="0.1.0",
        description=(
            "Single-host trusted gateway for permission-checked persistent "
            "memory delivery between heterogeneous agents."
        ),
    )
    app.state.gateway = gateway

    def require_token(authorization: str | None = Header(default=None)):
        if not isinstance(authorization, str):
            raise HTTPException(status_code=401, detail={"code": "bearer_token_required"})
        scheme, separator, supplied = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not secrets.compare_digest(supplied, token)
        ):
            raise HTTPException(status_code=401, detail={"code": "invalid_bearer_token"})

    router = APIRouter(
        prefix="/v1",
        dependencies=[Depends(require_token)],
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "agent-memory-gateway", "version": "0.1.0"}

    @router.post("/agents/{agent_id}/sources", status_code=201)
    def register_source(agent_id: str, body: SourceCreate):
        return _call(
            lambda: gateway.register_source(
                agent_id, body.source_id, body.text, body.version, body.metadata
            )
        )

    @router.post("/agents/{agent_id}/memories", status_code=201)
    def create_memory(agent_id: str, body: MemoryCreate):
        return _call(
            lambda: gateway.create_memory(
                agent_id,
                body.memory_id,
                body.content,
                body.source_ids,
                body.parent_memory_ids,
                body.version,
                body.provenance,
                body.kind,
            )
        )

    @router.get("/recipients/{recipient_id}/permissions")
    def get_permissions(recipient_id: str):
        return _call(lambda: gateway.get_permissions(recipient_id))

    @router.put("/recipients/{recipient_id}/permissions")
    def set_permissions(recipient_id: str, body: PermissionUpdate):
        return _call(
            lambda: gateway.set_permissions(recipient_id, body.allowed_source_ids)
        )

    @router.post("/transfers", status_code=201)
    def prepare_transfer(body: TransferPrepare):
        return _call(
            lambda: gateway.prepare_transfer(
                body.sender_id,
                body.recipient_id,
                body.memory_refs,
                body.batch_id,
            )
        )

    @router.get("/transfers/{transfer_id}")
    def get_transfer(transfer_id: str):
        return _call(lambda: gateway.get_transfer(transfer_id))

    @router.post("/transfers/{transfer_id}/commit")
    def commit_transfer(transfer_id: str):
        return _call(lambda: gateway.commit_transfer(transfer_id))

    @router.delete("/transfers/{transfer_id}")
    def discard_transfer(transfer_id: str):
        return _call(lambda: gateway.discard_transfer(transfer_id))

    @router.get("/agents/{agent_id}/batches/{batch_id}")
    def retrieve_batch(agent_id: str, batch_id: str):
        return _call(lambda: gateway.retrieve_batch(agent_id, batch_id))

    @router.get("/agents/{agent_id}/audit")
    def audit(agent_id: str, limit: int = Query(default=100, ge=1, le=500)):
        return _call(lambda: gateway.audit(agent_id, limit))

    app.include_router(router)
    return app
