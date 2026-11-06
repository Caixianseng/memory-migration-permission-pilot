"""Local, model-agnostic Agent Memory Gateway."""

from .api import create_app
from .service import GatewayService

__all__ = ["create_app", "GatewayService"]
