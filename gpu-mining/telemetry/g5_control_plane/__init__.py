"""Local-only G5 control plane; real Salad mutation capabilities default OFF."""

from .config import G5Config, load_config
from .service import G5ControlPlaneService

__all__ = ["G5Config", "G5ControlPlaneService", "load_config"]
