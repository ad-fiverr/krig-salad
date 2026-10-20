"""Local-only G5 control plane; real Salad mutation capabilities default OFF."""

from .config import G5Config, load_config

__all__ = ["G5Config", "G5ControlPlaneService", "load_config"]


def __getattr__(name: str):
    """Load the heavyweight local service only when a caller requests it."""
    if name == "G5ControlPlaneService":
        from .service import G5ControlPlaneService

        return G5ControlPlaneService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
