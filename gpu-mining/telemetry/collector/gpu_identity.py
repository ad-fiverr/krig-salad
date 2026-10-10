"""Exact GPU identity normalization for fail-closed physical floors."""

from __future__ import annotations

import re
from typing import Any


VERIFIED_GPU_IDENTITY_SOURCES = frozenset({
    "salad_json_log_gpu_class_name",
    "synthetic_test_fixture",
})

SUPPORTED_EXACT_MODELS = frozenset({"RTX 5090", "RTX 5080", "RTX 4090", "RTX 3090"})


def normalize_gpu_identity(
    raw_model: Any,
    *,
    identity_source: Any,
    identity_verified: Any = False,
    reported_form_factor: Any = None,
) -> dict[str, Any]:
    """Normalize a single exact model claim without inferring Desktop from omission.

    A source is considered eligible only when the caller marks it verified and the
    source is an explicitly supported identity source. Form factor must be present
    in the source label or as an explicit, non-conflicting source field.
    """
    raw = raw_model.strip() if isinstance(raw_model, str) else ""
    source = identity_source.strip() if isinstance(identity_source, str) else ""
    text = re.sub(r"\s+", " ", raw.casefold()).strip()

    laptop = bool(re.search(r"\b(laptop|mobile)\b", text))
    desktop = bool(re.search(r"\bdesktop\b", text))
    variant = "unknown"
    variant_conflict = laptop and desktop
    if laptop and not desktop:
        variant = "laptop"
    elif desktop and not laptop:
        variant = "desktop"

    explicit_variant = reported_form_factor.strip().casefold() if isinstance(reported_form_factor, str) else ""
    if explicit_variant in {"laptop", "desktop"}:
        if variant not in {"unknown", explicit_variant}:
            variant_conflict = True
        elif variant == "unknown":
            variant = explicit_variant

    # Only remove known non-model qualifiers. Unknown suffixes remain and cause
    # an exact-model miss instead of inheriting a neighboring model's floor.
    candidate = re.sub(r"\(\s*\d+\s*gb\s*\)", " ", text)
    candidate = re.sub(r"\b(nvidia|geforce|gpu|laptop|mobile|desktop)\b", " ", candidate)
    candidate = re.sub(r"\s+", " ", candidate).strip(" -_")
    candidate = re.sub(r"\brtx[- ]+(\d{4})\b", r"rtx \1", candidate)
    canonical = next(
        (model for model in sorted(SUPPORTED_EXACT_MODELS) if candidate == model.casefold()),
        None,
    )

    source_verified = (
        identity_verified is True
        and source in VERIFIED_GPU_IDENTITY_SOURCES
        and canonical is not None
        and variant in {"laptop", "desktop"}
        and not variant_conflict
    )
    if not raw:
        status = "missing_model"
    elif canonical is None:
        status = "model_not_exactly_recognized"
    elif variant_conflict:
        status = "conflicting_form_factor"
    elif variant == "unknown":
        status = "form_factor_unverified"
    elif source not in VERIFIED_GPU_IDENTITY_SOURCES or identity_verified is not True:
        status = "identity_source_unverified"
    else:
        status = "verified_exact_model_variant"

    return {
        "raw_model": raw or None,
        "model": canonical,
        "form_factor": variant,
        "identity_source": source or None,
        "identity_verified": source_verified,
        "identity_status": status,
    }
