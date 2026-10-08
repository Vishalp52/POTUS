"""Finite, scale-stable cosine similarity for signed deviation vectors."""
import numpy as np

def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    a, b = np.asarray(v1, dtype=float), np.asarray(v2, dtype=float)
    if a.ndim != 1 or b.ndim != 1 or not len(a) or a.shape != b.shape:
        raise ValueError("signatures must be nonempty one-dimensional vectors of equal length")
    if not np.isfinite(a).all() or not np.isfinite(b).all():
        raise ValueError("signatures must contain only finite values")
    # Scaling before the norm prevents overflow for large finite inputs.
    scale_a, scale_b = np.max(np.abs(a)), np.max(np.abs(b))
    if scale_a == 0 or scale_b == 0:
        return 0.0
    a, b = a / scale_a, b / scale_b
    return float(np.clip(np.dot(a / np.linalg.norm(a), b / np.linalg.norm(b)), -1, 1))
