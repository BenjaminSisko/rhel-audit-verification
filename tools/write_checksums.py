#!/usr/bin/env python3
"""Generate hashes for the retained installable app releases."""
import hashlib
from pathlib import Path
dist = Path(__file__).resolve().parents[1] / "dist"
(dist / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(dist.glob("*.spl"))))
