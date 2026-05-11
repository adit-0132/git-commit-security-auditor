from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..models import Report


def write_json_report(report: Report, output_path: Path) -> None:
    """Serialize a Report to a JSON file with ISO 8601 timestamps."""
    data = report.model_dump(mode="json")
    output_path.write_text(
        json.dumps(data, indent=2, default=_json_default), encoding="utf-8"
    )


def _json_default(obj: object) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
