from datetime import UTC, datetime
from typing import Any

from libtea.server import tea_datetime_serializer


def _serialize_value(v: Any) -> Any:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=UTC)
        return tea_datetime_serializer(v)
    if isinstance(v, dict):
        return serialize_tea(v)
    if isinstance(v, (list, tuple)):
        return [_serialize_value(item) for item in v]
    return v


def serialize_tea(data: dict[str, Any]) -> dict[str, Any]:
    return {k: _serialize_value(v) for k, v in data.items()}


def tea_dump(model: Any) -> dict[str, Any]:
    return serialize_tea(model.model_dump(by_alias=True))
