"""CloudWatch metrics via the Embedded Metric Format (EMF).

EMF means a specially-shaped JSON log line becomes a CloudWatch metric automatically. That
avoids both a sidecar agent and a synchronous ``PutMetricData`` call on the request path — an
API call that could add latency to, or fail, a token issuance. On a laptop the same lines are
just structured logs, so behaviour is identical everywhere.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Literal

Unit = Literal["Count", "Milliseconds", "Seconds", "None"]

METRIC_NAMESPACE = "AuthForge"


class MetricsEmitter:
    def __init__(self, *, namespace: str = METRIC_NAMESPACE, environment: str = "local") -> None:
        self._namespace = namespace
        self._environment = environment
        self._enabled = True

    def disable(self) -> None:
        """Used by tests to keep EMF lines out of captured output."""
        self._enabled = False

    def emit(
        self,
        *,
        name: str,
        value: float = 1.0,
        unit: Unit = "Count",
        dimensions: dict[str, str] | None = None,
    ) -> None:
        if not self._enabled:
            return
        dims = {"Environment": self._environment}
        if dimensions:
            # Dimension values must be non-empty strings; CloudWatch silently drops the whole
            # metric otherwise, which is a confusing way to lose observability.
            dims.update({k: str(v) for k, v in dimensions.items() if v})
        document = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": self._namespace,
                        "Dimensions": [list(dims.keys())],
                        "Metrics": [{"Name": name, "Unit": unit}],
                    }
                ],
            },
            **dims,
            name: value,
        }
        sys.stdout.write(json.dumps(document, separators=(",", ":")) + "\n")

    def count(self, name: str, dimensions: dict[str, str] | None = None) -> None:
        self.emit(name=name, value=1.0, unit="Count", dimensions=dimensions)

    def duration_ms(
        self, name: str, milliseconds: float, dimensions: dict[str, str] | None = None
    ) -> None:
        self.emit(name=name, value=milliseconds, unit="Milliseconds", dimensions=dimensions)


_emitter: MetricsEmitter | None = None


def configure_metrics(*, environment: str) -> MetricsEmitter:
    global _emitter
    _emitter = MetricsEmitter(environment=environment)
    return _emitter


def get_metrics() -> MetricsEmitter:
    global _emitter
    if _emitter is None:
        _emitter = MetricsEmitter()
    return _emitter
