"""
Rolling battery sample buffer and drain / risk calculations for the system monitor.

Estimates **percent charge lost per hour** from samples in a ~1-hour window and maps
that rate to ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL`` using configurable thresholds.

The OS does not provide true per-process battery draw; the hourly rate is derived from
percentage samples taken while discharging when possible.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List

from config import (
    BATTERY_DRAIN_RISK_HIGH_MAX_PCT_PER_H,
    BATTERY_DRAIN_RISK_LOW_MAX_PCT_PER_H,
    BATTERY_DRAIN_RISK_MEDIUM_MAX_PCT_PER_H,
    BATTERY_FAST_DRAIN_RATE_PCT_PER_H,
    BATTERY_FAST_DRAIN_SHORT_DROP_PCT,
    BATTERY_FAST_DRAIN_SHORT_WINDOW_MIN,
)

WINDOW_SEC = 3600.0


@dataclass
class _Sample:
    """Single battery reading at a point in time."""

    ts: float
    percent: float
    charging: bool


def drain_risk_level_from_rate(rate_per_hour: float) -> str:
    """
    Map estimated battery drain (percentage points per hour) to a risk label.

    Bands (from ``config`` defaults):
        - up to ``BATTERY_DRAIN_RISK_LOW_MAX_PCT_PER_H`` → LOW
        - above that up to ``BATTERY_DRAIN_RISK_MEDIUM_MAX_PCT_PER_H`` → MEDIUM
        - above that up to ``BATTERY_DRAIN_RISK_HIGH_MAX_PCT_PER_H`` → HIGH
        - above that → CRITICAL

    Negative or NaN rates are treated as LOW (no meaningful drain).
    """
    try:
        r = float(rate_per_hour)
    except (TypeError, ValueError):
        return "LOW"
    if r != r:  # NaN
        return "LOW"
    if r <= 0:
        return "LOW"
    if r <= BATTERY_DRAIN_RISK_LOW_MAX_PCT_PER_H:
        return "LOW"
    if r <= BATTERY_DRAIN_RISK_MEDIUM_MAX_PCT_PER_H:
        return "MEDIUM"
    if r <= BATTERY_DRAIN_RISK_HIGH_MAX_PCT_PER_H:
        return "HIGH"
    return "CRITICAL"


class BatteryHourlyTracker:
    """
    Maintains a deque of battery samples within ``WINDOW_SEC`` and derives metrics.

    ``add_sample`` enforces a minimum spacing between points. ``build_metrics`` computes
    consumed charge, extrapolated hourly drain rate, fast-drain flags, and ``riskLevel``
    via :func:`drain_risk_level_from_rate`.
    """

    def __init__(
        self,
        sample_interval_sec: float,
        fast_drain_rate_pct_per_h: float,
        _risk_medium_rate: float | None = None,
        _risk_high_rate: float | None = None,
        fast_drain_short_window_min: float = BATTERY_FAST_DRAIN_SHORT_WINDOW_MIN,
        fast_drain_short_drop_pct: float = BATTERY_FAST_DRAIN_SHORT_DROP_PCT,
        **legacy_kwargs: Any,
    ) -> None:
        """See class docstring. Accept legacy ``risk_*`` keyword names for compatibility."""
        # Backward compatibility for older callers passing named kwargs.
        if _risk_medium_rate is None:
            _risk_medium_rate = legacy_kwargs.pop("risk_medium_rate", None)
        if _risk_high_rate is None:
            _risk_high_rate = legacy_kwargs.pop("risk_high_rate", None)
        if _risk_medium_rate is None:
            _risk_medium_rate = BATTERY_DRAIN_RISK_MEDIUM_MAX_PCT_PER_H
        if _risk_high_rate is None:
            _risk_high_rate = BATTERY_DRAIN_RISK_HIGH_MAX_PCT_PER_H

        self._samples: deque[_Sample] = deque()
        self._last_append_mono = 0.0
        self._sample_interval = max(30.0, float(sample_interval_sec))
        self._fast_rate = float(fast_drain_rate_pct_per_h)
        self._fast_short_min = float(fast_drain_short_window_min)
        self._fast_short_drop = float(fast_drain_short_drop_pct)
        # Keep values for observability/debugging in case callers still pass these knobs.
        self._risk_medium_rate = float(_risk_medium_rate)
        self._risk_high_rate = float(_risk_high_rate)

    def add_sample(self, wall_ts: float, percent: float, charging: bool) -> None:
        """Append one battery reading if the minimum sample interval has elapsed."""
        mono = time.monotonic()
        if self._last_append_mono and (mono - self._last_append_mono) < self._sample_interval:
            return
        self._last_append_mono = mono
        self._samples.append(_Sample(float(wall_ts), float(percent), bool(charging)))
        while self._samples and self._samples[0].ts < wall_ts - WINDOW_SEC:
            self._samples.popleft()

    def build_metrics(self) -> Dict[str, Any]:
        """
        Compute rolling-window battery analytics for inclusion in telemetry payloads.

        Returns keys including ``batteryConsumedLastHour``, ``batteryDrainRatePerHour``,
        ``batteryFastDrain``, and ``riskLevel`` (from hourly rate via
        :func:`drain_risk_level_from_rate`). If fewer than two samples exist, numeric
        fields are ``None`` and ``riskLevel`` is ``UNKNOWN``.
        """
        samples: List[_Sample] = list(self._samples)
        n = len(samples)
        if n < 2:
            return {
                "batteryConsumedLastHour": None,
                "batteryDrainRatePerHour": None,
                "chargerConnected": None,
                "batteryFastDrain": False,
                "riskLevel": "UNKNOWN",
                "batteryMetricsWindowMinutes": 0.0,
                "batteryHistorySamples": n,
            }

        oldest, newest = samples[0], samples[-1]
        span_sec = max(0.0, newest.ts - oldest.ts)
        span_min = span_sec / 60.0
        span_h = span_sec / 3600.0 if span_sec > 0 else 0.0

        raw_change = oldest.percent - newest.percent
        consumed = max(0.0, raw_change)

        drain_rate = consumed / max(span_h, 1.0 / 60.0)

        if span_h >= 0.92:
            consumed_last_hour = round(consumed, 2)
        else:
            consumed_last_hour = round(min(100.0, drain_rate), 2)

        charger_connected = any(s.charging for s in samples)

        fast = False
        if drain_rate >= self._fast_rate:
            fast = True
        if span_min <= self._fast_short_min and consumed >= self._fast_short_drop:
            fast = True

        # Goal 3: map hourly drain rate to tiers; if currently on AC, surface LOW
        risk = "LOW" if newest.charging else drain_risk_level_from_rate(drain_rate)

        return {
            "batteryConsumedLastHour": consumed_last_hour,
            "batteryDrainRatePerHour": round(drain_rate, 2),
            "chargerConnected": charger_connected,
            "batteryFastDrain": fast,
            "riskLevel": risk,
            "batteryMetricsWindowMinutes": round(span_min, 1),
            "batteryHistorySamples": n,
            "batteryPercentAtWindowStart": round(oldest.percent, 1),
            "batteryPercentNow": round(newest.percent, 1),
        }
