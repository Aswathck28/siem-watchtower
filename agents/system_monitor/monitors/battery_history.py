"""
Deprecated location for battery analytics.

Use :mod:`utils.battery_history` (``BatteryHourlyTracker``, ``drain_risk_level_from_rate``).
This module remains so older imports ``from monitors.battery_history import ...`` work.
"""
from utils.battery_history import BatteryHourlyTracker, drain_risk_level_from_rate

__all__ = ["BatteryHourlyTracker", "drain_risk_level_from_rate"]
