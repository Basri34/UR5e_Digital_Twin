"""Leakage-safe live feature construction matching the trained IDS schema."""

from __future__ import annotations

import json
import math
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

import numpy as np


JOINTS = (
    "shoulder_pan",
    "shoulder_lift",
    "elbow",
    "wrist_1",
    "wrist_2",
    "wrist_3",
)
JOINT_NAMES = tuple(f"{joint}_joint" for joint in JOINTS)
GRIPPER_JOINT_CANDIDATES = (
    "finger_joint",
    "robotiq_85_left_knuckle_joint",
    "robotiq_2f_85_left_knuckle_joint",
    "left_knuckle_joint",
    "gripper_joint",
)
AGGREGATIONS = ("mean", "std", "min", "max", "range", "rms", "first", "last", "delta")
WINDOW_SIZE = 3


def finite_float(value: Any) -> float:
    try:
        converted = float(value)
    except (TypeError, ValueError):
        return math.nan
    return converted if math.isfinite(converted) else math.nan


def parse_timestamp(value: Any) -> float:
    text = str(value or "").strip()
    if not text:
        return math.nan
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return math.nan


def final_positions(trajectory_json: Any, joint_names_json: Any) -> dict[str, float]:
    try:
        trajectory = json.loads(str(trajectory_json))
        names = trajectory.get("joint_names") or json.loads(str(joint_names_json))
        points = trajectory.get("points", [])
        positions = points[-1].get("positions", []) if points else []
        return {
            str(name): float(value)
            for name, value in zip(names, positions, strict=False)
        }
    except (TypeError, ValueError, json.JSONDecodeError, IndexError):
        return {}


def aggregate(values: Sequence[float]) -> dict[str, float]:
    array = np.asarray(values, dtype=float)
    array = array[np.isfinite(array)]
    if array.size == 0:
        return {name: math.nan for name in AGGREGATIONS}
    first = float(array[0])
    last = float(array[-1])
    return {
        "mean": float(np.mean(array)),
        "std": float(np.std(array, ddof=0)),
        "min": float(np.min(array)),
        "max": float(np.max(array)),
        "range": float(np.max(array) - np.min(array)),
        "rms": float(np.sqrt(np.mean(np.square(array)))),
        "first": first,
        "last": last,
        "delta": last - first,
    }


@dataclass(frozen=True)
class TelemetrySample:
    wall_time_seconds: float
    sample_interval_seconds: float
    values: Mapping[str, float]


class LiveFeatureBuilder:
    """Construct one command observation and its causal temporal extension."""

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        if window_size != WINDOW_SIZE:
            raise ValueError(f"The deployed temporal model requires a window of {WINDOW_SIZE} commands.")
        self.window_size = window_size
        self._previous_targets: dict[str, np.ndarray] = {}
        self._previous_received: dict[str, float] = {}
        self._ordinals: dict[str, int] = defaultdict(int)
        self._cyber_history: dict[str, deque[dict[str, float]]] = defaultdict(
            # The current command is added separately when constructing the
            # causal window, so retain only the preceding window_size - 1
            # commands. For the trained w3 model this means previous two plus
            # current, exactly matching pandas rolling(window=3).
            lambda: deque(maxlen=self.window_size - 1)
        )

    @staticmethod
    def cyber_columns() -> list[str]:
        columns = [
            "cyber_command_ordinal",
            "cyber_is_first_command",
            "cyber_time_since_previous_command_s",
            "cyber_context_age_seconds",
            "cyber_forwarded_duration_seconds",
            "cyber_command_latency_ms",
            "cyber_controller_execution_seconds",
            "cyber_proxy_total_seconds",
            "cyber_target_delta_l1",
            "cyber_target_delta_l2",
        ]
        for joint in JOINTS:
            columns.extend([f"cyber_target_{joint}", f"cyber_target_delta_{joint}"])
        return sorted(columns)

    def build(
        self,
        command: Mapping[str, Any],
        samples: Sequence[TelemetrySample],
    ) -> dict[str, float]:
        run_key = str(command.get("run_key") or "unassigned")
        received = parse_timestamp(command.get("received_at"))
        target_map = final_positions(
            command.get("forwarded_trajectory_json", "{}"),
            command.get("joint_names_json", "[]"),
        )
        target = np.asarray(
            [target_map.get(name, math.nan) for name in JOINT_NAMES], dtype=float
        )
        previous = self._previous_targets.get(run_key)
        previous_received = self._previous_received.get(run_key)
        ordinal = self._ordinals[run_key]
        if previous is None:
            target_delta = np.zeros(len(JOINTS), dtype=float)
            is_first = 1
        else:
            target_delta = target - previous
            is_first = 0
        time_since_previous = (
            received - previous_received
            if previous_received is not None
            and math.isfinite(received)
            and math.isfinite(previous_received)
            else math.nan
        )
        features: dict[str, float] = {
            "cyber_command_ordinal": float(ordinal),
            "cyber_is_first_command": float(is_first),
            "cyber_time_since_previous_command_s": time_since_previous,
            "cyber_context_age_seconds": finite_float(command.get("context_age_seconds")),
            "cyber_forwarded_duration_seconds": finite_float(
                command.get("forwarded_duration_seconds")
            ),
            "cyber_command_latency_ms": finite_float(command.get("command_latency_ms")),
            "cyber_controller_execution_seconds": finite_float(
                command.get("controller_execution_seconds")
            ),
            "cyber_proxy_total_seconds": finite_float(command.get("proxy_total_seconds")),
            "cyber_target_delta_l1": float(np.nansum(np.abs(target_delta))),
            "cyber_target_delta_l2": float(np.sqrt(np.nansum(np.square(target_delta)))),
        }
        for index, joint in enumerate(JOINTS):
            features[f"cyber_target_{joint}"] = float(target[index])
            features[f"cyber_target_delta_{joint}"] = float(target_delta[index])

        ordered_samples = sorted(samples, key=lambda item: item.wall_time_seconds)
        features["physical_sample_count"] = float(len(ordered_samples))
        features["physical_observed_window_seconds"] = (
            ordered_samples[-1].wall_time_seconds - ordered_samples[0].wall_time_seconds
            if len(ordered_samples) >= 2
            else 0.0
        )
        intervals = [sample.sample_interval_seconds for sample in ordered_samples]
        finite_intervals = [value for value in intervals if math.isfinite(value)]
        features["physical_mean_sample_interval_seconds"] = (
            float(np.mean(finite_intervals)) if finite_intervals else math.nan
        )
        signals = [
            *(f"reported_{joint}_{measure}" for joint in JOINTS for measure in ("position", "velocity", "effort")),
            "reported_gripper_position",
            "reported_gripper_velocity",
        ]
        for signal in signals:
            statistics = aggregate(
                [finite_float(sample.values.get(signal)) for sample in ordered_samples]
            )
            for statistic, value in statistics.items():
                features[f"physical_{signal}_{statistic}"] = value

        absolute_tracking_errors = []
        for index, joint in enumerate(JOINTS):
            final_position = features[f"physical_reported_{joint}_position_last"]
            error = final_position - target[index]
            features[f"fused_final_tracking_error_{joint}"] = float(error)
            features[f"fused_abs_final_tracking_error_{joint}"] = float(abs(error))
            absolute_tracking_errors.append(abs(error))
        features["fused_abs_final_tracking_error_l1"] = float(
            np.nansum(absolute_tracking_errors)
        )
        features["fused_abs_final_tracking_error_l2"] = float(
            np.sqrt(np.nansum(np.square(absolute_tracking_errors)))
        )

        cyber_columns = self.cyber_columns()
        current_cyber = {column: finite_float(features[column]) for column in cyber_columns}
        history = self._cyber_history[run_key]
        window = [*history, current_cyber]
        previous_cyber = history[-1] if history else None
        for column in cyber_columns:
            current_value = current_cyber[column]
            previous_value = previous_cyber[column] if previous_cyber else math.nan
            delta = (
                current_value - previous_value
                if math.isfinite(current_value) and math.isfinite(previous_value)
                else 0.0
            )
            values = np.asarray([item[column] for item in window], dtype=float)
            finite = values[np.isfinite(values)]
            features[f"temporal_w{self.window_size}_delta__{column}"] = float(delta)
            features[f"temporal_w{self.window_size}_mean__{column}"] = (
                float(np.mean(finite)) if finite.size else math.nan
            )
            features[f"temporal_w{self.window_size}_std__{column}"] = (
                float(np.std(finite, ddof=0)) if finite.size else 0.0
            )

        history.append(current_cyber)
        self._previous_targets[run_key] = target
        self._previous_received[run_key] = received
        self._ordinals[run_key] = ordinal + 1
        return features