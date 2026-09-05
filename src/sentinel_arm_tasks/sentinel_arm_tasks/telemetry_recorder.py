#!/usr/bin/env python3

from __future__ import annotations

import csv
import json
import math
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO, Mapping, Sequence

import rclpy
from rclpy.executors import SingleThreadedExecutor
from rclpy.qos import QoSProfile, ReliabilityPolicy, qos_profile_sensor_data
from sensor_msgs.msg import JointState
from std_msgs.msg import String


SCHEMA_VERSION = "sentinel_joint_telemetry_v2"
ARM_JOINTS = (
    "shoulder_pan_joint",
    "shoulder_lift_joint",
    "elbow_joint",
    "wrist_1_joint",
    "wrist_2_joint",
    "wrist_3_joint",
)
GRIPPER_JOINTS = (
    "finger_joint",
    "robotiq_85_left_knuckle_joint",
    "robotiq_2f_85_left_knuckle_joint",
    "left_knuckle_joint",
    "gripper_joint",
)
ATTACK_KEYS = (
    "attack_type",
    "attack_variant",
    "attack_severity",
    "attack_target",
    "attack_target_object",
    "attack_target_phase",
    "attack_parameter_value",
    "attack_parameter_unit",
)

CSV_FIELDS = [
    "schema_version", "session_id", "run_key", "run_id", "sample_index",
    "task_type", "condition", *ATTACK_KEYS, "attack_event_id",
    "attack_active", "attack_source", "attack_start_elapsed_seconds",
    "attack_elapsed_seconds", "task_phase", "received_at", "elapsed_seconds",
    "sample_interval_seconds", "instantaneous_sample_rate_hz", "sampling_gap",
    "ros_time_seconds", "reported_ros_time_seconds", "reported_state_source",
    "reported_state_age_seconds",
]
for joint in ARM_JOINTS:
    name = joint.removesuffix("_joint")
    for prefix in ("", "reported_"):
        CSV_FIELDS += [f"{prefix}{name}_{field}" for field in ("position", "velocity", "effort")]
    CSV_FIELDS += [f"{name}_{field}_residual" for field in ("position", "velocity", "effort")]
CSV_FIELDS += [
    "gripper_joint_name", "gripper_position", "gripper_velocity", "gripper_effort",
    "reported_gripper_joint_name", "reported_gripper_position",
    "reported_gripper_velocity", "reported_gripper_effort",
    "gripper_position_residual", "gripper_velocity_residual",
    "gripper_effort_residual",
]

ATTACK_EVENT_FIELDS = [
    "schema_version", "session_id", "run_key", "run_id", "task_type",
    "attack_event_id", *ATTACK_KEYS, "attack_source", "source_timestamp",
    "started_at", "start_elapsed_seconds", "ended_at", "end_elapsed_seconds",
    "duration_seconds", "end_reason",
]


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def text(value: object, default: str = "") -> str:
    value = "" if value is None else str(value).strip()
    return value or default


def number(value: object) -> float | None:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def csv_number(value: object) -> str:
    value = number(value)
    return "" if value is None else f"{value:.6f}"


def value_at(values: Sequence[float], index: int | None) -> float | str:
    if index is None or index < 0 or index >= len(values):
        return ""
    value = number(values[index])
    return "" if value is None else value


def difference(reported: object, trusted: object) -> float | str:
    reported, trusted = number(reported), number(trusted)
    return "" if reported is None or trusted is None else reported - trusted


@dataclass(frozen=True)
class JointSnapshot:
    names: tuple[str, ...]
    position: tuple[float, ...]
    velocity: tuple[float, ...]
    effort: tuple[float, ...]
    ros_time: float
    received_at: float

    @classmethod
    def from_message(cls, message: JointState, received_at: float) -> "JointSnapshot":
        stamp = message.header.stamp
        return cls(
            tuple(message.name),
            tuple(message.position),
            tuple(message.velocity),
            tuple(message.effort),
            stamp.sec + stamp.nanosec / 1_000_000_000,
            received_at,
        )


@dataclass
class AttackEvent:
    event_id: str
    metadata: dict[str, str]
    source: str
    source_timestamp: str
    started_at: str
    started_monotonic: float
    start_elapsed: float


class TelemetryRecorder:
    def __init__(
        self,
        csv_path: Path | str,
        joint_states_topic: str = "/joint_states",
        reported_joint_states_topic: str | None = "/sentinel/reported_joint_states",
        attack_status_topic: str | None = "/sentinel/attack/status",
        attack_events_csv_path: Path | str | None = None,
        max_sample_rate_hz: float | None = 50.0,
        flush_every_samples: int = 25,
        maximum_reported_state_age_seconds: float = 0.25,
        sampling_gap_multiplier: float = 2.5,
    ) -> None:
        if not rclpy.ok():
            raise RuntimeError("Call rclpy.init() before creating TelemetryRecorder.")
        if max_sample_rate_hz is not None and max_sample_rate_hz <= 0:
            raise ValueError("max_sample_rate_hz must be positive or None.")
        if flush_every_samples <= 0 or maximum_reported_state_age_seconds <= 0:
            raise ValueError("Flush count and reported-state age must be positive.")
        if sampling_gap_multiplier <= 1:
            raise ValueError("sampling_gap_multiplier must be greater than 1.")

        self.csv_path = Path(csv_path).expanduser().resolve()
        self.attack_events_csv_path = (
            self.csv_path.parent / "attack_events.csv"
            if attack_events_csv_path is None
            else Path(attack_events_csv_path).expanduser().resolve()
        )
        self.flush_every_samples = flush_every_samples
        self.minimum_sample_period = 0.0 if max_sample_rate_hz is None else 1 / max_sample_rate_hz
        self.maximum_reported_state_age_seconds = maximum_reported_state_age_seconds
        self.sampling_gap_multiplier = sampling_gap_multiplier

        self._lock = threading.RLock()
        self._first_message = threading.Event()
        self._shutdown = self._active = False
        self._session_id = self._run_key = self._task_type = self._condition = ""
        self._run_id = self._sample_index = 0
        self._task_phase = "unassigned"
        self._attack = {key: ("" if key.endswith(("value", "unit")) else "none") for key in ATTACK_KEYS}
        self._active_attack: AttackEvent | None = None
        self._last_attack_start: float | None = None
        self._latest_reported: JointSnapshot | None = None
        self._run_start = self._last_sample_time = 0.0
        self._csv_file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None

        suffix = f"{os.getpid()}_{id(self) % 100000}"
        self._node = rclpy.create_node(f"sentinel_telemetry_recorder_{suffix}")
        self._node.create_subscription(JointState, joint_states_topic, self._trusted_callback, qos_profile_sensor_data)
        if reported_joint_states_topic:
            self._node.create_subscription(JointState, reported_joint_states_topic, self._reported_callback, qos_profile_sensor_data)
        if attack_status_topic:
            qos = QoSProfile(depth=20)
            qos.reliability = ReliabilityPolicy.RELIABLE
            self._node.create_subscription(String, attack_status_topic, self._attack_status_callback, qos)

        self._executor = SingleThreadedExecutor()
        self._executor.add_node(self._node)
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    @property
    def is_recording(self) -> bool:
        return self._active

    @property
    def sample_count(self) -> int:
        return self._sample_index

    @property
    def attack_active(self) -> bool:
        return self._active_attack is not None

    def wait_for_joint_states(self, timeout_seconds: float = 5.0) -> bool:
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds cannot be negative.")
        return self._first_message.wait(timeout_seconds)

    def start_run(
        self, *, session_id: str, run_id: int, task_type: str, condition: str,
        attack_type: str = "none", initial_phase: str = "task_start",
        attack_variant: str = "none", attack_severity: str = "none",
        attack_target: str = "none", attack_target_object: str = "none",
        attack_target_phase: str = "none", attack_parameter_value: object = "",
        attack_parameter_unit: str = "",
    ) -> None:
        required = {
            "session_id": text(session_id), "task_type": text(task_type),
            "condition": text(condition), "initial_phase": text(initial_phase),
        }
        if missing := [name for name, value in required.items() if not value]:
            raise ValueError(f"{missing[0]} cannot be empty.")
        if run_id <= 0:
            raise ValueError("run_id must be positive.")

        with self._lock:
            if self._shutdown:
                raise RuntimeError("The telemetry recorder is shut down.")
            if self._active:
                raise RuntimeError("A telemetry run is already active.")
            self._open_csv()
            self._session_id, self._run_id = required["session_id"], run_id
            self._run_key = f"{self._session_id}:{run_id}"
            self._task_type, self._condition = required["task_type"], required["condition"]
            self._task_phase = required["initial_phase"]
            self._attack.update({
                "attack_type": text(attack_type, "none"),
                "attack_variant": text(attack_variant, "none"),
                "attack_severity": text(attack_severity, "none"),
                "attack_target": text(attack_target, "none"),
                "attack_target_object": text(attack_target_object, "none"),
                "attack_target_phase": text(attack_target_phase, "none"),
                "attack_parameter_value": text(attack_parameter_value),
                "attack_parameter_unit": text(attack_parameter_unit),
            })
            self._active_attack = None
            self._last_attack_start = None
            self._latest_reported = None
            self._run_start = time.monotonic()
            self._last_sample_time = 0.0
            self._sample_index = 0
            self._active = True

        self._node.get_logger().info(
            f"Recording V2 telemetry for run {run_id}: {task_type}, {condition}, {self._attack['attack_type']}"
        )

    def set_phase(self, task_phase: str) -> None:
        task_phase = text(task_phase)
        if not task_phase:
            raise ValueError("task_phase cannot be empty.")
        with self._lock:
            self._require_active()
            self._task_phase = task_phase

    def set_attack_metadata(self, **metadata: object) -> None:
        with self._lock:
            self._require_active()
            for key, value in metadata.items():
                if key in ATTACK_KEYS and value is not None:
                    default = "" if key.endswith(("value", "unit")) else "none"
                    self._attack[key] = text(value, default)

    def start_attack(self, *, attack_event_id: str | None = None, source: str = "direct_api", source_timestamp: str = "", **metadata: object) -> str:
        with self._lock:
            self._require_active()
            if self._active_attack:
                self._finish_attack("replaced_by_new_event")
            self.set_attack_metadata(**metadata)
            event_id = text(attack_event_id) or f"{self._session_id}_{self._run_id}_{uuid.uuid4().hex[:10]}"
            started = time.monotonic()
            elapsed = started - self._run_start
            self._active_attack = AttackEvent(
                event_id, dict(self._attack), text(source, "unknown"),
                text(source_timestamp), now_text(), started, elapsed,
            )
            self._last_attack_start = elapsed

        self._node.get_logger().warning(
            f"Attack active for run {self._run_id}: {self._attack['attack_type']} ({self._attack['attack_variant']})"
        )
        return event_id

    def stop_attack(self, *, end_reason: str = "completed") -> None:
        with self._lock:
            if self._active_attack:
                self._finish_attack(text(end_reason, "completed"))

    def stop_run(self) -> int:
        with self._lock:
            if not self._active:
                return self._sample_index
            if self._active_attack:
                self._finish_attack("run_stopped")
            self._active = False
            count, run_id = self._sample_index, self._run_id
            self._close_csv()
        self._node.get_logger().info(f"Stopped V2 telemetry for run {run_id}: {count} samples")
        return count

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
        self.stop_run()
        try:
            self._executor.shutdown(timeout_sec=2.0)
        except TypeError:
            self._executor.shutdown()
        self._thread.join(timeout=2.0)
        try:
            self._executor.remove_node(self._node)
        except Exception:
            pass
        self._node.destroy_node()

    def _require_active(self) -> None:
        if not self._active:
            raise RuntimeError("No telemetry run is active.")

    def _spin(self) -> None:
        try:
            self._executor.spin()
        except Exception as exc:
            if not self._shutdown:
                self._node.get_logger().error(f"Telemetry executor stopped: {exc}")

    def _reported_callback(self, message: JointState) -> None:
        with self._lock:
            self._latest_reported = JointSnapshot.from_message(message, time.monotonic())

    def _attack_status_callback(self, message: String) -> None:
        try:
            payload = json.loads(message.data)
        except json.JSONDecodeError as exc:
            self._node.get_logger().error(f"Invalid attack-status JSON: {exc}")
            return
        if not isinstance(payload, dict):
            self._node.get_logger().error("Attack-status JSON must contain an object.")
            return

        with self._lock:
            if not self._active:
                return
            if payload.get("session_id") and text(payload["session_id"]) != self._session_id:
                return
            try:
                if payload.get("run_id") is not None and int(payload["run_id"]) != self._run_id:
                    return
            except (TypeError, ValueError):
                self._node.get_logger().error("Attack-status run_id must be an integer.")
                return

        action = text(payload.get("action")).lower()
        if action in {"stop", "end", "inactive"}:
            self.stop_attack(end_reason=text(payload.get("end_reason"), "status_message_stop"))
        elif action in {"start", "begin", "active"}:
            metadata = {key: payload.get(key) for key in ATTACK_KEYS}
            try:
                self.start_attack(
                    attack_event_id=payload.get("attack_event_id"),
                    source=text(payload.get("source"), "ros_topic"),
                    source_timestamp=text(payload.get("source_timestamp")),
                    **metadata,
                )
            except Exception as exc:
                self._node.get_logger().error(f"Could not start attack event: {exc}")
        else:
            self._node.get_logger().error("Attack-status action must be start or stop.")

    def _trusted_callback(self, message: JointState) -> None:
        self._first_message.set()
        received = time.monotonic()
        with self._lock:
            if not self._active:
                return
            interval = received - self._last_sample_time if self._last_sample_time else None
            if interval is not None and interval < self.minimum_sample_period:
                return
            if not self._writer or not self._csv_file:
                self._node.get_logger().error("Telemetry is active but the CSV is not open.")
                return

            trusted = JointSnapshot.from_message(message, received)
            reported, source, reported_age = trusted, "trusted_fallback", 0.0
            if self._latest_reported:
                age = received - self._latest_reported.received_at
                if 0 <= age <= self.maximum_reported_state_age_seconds:
                    reported, source, reported_age = self._latest_reported, "reported_topic", age

            elapsed = received - self._run_start
            rate = "" if not interval or interval <= 0 else 1 / interval
            expected = self.minimum_sample_period or interval or 0.0
            gap = int(bool(interval and expected and interval > expected * self.sampling_gap_multiplier))
            event = self._active_attack
            attack_start = event.start_elapsed if event else self._last_attack_start

            row: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "session_id": self._session_id,
                "run_key": self._run_key,
                "run_id": self._run_id,
                "sample_index": self._sample_index,
                "task_type": self._task_type,
                "condition": self._condition,
                **self._attack,
                "attack_event_id": event.event_id if event else "",
                "attack_active": int(event is not None),
                "attack_source": event.source if event else "",
                "attack_start_elapsed_seconds": csv_number(attack_start),
                "attack_elapsed_seconds": csv_number(received - event.started_monotonic) if event else "",
                "task_phase": self._task_phase,
                "received_at": now_text(),
                "elapsed_seconds": f"{elapsed:.6f}",
                "sample_interval_seconds": csv_number(interval),
                "instantaneous_sample_rate_hz": csv_number(rate),
                "sampling_gap": gap,
                "ros_time_seconds": f"{trusted.ros_time:.9f}",
                "reported_ros_time_seconds": f"{reported.ros_time:.9f}",
                "reported_state_source": source,
                "reported_state_age_seconds": csv_number(reported_age),
            }
            self._add_joint_data(row, trusted, reported)

            try:
                self._writer.writerow(row)
            except OSError as exc:
                self._node.get_logger().error(f"Could not write telemetry: {exc}")
                self._active = False
                self._close_csv()
                return

            self._sample_index += 1
            self._last_sample_time = received
            if self._sample_index % self.flush_every_samples == 0:
                self._csv_file.flush()

    def _add_joint_data(self, row: dict[str, object], trusted: JointSnapshot, reported: JointSnapshot) -> None:
        trusted_index = {name: i for i, name in enumerate(trusted.names)}
        reported_index = {name: i for i, name in enumerate(reported.names)}

        for joint in ARM_JOINTS:
            name = joint.removesuffix("_joint")
            trusted_values = self._joint_values(trusted, trusted_index.get(joint))
            reported_values = self._joint_values(reported, reported_index.get(joint))
            for field, trusted_value, reported_value in zip(
                ("position", "velocity", "effort"), trusted_values, reported_values
            ):
                row[f"{name}_{field}"] = trusted_value
                row[f"reported_{name}_{field}"] = reported_value
                row[f"{name}_{field}_residual"] = difference(reported_value, trusted_value)

        trusted_gripper = self._find_gripper(trusted.names)
        reported_gripper = self._find_gripper(reported.names)
        trusted_values = self._joint_values(trusted, trusted_index.get(trusted_gripper))
        reported_values = self._joint_values(reported, reported_index.get(reported_gripper))
        row["gripper_joint_name"] = trusted_gripper
        row["reported_gripper_joint_name"] = reported_gripper
        for field, trusted_value, reported_value in zip(
            ("position", "velocity", "effort"), trusted_values, reported_values
        ):
            row[f"gripper_{field}"] = trusted_value
            row[f"reported_gripper_{field}"] = reported_value
            row[f"gripper_{field}_residual"] = difference(reported_value, trusted_value)

    @staticmethod
    def _joint_values(snapshot: JointSnapshot, index: int | None) -> tuple[float | str, ...]:
        return (
            value_at(snapshot.position, index),
            value_at(snapshot.velocity, index),
            value_at(snapshot.effort, index),
        )

    def _open_csv(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._check_header(self.csv_path, CSV_FIELDS)
        self._csv_file = self.csv_path.open("a", newline="", encoding="utf-8", buffering=1)
        self._writer = csv.DictWriter(self._csv_file, fieldnames=CSV_FIELDS)
        if self.csv_path.stat().st_size == 0:
            self._writer.writeheader()
            self._csv_file.flush()

    def _close_csv(self) -> None:
        if self._csv_file:
            try:
                self._csv_file.flush()
            finally:
                self._csv_file.close()
        self._csv_file = self._writer = None

    def _finish_attack(self, reason: str) -> None:
        event = self._active_attack
        if not event:
            return
        ended = time.monotonic()
        row = {
            "schema_version": SCHEMA_VERSION,
            "session_id": self._session_id,
            "run_key": self._run_key,
            "run_id": self._run_id,
            "task_type": self._task_type,
            "attack_event_id": event.event_id,
            **event.metadata,
            "attack_source": event.source,
            "source_timestamp": event.source_timestamp,
            "started_at": event.started_at,
            "start_elapsed_seconds": f"{event.start_elapsed:.6f}",
            "ended_at": now_text(),
            "end_elapsed_seconds": f"{ended - self._run_start:.6f}",
            "duration_seconds": f"{ended - event.started_monotonic:.6f}",
            "end_reason": reason,
        }
        self._append_row(self.attack_events_csv_path, ATTACK_EVENT_FIELDS, row)
        self._active_attack = None

    @classmethod
    def _append_row(cls, path: Path, fields: Sequence[str], row: Mapping[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        cls._check_header(path, fields)
        with path.open("a", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            if path.stat().st_size == 0:
                writer.writeheader()
            writer.writerow(dict(row))

    @staticmethod
    def _check_header(path: Path, fields: Sequence[str]) -> None:
        if not path.exists():
            path.touch()
            return
        if path.stat().st_size == 0:
            return
        with path.open(newline="", encoding="utf-8") as file:
            existing = next(csv.reader(file), [])
        if existing != list(fields):
            raise RuntimeError(f"The existing CSV has an incompatible header: {path}")

    @staticmethod
    def _find_gripper(names: Sequence[str]) -> str:
        for candidate in GRIPPER_JOINTS:
            if candidate in names:
                return candidate
        return next(
            (name for name in names if name not in ARM_JOINTS and any(word in name.lower() for word in ("gripper", "finger", "knuckle"))),
            "",
        )