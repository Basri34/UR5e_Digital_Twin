#!/usr/bin/env python3

"""Passive live IDS for completed UR5e trajectory commands.

The node combines command records written by the trajectory proxy with joint-state
samples observed during each command.  It then applies the trained supervised and
normal-only novelty models, publishes JSON decisions, and appends an audit record
to CSV.  This path is deliberately post-execution: it can observe physical effects
that are unavailable to the pre-execution gateway.
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

import rclpy
from ament_index_python.packages import get_package_share_directory
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, qos_profile_sensor_data
from sensor_msgs.msg import JointState
from std_msgs.msg import String

from .features import (
    GRIPPER_JOINT_CANDIDATES,
    JOINTS,
    JOINT_NAMES,
    LiveFeatureBuilder,
    TelemetrySample,
    finite_float,
    parse_timestamp,
)
from .model_runtime import IdsEngine


# Stable column order for the live-decision audit log.  Keeping this explicit also
# makes the live output directly comparable with the offline evaluation scripts.
LOG_FIELDS = [
    "detected_at",
    "command_id",
    "run_key",
    "task_type",
    "task_phase",
    "pose_name",
    "command_completed_at",
    "telemetry_samples",
    "decision_delay_ms",
    "inference_ms",
    "supervised_label",
    "supervised_confidence",
    "supervised_normal_probability",
    "supervised_probability_normal",
    "supervised_probability_mitm_trajectory_manipulation",
    "supervised_probability_command_injection",
    "supervised_probability_replay_attack",
    "supervised_probability_denial_of_service",
    "known_attack_alert",
    "novelty_base_score",
    "novelty_base_command_threshold",
    "novelty_base_run_max",
    "novelty_base_run_threshold",
    "novelty_temporal_score",
    "novelty_temporal_command_threshold",
    "novelty_temporal_run_max",
    "novelty_temporal_run_threshold",
    "temporal_command_alert",
    "base_run_alert",
    "novelty_alert",
    "verdict",
    "alert_label",
]


# Return a finite joint value, or NaN when the message lacks that field.
def safe_sequence_value(values: Sequence[float], index: int | None) -> float:
    if index is None or index < 0 or index >= len(values):
        return math.nan
    return finite_float(values[index])


# Identify the gripper joint while tolerating different URDF naming schemes.
def find_gripper_joint(names: Sequence[str]) -> str:
    available = set(names)
    for candidate in GRIPPER_JOINT_CANDIDATES:
        if candidate in available:
            return candidate
    for name in names:
        lowered = name.lower()
        if any(word in lowered for word in ("gripper", "finger", "knuckle")):
            return name
    return ""


# Replace non-finite floats recursively with JSON-compatible null values.
def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


# Fuse command and physical telemetry for post-execution IDS decisions.
class LiveIdsNode(Node):
    def __init__(self) -> None:
        # Configure model paths, ROS interfaces, telemetry storage and logging.
        super().__init__("sentinel_live_ids")
        share = Path(get_package_share_directory("sentinel_arm_ids"))
        default_workspace = Path.home() / "master_project" / "sentinel_arm_ws"

        # Paths and topics remain parameters so the same node can be used for the
        # development workspace and for a separately installed ROS 2 package.
        self.declare_parameter(
            "command_trace_csv", str(default_workspace / "data" / "command_trace.csv")
        )
        self.declare_parameter("joint_states_topic", "/joint_states")
        self.declare_parameter("prediction_topic", "/sentinel/ids/prediction")
        self.declare_parameter("alert_topic", "/sentinel/ids/alert")
        self.declare_parameter(
            "prediction_log_csv", str(default_workspace / "data" / "live_ids_predictions.csv")
        )
        self.declare_parameter("poll_period_seconds", 0.20)
        self.declare_parameter("telemetry_retention_seconds", 180.0)
        self.declare_parameter("telemetry_time_tolerance_seconds", 0.02)
        self.declare_parameter("maximum_sample_rate_hz", 50.0)
        self.declare_parameter("skip_existing_commands", True)
        self.declare_parameter("supervised_attack_threshold", 0.50)
        self.declare_parameter(
            "supervised_model_path",
            str(share / "models" / "best_multiclass_ids_model.joblib"),
        )
        self.declare_parameter(
            "novelty_model_path",
            str(share / "models" / "best_novelty_ids_model.joblib"),
        )
        self.declare_parameter(
            "temporal_model_path",
            str(share / "models" / "best_temporal_novelty_ids_model.joblib"),
        )

        self._trace_path = Path(
            str(self.get_parameter("command_trace_csv").value)
        ).expanduser()
        self._prediction_log_path = Path(
            str(self.get_parameter("prediction_log_csv").value)
        ).expanduser()
        self._poll_period = float(self.get_parameter("poll_period_seconds").value)
        self._retention = float(
            self.get_parameter("telemetry_retention_seconds").value
        )
        self._time_tolerance = float(
            self.get_parameter("telemetry_time_tolerance_seconds").value
        )
        self._maximum_sample_rate_hz = float(
            self.get_parameter("maximum_sample_rate_hz").value
        )
        self._skip_existing = bool(
            self.get_parameter("skip_existing_commands").value
        )
        if self._poll_period <= 0 or self._retention <= 0:
            raise ValueError("Polling period and telemetry retention must be positive.")
        if self._maximum_sample_rate_hz <= 0:
            raise ValueError("maximum_sample_rate_hz must be positive.")

        # IdsEngine owns the trained supervised, base-novelty and temporal-novelty
        # models and applies the decision policy evaluated in the dissertation.
        self._engine = IdsEngine(
            Path(str(self.get_parameter("supervised_model_path").value)).expanduser(),
            Path(str(self.get_parameter("novelty_model_path").value)).expanduser(),
            Path(str(self.get_parameter("temporal_model_path").value)).expanduser(),
            float(self.get_parameter("supervised_attack_threshold").value),
        )
        self._features = LiveFeatureBuilder()
        # A bounded time-window of joint states is retained so completed commands
        # can be matched to the physical samples collected during their execution.
        self._samples: deque[TelemetrySample] = deque()
        self._last_sample_monotonic: float | None = None

        joint_topic = str(self.get_parameter("joint_states_topic").value)
        self._joint_subscription = self.create_subscription(
            JointState,
            joint_topic,
            self._joint_state_callback,
            qos_profile_sensor_data,
        )
        output_qos = QoSProfile(depth=50)
        output_qos.reliability = ReliabilityPolicy.RELIABLE
        self._prediction_publisher = self.create_publisher(
            String,
            str(self.get_parameter("prediction_topic").value),
            output_qos,
        )
        self._alert_publisher = self.create_publisher(
            String,
            str(self.get_parameter("alert_topic").value),
            output_qos,
        )
        self._timer = self.create_timer(self._poll_period, self._poll_trace)

        # The command trace is tailed incrementally.  Byte offsets and file identity
        # allow the node to handle partial writes, truncation and file replacement.
        self._trace_fields: list[str] | None = None
        self._trace_offset = 0
        self._trace_identity: tuple[int, int] | None = None
        self._partial_trace_bytes = b""
        self._first_trace_initialisation = True
        self._trace_existed_at_startup = self._trace_path.exists()
        self._trace_missing_logged = False

        self._prediction_log_path.parent.mkdir(parents=True, exist_ok=True)
        log_exists = self._prediction_log_path.exists()
        self._log_handle = self._prediction_log_path.open(
            "a", newline="", encoding="utf-8", buffering=1
        )
        self._log_writer = csv.DictWriter(self._log_handle, fieldnames=LOG_FIELDS)
        if not log_exists or self._prediction_log_path.stat().st_size == 0:
            self._log_writer.writeheader()

        self.get_logger().info("Sentinel live IDS is ready.")
        self.get_logger().info(f"Joint telemetry: {joint_topic}")
        self.get_logger().info(f"Command trace: {self._trace_path}")
        self.get_logger().info(
            "Decision policy: supervised known-attack classification; "
            "temporal command novelty plus base run novelty for unknown attacks."
        )
        if self._skip_existing:
            self.get_logger().info(
                "Existing command rows will be skipped. Start this node before the next task run."
            )

    def _joint_state_callback(self, message: JointState) -> None:
        # Downsample and retain recent position, velocity and effort telemetry.
        now_monotonic = time.monotonic()
        minimum_period = 1.0 / self._maximum_sample_rate_hz
        if (
            self._last_sample_monotonic is not None
            and now_monotonic - self._last_sample_monotonic < minimum_period
        ):
            return
        interval = (
            now_monotonic - self._last_sample_monotonic
            if self._last_sample_monotonic is not None
            else math.nan
        )
        self._last_sample_monotonic = now_monotonic
        # JointState arrays are indexed through message.name because publishers are
        # not required to use the model's canonical joint ordering.
        indices = {name: index for index, name in enumerate(message.name)}
        values: dict[str, float] = {}
        for joint, joint_name in zip(JOINTS, JOINT_NAMES, strict=True):
            index = indices.get(joint_name)
            values[f"reported_{joint}_position"] = safe_sequence_value(
                message.position, index
            )
            values[f"reported_{joint}_velocity"] = safe_sequence_value(
                message.velocity, index
            )
            values[f"reported_{joint}_effort"] = safe_sequence_value(
                message.effort, index
            )
        gripper_name = find_gripper_joint(message.name)
        gripper_index = indices.get(gripper_name) if gripper_name else None
        values["reported_gripper_position"] = safe_sequence_value(
            message.position, gripper_index
        )
        values["reported_gripper_velocity"] = safe_sequence_value(
            message.velocity, gripper_index
        )
        now_wall = time.time()
        self._samples.append(
            TelemetrySample(
                wall_time_seconds=now_wall,
                sample_interval_seconds=interval,
                values=values,
            )
        )
        # Discard samples too old to belong to any newly completed command.
        cutoff = now_wall - self._retention
        while self._samples and self._samples[0].wall_time_seconds < cutoff:
            self._samples.popleft()

    def _initialise_trace(self, process_existing: bool) -> bool:
        # Open a command trace and choose whether existing rows should be read.
        if not self._trace_path.exists():
            if not self._trace_missing_logged:
                self.get_logger().warning(
                    f"Waiting for command trace file: {self._trace_path}"
                )
                self._trace_missing_logged = True
            return False
        self._trace_missing_logged = False
        stat = self._trace_path.stat()
        with self._trace_path.open("rb") as handle:
            header_bytes = handle.readline()
            if not header_bytes:
                return False
            header_text = header_bytes.decode("utf-8-sig").rstrip("\r\n")
            self._trace_fields = next(csv.reader([header_text]))
            self._trace_offset = handle.tell()
            if not process_existing:
                handle.seek(0, os.SEEK_END)
                self._trace_offset = handle.tell()
        self._trace_identity = (stat.st_dev, stat.st_ino)
        self._partial_trace_bytes = b""
        return True

    def _poll_trace(self) -> None:
        # Read complete rows appended to the command CSV since the previous poll.
        try:
            if self._trace_fields is None:
                process_existing = not (
                    self._first_trace_initialisation and self._skip_existing
                    and self._trace_existed_at_startup
                )
                if not self._initialise_trace(process_existing=process_existing):
                    return
                self._first_trace_initialisation = False

            stat = self._trace_path.stat()
            identity = (stat.st_dev, stat.st_ino)
            # A changed inode or shorter file indicates log rotation/replacement.
            if identity != self._trace_identity or stat.st_size < self._trace_offset:
                self.get_logger().info("Command trace was replaced; following the new file.")
                if not self._initialise_trace(process_existing=True):
                    return

            with self._trace_path.open("rb") as handle:
                handle.seek(self._trace_offset)
                new_bytes = handle.read()
                self._trace_offset = handle.tell()
            if not new_bytes:
                return
            # Preserve an unfinished final row until the proxy completes its write.
            combined = self._partial_trace_bytes + new_bytes
            lines = combined.splitlines(keepends=True)
            complete: list[bytes] = []
            self._partial_trace_bytes = b""
            for line in lines:
                if line.endswith((b"\n", b"\r")):
                    complete.append(line)
                else:
                    self._partial_trace_bytes = line
            if not complete:
                return
            text = b"".join(complete).decode("utf-8")
            reader = csv.DictReader(io.StringIO(text), fieldnames=self._trace_fields)
            for row in reader:
                if row.get("command_id") and row.get("completed_at"):
                    self._process_command(row)
        except FileNotFoundError:
            self._trace_fields = None
        except Exception as exc:
            self.get_logger().error(f"Could not process command trace update: {exc}")

    def _process_command(self, row: dict[str, str]) -> None:
        # Build one command window, run inference and publish its IDS verdict.
        run_key = str(row.get("run_key") or "").strip()
        task_phase = str(row.get("task_phase") or "").strip()
        if not run_key or run_key == "unassigned" or task_phase == "outside_measurement":
            self.get_logger().debug(
                "Skipping command outside a measured run: "
                f"run={run_key or 'unassigned'}, phase={task_phase or 'unassigned'}."
            )
            return

        started = time.perf_counter()
        received = parse_timestamp(row.get("received_at"))
        completed = parse_timestamp(row.get("completed_at"))
        
        if not math.isfinite(received) or not math.isfinite(completed):
            self.get_logger().warning(
                f"Skipping command {row.get('command_id', '')[:8]} with invalid timestamps."
            )
            return
        
        # The tolerance accounts for small differences between proxy timestamps and
        # the wall-clock time assigned when /joint_states messages are received.
        window_start = received - self._time_tolerance
        window_end = completed + self._time_tolerance
        
        samples = [
            sample
            for sample in self._samples
            if window_start <= sample.wall_time_seconds <= window_end
        ]
        
        # LiveFeatureBuilder reproduces the feature schema used during offline model
        # development; IdsEngine then combines known-attack and novelty evidence.
        features = self._features.build(row, samples)
        prediction = self._engine.predict(features, run_key)
        inference_ms = (time.perf_counter() - started) * 1000.0
        detected_at = datetime.now().astimezone()
        
        record: dict[str, Any] = {
            "detected_at": detected_at.isoformat(timespec="milliseconds"),
            "command_id": row.get("command_id", ""),
            "run_key": run_key,
            "task_type": row.get("task_type", ""),
            "task_phase": row.get("task_phase", ""),
            "pose_name": row.get("pose_name", ""),
            "command_completed_at": row.get("completed_at", ""),
            "telemetry_samples": len(samples),
            "decision_delay_ms": max(
                0.0, (detected_at.timestamp() - completed) * 1000.0
            ),
            "inference_ms": inference_ms,
            **prediction,
        }
        
        message = String()
        message.data = json.dumps(json_safe(record), separators=(",", ":"))
        self._prediction_publisher.publish(message)
        self._log_writer.writerow({field: record.get(field, "") for field in LOG_FIELDS})

        # Every prediction is published, while only anomalous verdicts are repeated
        # on the alert topic for downstream monitoring or operator notification.
        if prediction["verdict"] != "normal":
            self._alert_publisher.publish(message)
            if prediction["verdict"] == "known_attack":
                detail = (
                    f"confidence={prediction['supervised_confidence']:.3f}"
                )
            else:
                detail = (
                    "temporal_score="
                    f"{prediction['novelty_temporal_score']:.6f}/"
                    f"{prediction['novelty_temporal_command_threshold']:.6f}, "
                    "base_run_max="
                    f"{prediction['novelty_base_run_max']:.6f}/"
                    f"{prediction['novelty_base_run_threshold']:.6f}"
                )
            self.get_logger().warning(
                "IDS ALERT: "
                f"run={run_key}, phase={row.get('task_phase', '')}, "
                f"verdict={prediction['verdict']}, "
                f"label={prediction['alert_label']}, {detail}"
            )
        else:
            self.get_logger().info(
                f"IDS normal: run={run_key}, phase={row.get('task_phase', '')}, "
                f"confidence={prediction['supervised_confidence']:.3f}, "
                f"inference={inference_ms:.1f} ms"
            )
        if not samples:
            self.get_logger().warning(
                "No live joint samples matched this command window; physical features were imputed."
            )

    def destroy_node(self) -> bool:
        # Flush the decision log before releasing ROS resources.
        try:
            self._log_handle.flush()
            self._log_handle.close()
        finally:
            return super().destroy_node()


# Initialise ROS 2 and run the passive IDS until interrupted.
def main(args: Sequence[str] | None = None) -> None:
    rclpy.init(args=args)
    node = LiveIdsNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()