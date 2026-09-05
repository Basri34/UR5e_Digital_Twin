#!/usr/bin/env python3

# ROS 2 action proxy that simulates delay-based denial of service by waiting for
# a controlled period before forwarding a legitimate trajectory unchanged.

from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, IO, Sequence

import rclpy
from action_msgs.msg import GoalStatus
from control_msgs.action import FollowJointTrajectory
from rclpy.action import ActionClient, ActionServer
from rclpy.action.server import CancelResponse, GoalResponse
from rclpy.callback_groups import ReentrantCallbackGroup
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from rclpy.utilities import remove_ros_args
from std_msgs.msg import String


# Version written into every command-trace row.
SCHEMA_VERSION = "sentinel_command_trace_v2"

# Proxy modes distinguish normal forwarding, an armed delay and an applied delay.
PROXY_MODE_NORMAL = "normal_passthrough"
PROXY_MODE_DELAY_ARMED = "command_delay_armed"
PROXY_MODE_DELAY_APPLIED = "command_delay"

DELAY_DOS_ATTACK_TYPES = {
    "denial_of_service",
    "dos",
    "delay_dos",
    "command_delay_dos",
    "trajectory_delay_dos",
}

DELAY_DOS_VARIANTS = {
    "command_delay",
    "trajectory_delay",
    "pre_forward_delay",
}

# Safety limits bound the delay length and number of delayed commands per run.
DEFAULT_MAXIMUM_DELAY_MILLISECONDS = 3000.0
DEFAULT_MAXIMUM_DELAYS_PER_RUN = 1

DEFAULT_PROXY_ACTION = "/sentinel/arm_proxy/follow_joint_trajectory"
DEFAULT_CONTROLLER_ACTION = (
    "/scaled_joint_trajectory_controller/follow_joint_trajectory"
)
DEFAULT_CONTEXT_TOPIC = "/sentinel/experiment/context"
DEFAULT_ATTACK_STATUS_TOPIC = "/sentinel/attack/status"

# Baseline context prevents missing optional JSON fields from affecting logging.
CONTEXT_DEFAULTS = {
    "session_id": "",
    "run_key": "",
    "task_type": "",
    "condition": "",
    "attack_type": "none",
    "attack_variant": "none",
    "attack_severity": "none",
    "attack_target": "none",
    "attack_target_object": "none",
    "attack_target_phase": "none",
    "attack_parameter_value": "",
    "attack_parameter_unit": "",
    "attack_event_id": "",
    "task_phase": "unassigned",
    "pose_name": "",
}

# Fixed trace schema shared with downstream feature-preparation scripts.
CSV_FIELDS = [
    "schema_version",
    "command_id",
    "command_sequence_index",
    "proxy_mode",
    "session_id",
    "run_key",
    "run_id",
    "task_type",
    "condition",
    "attack_type",
    "attack_variant",
    "attack_severity",
    "attack_target",
    "attack_target_object",
    "attack_target_phase",
    "attack_parameter_value",
    "attack_parameter_unit",
    "attack_event_id",
    "attack_active",
    "task_phase",
    "pose_name",
    "context_received_at",
    "context_age_seconds",
    "received_at",
    "forwarded_at",
    "controller_accepted_at",
    "completed_at",
    "proxy_action",
    "controller_action",
    "joint_names_json",
    "original_trajectory_json",
    "forwarded_trajectory_json",
    "original_duration_seconds",
    "forwarded_duration_seconds",
    "command_modified",
    "command_injected",
    "command_replayed",
    "command_delayed",
    "command_dropped",
    "attack_applied",
    "modified_joint_names_json",
    "joint_offsets_json",
    "delay_applied_ms",
    "source_command_id",
    "source_run_key",
    "drop_reason",
    "controller_goal_accepted",
    "controller_status",
    "result_error_code",
    "result_error_string",
    "command_latency_ms",
    "controller_execution_seconds",
    "proxy_total_seconds",
    "attack_status_start_published",
    "attack_status_stop_published",
    "log_status",
    "log_error",
]


def timestamp() -> str:
    # Return a timezone-aware local timestamp.

    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def duration_to_seconds(duration: Any) -> float:
    # Convert a builtin_interfaces/Duration message to seconds.

    return float(duration.sec) + float(duration.nanosec) / 1_000_000_000.0


def number_list(values: Sequence[Any]) -> list[float]:
    # Convert a ROS numeric sequence into ordinary Python floats.

    return [float(value) for value in values]


def point_to_dictionary(point: Any) -> dict[str, Any]:
    # Convert one JointTrajectoryPoint into JSON-serialisable data.

    return {
        "positions": number_list(point.positions),
        "velocities": number_list(point.velocities),
        "accelerations": number_list(point.accelerations),
        "effort": number_list(point.effort),
        "time_from_start_seconds": duration_to_seconds(point.time_from_start),
    }


def trajectory_to_dictionary(trajectory: Any) -> dict[str, Any]:
    # Convert a JointTrajectory message into JSON-serialisable data.

    return {
        "header_frame_id": trajectory.header.frame_id,
        "header_stamp_seconds": (
            float(trajectory.header.stamp.sec)
            + float(trajectory.header.stamp.nanosec) / 1_000_000_000.0
        ),
        "joint_names": list(trajectory.joint_names),
        "points": [point_to_dictionary(point) for point in trajectory.points],
    }


def trajectory_duration_seconds(trajectory: Any) -> float:
    # Return the final trajectory point's time-from-start value.

    if not trajectory.points:
        return 0.0
    return duration_to_seconds(trajectory.points[-1].time_from_start)


def compact_json(value: Any) -> str:
    # Encode a value using stable compact JSON.

    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def normalise_label(value: Any) -> str:
    # Return a lowercase underscore-separated label.

    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def clean_text(value: Any, default: str = "") -> str:
    # Convert a context value to stripped text, using a fallback if empty.

    return str(value if value is not None else "").strip() or default


def parse_delay_milliseconds(raw_value: Any, raw_unit: Any) -> float:
    # Parse a finite positive delay and convert it to milliseconds.

    try:
        value = float(str(raw_value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Delay-DoS attack_parameter_value must be numeric."
        ) from exc

    if not math.isfinite(value):
        raise ValueError("Delay-DoS duration must be finite.")

    unit = normalise_label(raw_unit)
    if unit in {"ms", "millisecond", "milliseconds"}:
        delay_ms = value
    elif unit in {"s", "sec", "second", "seconds"}:
        delay_ms = value * 1000.0
    else:
        raise ValueError(
            "Delay-DoS attack_parameter_unit must be ms/milliseconds "
            "or s/seconds."
        )

    if delay_ms <= 0.0:
        raise ValueError("Delay-DoS duration must be greater than zero.")
    return delay_ms


@dataclass(frozen=True)
class DelayPlan:
    # Decision made for one incoming trajectory command.

    proxy_mode: str
    delay_ms: float = 0.0

    @property
    def should_delay(self) -> bool:
        return self.proxy_mode == PROXY_MODE_DELAY_APPLIED


class CommandTraceWriter:
    # Thread-safe append-only CSV writer.

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path.expanduser().resolve()
        self._lock = threading.Lock()
        self._file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None
        self._open()

    def _open(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)

        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            with self.csv_path.open(
                "r", newline="", encoding="utf-8"
            ) as existing_file:
                header = next(csv.reader(existing_file), [])

            if header != CSV_FIELDS:
                raise RuntimeError(
                    "The existing command trace has an incompatible header:\n"
                    f"{self.csv_path}\n"
                    f"Expected: {CSV_FIELDS}\n"
                    f"Found:    {header}"
                )

        self._file = self.csv_path.open(
            "a", newline="", encoding="utf-8", buffering=1
        )
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_FIELDS)

        if self.csv_path.stat().st_size == 0:
            self._writer.writeheader()
            self._file.flush()

    def append(self, row: dict[str, Any]) -> None:
        with self._lock:
            if self._writer is None or self._file is None:
                raise RuntimeError("The command trace writer is closed.")

            complete_row = {field: row.get(field, "") for field in CSV_FIELDS}
            self._writer.writerow(complete_row)
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()
                self._file.close()
            self._file = None
            self._writer = None


class ArmDelayDosProxy(Node):
    # Transparent proxy that can delay one legitimate command per run.

    def __init__(
        self,
        *,
        proxy_action: str,
        controller_action: str,
        context_topic: str,
        attack_status_topic: str,
        command_trace_csv: Path,
        maximum_delay_milliseconds: float,
        maximum_delays_per_run: int,
    ) -> None:
        super().__init__("sentinel_arm_delay_dos_proxy")

        self.proxy_action = proxy_action
        self.controller_action = controller_action
        self.context_topic = context_topic
        self.attack_status_topic = attack_status_topic
        self.max_delay_ms = float(maximum_delay_milliseconds)
        self.max_delays_per_run = int(maximum_delays_per_run)

        if not math.isfinite(self.max_delay_ms) or self.max_delay_ms <= 0.0:
            raise ValueError("maximum_delay_milliseconds must be positive.")
        if self.max_delays_per_run <= 0:
            raise ValueError("maximum_delays_per_run must be positive.")

        self._callback_group = ReentrantCallbackGroup()
        self._trace_writer = CommandTraceWriter(command_trace_csv)

        self._experiment_context_lock = threading.RLock()
        self._experiment_context = self._empty_context()

        self._sequence_lock = threading.Lock()
        self._command_sequence_index = 0

        self._delay_count_lock = threading.Lock()
        self._delay_counts_by_run: dict[str, int] = {}

        context_qos = QoSProfile(depth=50)
        context_qos.reliability = ReliabilityPolicy.RELIABLE

        self._context_subscription = self.create_subscription(
            String,
            self.context_topic,
            self._context_callback,
            context_qos,
            callback_group=self._callback_group,
        )

        self._attack_status_publisher = self.create_publisher(
            String,
            self.attack_status_topic,
            context_qos,
            callback_group=self._callback_group,
        )

        self._controller_client = ActionClient(
            self,
            FollowJointTrajectory,
            self.controller_action,
            callback_group=self._callback_group,
        )

        self._proxy_server = ActionServer(
            self,
            FollowJointTrajectory,
            self.proxy_action,
            execute_callback=self._execute_callback,
            goal_callback=self._goal_callback,
            cancel_callback=self._cancel_callback,
            callback_group=self._callback_group,
        )

        self.get_logger().info("Delay-based DoS arm proxy created.")
        self.get_logger().info(f"Task-facing action: {self.proxy_action}")
        self.get_logger().info(
            f"Real controller action: {self.controller_action}"
        )
        self.get_logger().info(
            f"Experiment context topic: {self.context_topic}"
        )
        self.get_logger().info(
            f"Attack status topic: {self.attack_status_topic}"
        )
        self.get_logger().info(
            f"Command trace: {self._trace_writer.csv_path}"
        )
        self.get_logger().info(
            "Proxy modes: normal passthrough and controlled pre-forward "
            "command delay."
        )
        self.get_logger().info("Delay-DoS variant: command_delay")
        self.get_logger().info(
            "Maximum artificial delay: "
            f"{self.max_delay_ms:.3f} ms"
        )
        self.get_logger().info(
            "Maximum delayed commands per run: "
            f"{self.max_delays_per_run}"
        )

    @staticmethod
    def _empty_context() -> dict[str, Any]:
        context: dict[str, Any] = dict(CONTEXT_DEFAULTS)
        context.update(
            {
                "run_id": "",
                "attack_active": 0,
                "received_at": "",
                "received_monotonic": 0.0,
            }
        )
        return context

    def wait_for_controller(self, timeout_seconds: float = 30.0) -> bool:
        # Wait until the real trajectory controller is available.

        self.get_logger().info(
            "Waiting for the real UR5e trajectory controller..."
        )
        available = self._controller_client.wait_for_server(
            timeout_sec=timeout_seconds
        )

        if available:
            self.get_logger().info(
                "Real trajectory controller is available."
            )
        else:
            self.get_logger().error(
                "Real trajectory controller was not available within "
                f"{timeout_seconds:.1f} seconds."
            )
        return available

    def destroy_node(self) -> bool:
        # Close files and destroy ROS action entities.

        try:
            self._proxy_server.destroy()
        except Exception:
            pass
        try:
            self._controller_client.destroy()
        except Exception:
            pass
        self._trace_writer.close()
        return super().destroy_node()

    def _context_callback(self, message: String) -> None:
        # Store the newest run and pose context from a task script.

        try:
            payload = json.loads(message.data)
        except json.JSONDecodeError as exc:
            self.get_logger().error(
                f"Invalid experiment-context JSON: {exc}"
            )
            return

        if not isinstance(payload, dict):
            self.get_logger().error(
                "Experiment context must be a JSON object."
            )
            return

        context = {
            key: clean_text(payload.get(key), default)
            for key, default in CONTEXT_DEFAULTS.items()
        }

        session_id = context["session_id"]
        run_id = payload.get("run_id", "")
        run_key = context["run_key"]
        if not run_key and session_id and str(run_id).strip():
            run_key = f"{session_id}:{run_id}"

        context.update(
            {
                "run_key": run_key,
                "run_id": run_id,
                "attack_active": int(bool(payload.get("attack_active", 0))),
                "received_at": timestamp(),
                "received_monotonic": time.monotonic(),
            }
        )

        with self._experiment_context_lock:
            self._experiment_context = context

    def _publish_attack_status(self, payload: dict[str, Any]) -> None:
        message = String()
        message.data = compact_json(payload)
        self._attack_status_publisher.publish(message)

    def publish_attack_start(
        self,
        *,
        context: dict[str, Any],
        command_id: str,
        attack_event_id: str = "",
    ) -> str:
        # Publish a standard attack-start event and return its ID.

        event_id = attack_event_id or (
            f"{context.get('session_id', 'session')}_"
            f"{context.get('run_id', 'run')}_"
            f"{uuid.uuid4().hex[:10]}"
        )

        self._publish_attack_status(
            {
                "action": "start",
                "active": True,
                "session_id": context.get("session_id", ""),
                "run_id": context.get("run_id", ""),
                "run_key": context.get("run_key", ""),
                "attack_event_id": event_id,
                "attack_type": context.get("attack_type", "none"),
                "attack_variant": context.get("attack_variant", "none"),
                "attack_severity": context.get("attack_severity", "none"),
                "attack_target": context.get("attack_target", "none"),
                "attack_target_object": context.get(
                    "attack_target_object", "none"
                ),
                "attack_target_phase": context.get(
                    "attack_target_phase", "none"
                ),
                "attack_parameter_value": context.get(
                    "attack_parameter_value", ""
                ),
                "attack_parameter_unit": context.get(
                    "attack_parameter_unit", ""
                ),
                "source": "arm_delay_dos_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )
        return event_id

    def publish_attack_stop(
        self,
        *,
        context: dict[str, Any],
        attack_event_id: str,
        command_id: str,
        end_reason: str,
    ) -> None:
        # Publish a standard attack-stop event.

        self._publish_attack_status(
            {
                "action": "stop",
                "active": False,
                "session_id": context.get("session_id", ""),
                "run_id": context.get("run_id", ""),
                "run_key": context.get("run_key", ""),
                "attack_event_id": attack_event_id,
                "end_reason": end_reason,
                "source": "arm_delay_dos_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )

    def _delay_requested(self, context: dict[str, Any]) -> bool:
        return (
            normalise_label(context.get("attack_type"))
            in DELAY_DOS_ATTACK_TYPES
        )

    @staticmethod
    def _phase_matches(requested_phase: Any, current_phase: Any) -> bool:
        requested = normalise_label(requested_phase)
        current = normalise_label(current_phase)

        if requested in {"*", "all", "any"}:
            return bool(current)
        return bool(requested) and requested == current

    def _reserve_delay_for_run(self, run_key: str) -> bool:
        if not run_key:
            return False

        with self._delay_count_lock:
            current = self._delay_counts_by_run.get(run_key, 0)
            if current >= self.max_delays_per_run:
                return False
            self._delay_counts_by_run[run_key] = current + 1
            return True

    def _prepare_delay_plan(
        self,
        *,
        context: dict[str, Any],
    ) -> DelayPlan:
        # Validate and reserve a delay when this command is the target.

        if not self._delay_requested(context):
            return DelayPlan(PROXY_MODE_NORMAL)

        run_key = str(context.get("run_key", "")).strip()
        if not run_key:
            return DelayPlan(PROXY_MODE_DELAY_ARMED)

        target_phase = context.get("attack_target_phase", "")
        if normalise_label(target_phase) in {"", "none"}:
            raise ValueError(
                "Delay-DoS attack_target_phase must identify a task phase."
            )

        if not self._phase_matches(
            target_phase, context.get("task_phase", "")
        ):
            return DelayPlan(PROXY_MODE_DELAY_ARMED)

        variant = normalise_label(context.get("attack_variant", ""))
        if variant not in DELAY_DOS_VARIANTS:
            raise ValueError(
                "Unsupported Delay-DoS attack_variant. Use command_delay."
            )

        delay_ms = parse_delay_milliseconds(
            context.get("attack_parameter_value", ""),
            context.get("attack_parameter_unit", ""),
        )

        if delay_ms > self.max_delay_ms:
            raise ValueError(
                "Requested Delay-DoS duration exceeds the configured "
                "safety limit of "
                f"{self.max_delay_ms:.3f} ms."
            )

        if not self._reserve_delay_for_run(run_key):
            return DelayPlan(PROXY_MODE_DELAY_ARMED)

        return DelayPlan(PROXY_MODE_DELAY_APPLIED, delay_ms)

    def _goal_callback(
        self, goal_request: FollowJointTrajectory.Goal
    ) -> GoalResponse:
        if not goal_request.trajectory.joint_names:
            self.get_logger().error("Rejected trajectory with no joint names.")
            return GoalResponse.REJECT
        if not goal_request.trajectory.points:
            self.get_logger().error("Rejected trajectory with no points.")
            return GoalResponse.REJECT
        if not self._controller_client.server_is_ready():
            self.get_logger().error(
                "Rejected trajectory because the real controller is "
                "unavailable."
            )
            return GoalResponse.REJECT
        return GoalResponse.ACCEPT

    def _cancel_callback(self, goal_handle: Any) -> CancelResponse:
        del goal_handle
        self.get_logger().warning(
            "A cancellation request was rejected by the Delay-DoS proxy."
        )
        return CancelResponse.REJECT

    def _next_sequence_index(self) -> int:
        with self._sequence_lock:
            index = self._command_sequence_index
            self._command_sequence_index += 1
            return index

    def _context_snapshot(self) -> dict[str, Any]:
        with self._experiment_context_lock:
            snapshot = dict(self._experiment_context)

        received_monotonic = float(
            snapshot.pop("received_monotonic", 0.0) or 0.0
        )
        if received_monotonic > 0.0:
            context_age: float | str = time.monotonic() - received_monotonic
        else:
            context_age = ""
        snapshot["context_age_seconds"] = context_age
        return snapshot

    def _wait_for_fresh_command_context(
        self,
        *,
        timeout_seconds: float = 1.0,
        maximum_age_seconds: float = 0.25,
    ) -> tuple[dict[str, Any], bool]:
        # Wait for the pose-specific context belonging to a new goal.

        deadline = time.monotonic() + timeout_seconds
        latest = self._context_snapshot()

        while time.monotonic() < deadline:
            latest = self._context_snapshot()
            pose_name = str(latest.get("pose_name", "")).strip()
            context_age = latest.get("context_age_seconds", "")
            try:
                context_age_value = float(context_age)
            except (TypeError, ValueError):
                context_age_value = float("inf")

            if pose_name and context_age_value <= maximum_age_seconds:
                return latest, True
            time.sleep(0.005)

        return latest, False

    def _base_row(
        self,
        *,
        command_id: str,
        sequence_index: int,
        proxy_mode: str,
        context: dict[str, Any],
        received_at: str,
        original_goal: FollowJointTrajectory.Goal,
    ) -> dict[str, Any]:
        trajectory = original_goal.trajectory
        trajectory_json = compact_json(trajectory_to_dictionary(trajectory))
        duration_seconds = trajectory_duration_seconds(trajectory)

        return {
            "schema_version": SCHEMA_VERSION,
            "command_id": command_id,
            "command_sequence_index": sequence_index,
            "proxy_mode": proxy_mode,
            "session_id": context.get("session_id", ""),
            "run_key": context.get("run_key", ""),
            "run_id": context.get("run_id", ""),
            "task_type": context.get("task_type", ""),
            "condition": context.get("condition", ""),
            "attack_type": context.get("attack_type", "none"),
            "attack_variant": context.get("attack_variant", "none"),
            "attack_severity": context.get("attack_severity", "none"),
            "attack_target": context.get("attack_target", "none"),
            "attack_target_object": context.get(
                "attack_target_object", "none"
            ),
            "attack_target_phase": context.get(
                "attack_target_phase", "none"
            ),
            "attack_parameter_value": context.get(
                "attack_parameter_value", ""
            ),
            "attack_parameter_unit": context.get(
                "attack_parameter_unit", ""
            ),
            "attack_event_id": context.get("attack_event_id", ""),
            "attack_active": 0,
            "task_phase": context.get("task_phase", "unassigned"),
            "pose_name": context.get("pose_name", ""),
            "context_received_at": context.get("received_at", ""),
            "context_age_seconds": context.get(
                "context_age_seconds", ""
            ),
            "received_at": received_at,
            "forwarded_at": "",
            "controller_accepted_at": "",
            "completed_at": "",
            "proxy_action": self.proxy_action,
            "controller_action": self.controller_action,
            "joint_names_json": compact_json(list(trajectory.joint_names)),
            "original_trajectory_json": trajectory_json,
            "forwarded_trajectory_json": trajectory_json,
            "original_duration_seconds": f"{duration_seconds:.9f}",
            "forwarded_duration_seconds": f"{duration_seconds:.9f}",
            "command_modified": 0,
            "command_injected": 0,
            "command_replayed": 0,
            "command_delayed": 0,
            "command_dropped": 0,
            "attack_applied": 0,
            "modified_joint_names_json": "[]",
            "joint_offsets_json": "{}",
            "delay_applied_ms": "0.000000",
            "source_command_id": "",
            "source_run_key": "",
            "drop_reason": "",
            "controller_goal_accepted": 0,
            "controller_status": "",
            "result_error_code": "",
            "result_error_string": "",
            "command_latency_ms": "",
            "controller_execution_seconds": "",
            "proxy_total_seconds": "",
            "attack_status_start_published": 0,
            "attack_status_stop_published": 0,
            "log_status": "started",
            "log_error": "",
        }

    async def _send_controller_goal(
        self,
        *,
        goal: FollowJointTrajectory.Goal,
        row: dict[str, Any],
        timing_origin: float,
        feedback_callback: Any = None,
    ) -> tuple[FollowJointTrajectory.Result, int]:
        # Send one controller command and populate timing/result columns.

        forwarded_monotonic = time.monotonic()
        row["forwarded_at"] = timestamp()
        row["command_latency_ms"] = (
            f"{(forwarded_monotonic - timing_origin) * 1000.0:.6f}"
        )

        send_future = self._controller_client.send_goal_async(
            goal, feedback_callback=feedback_callback
        )
        controller_goal_handle = await send_future
        row["controller_accepted_at"] = timestamp()

        if (
            controller_goal_handle is None
            or not controller_goal_handle.accepted
        ):
            raise RuntimeError(
                "The real trajectory controller rejected the goal."
            )

        row["controller_goal_accepted"] = 1
        controller_execution_started = time.monotonic()
        wrapped_result = await controller_goal_handle.get_result_async()
        controller_execution_finished = time.monotonic()

        result = wrapped_result.result
        status = int(wrapped_result.status)

        row["completed_at"] = timestamp()
        row["controller_status"] = status
        row["result_error_code"] = int(result.error_code)
        row["result_error_string"] = result.error_string
        row["controller_execution_seconds"] = (
            f"{controller_execution_finished - controller_execution_started:.9f}"
        )
        row["proxy_total_seconds"] = (
            f"{controller_execution_finished - timing_origin:.9f}"
        )

        if status == GoalStatus.STATUS_SUCCEEDED:
            row["log_status"] = "succeeded"
        elif status == GoalStatus.STATUS_CANCELED:
            row["log_status"] = "controller_canceled"
        else:
            row["log_status"] = "controller_failed"

        return result, status

    @staticmethod
    def _error_result(message: str) -> FollowJointTrajectory.Result:
        result = FollowJointTrajectory.Result()
        result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
        result.error_string = message
        return result

    def _abort_command(
        self,
        *,
        goal_handle: Any,
        row: dict[str, Any],
        started_at: float,
        status: str,
        message: str,
    ) -> FollowJointTrajectory.Result:
        # Log a command error and abort the task-facing goal.

        row.update(
            {
                "completed_at": timestamp(),
                "proxy_total_seconds": (
                    f"{time.monotonic() - started_at:.9f}"
                ),
                "log_status": status,
                "log_error": message,
            }
        )
        self._trace_writer.append(row)
        self.get_logger().error(message)
        goal_handle.abort()
        return self._error_result(message)

    def _apply_delay(
        self,
        *,
        context: dict[str, Any],
        command_id: str,
        row: dict[str, Any],
        delay_ms: float,
    ) -> None:
        # Publish the attack window and wait before forwarding the command.

        row.update(
            {
                "attack_active": 1,
                "command_delayed": 1,
                "attack_applied": 1,
                "delay_applied_ms": f"{delay_ms:.6f}",
            }
        )

        event_id = self.publish_attack_start(
            context=context,
            command_id=command_id,
            attack_event_id=clean_text(context.get("attack_event_id")),
        )
        row["attack_event_id"] = event_id
        row["attack_status_start_published"] = 1

        self.get_logger().warning(
            "DELAY-BASED DOS applied: "
            f"run={row['run_key']}, "
            f"phase={row['task_phase']}, "
            f"delay={delay_ms:.3f} ms, "
            f"command={command_id[:8]}"
        )

        delay_started = time.monotonic()
        try:
            time.sleep(delay_ms / 1000.0)
        finally:
            self.publish_attack_stop(
                context=context,
                attack_event_id=event_id,
                command_id=command_id,
                end_reason="delay_elapsed_before_forwarding",
            )
            row["attack_status_stop_published"] = 1

        measured_delay_ms = (time.monotonic() - delay_started) * 1000.0
        self.get_logger().info(
            "Delay elapsed; forwarding the legitimate command unchanged "
            f"after {measured_delay_ms:.3f} ms."
        )

    @staticmethod
    def _finish_goal(goal_handle: Any, status: int) -> None:
        if status == GoalStatus.STATUS_SUCCEEDED:
            goal_handle.succeed()
        elif status == GoalStatus.STATUS_CANCELED:
            goal_handle.canceled()
        else:
            goal_handle.abort()

    async def _execute_callback(
        self, proxy_goal_handle: Any
    ) -> FollowJointTrajectory.Result:
        # Optionally delay one command, then forward it unchanged.

        command_id = uuid.uuid4().hex
        sequence_index = self._next_sequence_index()
        received_monotonic = time.monotonic()
        received_at = timestamp()

        context, context_is_valid = self._wait_for_fresh_command_context()
        original_goal = copy.deepcopy(proxy_goal_handle.request)

        default_mode = (
            PROXY_MODE_DELAY_ARMED
            if self._delay_requested(context)
            else PROXY_MODE_NORMAL
        )
        delay_plan = DelayPlan(default_mode)
        configuration_error = ""
        if context_is_valid:
            try:
                delay_plan = self._prepare_delay_plan(context=context)
            except ValueError as exc:
                configuration_error = str(exc)

        row = self._base_row(
            command_id=command_id,
            sequence_index=sequence_index,
            proxy_mode=delay_plan.proxy_mode,
            context=context,
            received_at=received_at,
            original_goal=original_goal,
        )

        self.get_logger().info(
            f"Command {sequence_index} received ({command_id[:8]}): "
            f"phase={row['task_phase']}, "
            f"pose={row['pose_name'] or 'unassigned'}, "
            f"mode={row['proxy_mode']}"
        )

        if not context_is_valid:
            message = (
                "A fresh pose-specific experiment context was not received "
                "before the trajectory goal."
            )
            return self._abort_command(
                goal_handle=proxy_goal_handle,
                row=row,
                started_at=received_monotonic,
                status="context_error",
                message=message,
            )

        if configuration_error:
            return self._abort_command(
                goal_handle=proxy_goal_handle,
                row=row,
                started_at=received_monotonic,
                status="attack_configuration_error",
                message=configuration_error,
            )

        try:
            if delay_plan.should_delay:
                self._apply_delay(
                    context=context,
                    command_id=command_id,
                    row=row,
                    delay_ms=delay_plan.delay_ms,
                )

            def forward_feedback(feedback_message: Any) -> None:
                proxy_goal_handle.publish_feedback(feedback_message.feedback)

            result, status = await self._send_controller_goal(
                goal=original_goal,
                row=row,
                timing_origin=received_monotonic,
                feedback_callback=forward_feedback,
            )

            self._trace_writer.append(row)
            self._finish_goal(proxy_goal_handle, status)

            self.get_logger().info(
                f"Command {sequence_index} completed: "
                f"status={row['log_status']}, "
                f"error_code={row['result_error_code']}, "
                f"delay_applied={int(delay_plan.should_delay)}"
            )
            return result

        except Exception as exc:
            row["completed_at"] = timestamp()
            row["proxy_total_seconds"] = (
                f"{time.monotonic() - received_monotonic:.9f}"
            )
            row["log_status"] = "proxy_exception"
            row["log_error"] = str(exc)

            try:
                self._trace_writer.append(row)
            except Exception as logging_exc:
                self.get_logger().error(
                    "The failed delayed command could not be logged: "
                    f"{logging_exc}"
                )

            self.get_logger().error(
                f"Delayed command failed in the proxy: {exc}"
            )
            proxy_goal_handle.abort()
            return self._error_result(str(exc))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Sentinel Arm controlled delay-based DoS proxy."
        )
    )
    parser.add_argument(
        "--proxy-action",
        default=DEFAULT_PROXY_ACTION,
        help=f"Action exposed to task scripts. Default: {DEFAULT_PROXY_ACTION}",
    )
    parser.add_argument(
        "--controller-action",
        default=DEFAULT_CONTROLLER_ACTION,
        help=(
            "Real controller action used by the proxy. "
            f"Default: {DEFAULT_CONTROLLER_ACTION}"
        ),
    )
    parser.add_argument(
        "--context-topic",
        default=DEFAULT_CONTEXT_TOPIC,
        help=(
            "JSON experiment-context topic. "
            f"Default: {DEFAULT_CONTEXT_TOPIC}"
        ),
    )
    parser.add_argument(
        "--attack-status-topic",
        default=DEFAULT_ATTACK_STATUS_TOPIC,
        help=(
            "JSON attack ground-truth topic. "
            f"Default: {DEFAULT_ATTACK_STATUS_TOPIC}"
        ),
    )
    parser.add_argument(
        "--command-trace-csv",
        type=Path,
        default=Path.cwd() / "data" / "command_trace.csv",
        help=(
            "Output path for command_trace.csv. "
            "Default: data/command_trace.csv"
        ),
    )
    parser.add_argument(
        "--maximum-delay-milliseconds",
        type=float,
        default=DEFAULT_MAXIMUM_DELAY_MILLISECONDS,
        help=(
            "Safety limit for one artificial command delay. "
            f"Default: {DEFAULT_MAXIMUM_DELAY_MILLISECONDS} ms."
        ),
    )
    parser.add_argument(
        "--maximum-delays-per-run",
        type=int,
        default=DEFAULT_MAXIMUM_DELAYS_PER_RUN,
        help=(
            "Maximum number of legitimate commands delayed in one run. "
            f"Default: {DEFAULT_MAXIMUM_DELAYS_PER_RUN}."
        ),
    )

    arguments_without_ros = remove_ros_args()[1:]
    return parser.parse_args(arguments_without_ros)


def main(args: Sequence[str] | None = None) -> None:
    rclpy.init(args=args)
    arguments = parse_arguments()

    node = ArmDelayDosProxy(
        proxy_action=arguments.proxy_action,
        controller_action=arguments.controller_action,
        context_topic=arguments.context_topic,
        attack_status_topic=arguments.attack_status_topic,
        command_trace_csv=arguments.command_trace_csv,
        maximum_delay_milliseconds=(
            arguments.maximum_delay_milliseconds
        ),
        maximum_delays_per_run=arguments.maximum_delays_per_run,
    )

    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(node)

    try:
        if not node.wait_for_controller(timeout_seconds=30.0):
            raise SystemExit(1)

        node.get_logger().info(
            "Delay-based DoS proxy is ready. Keep this terminal running."
        )
        executor.spin()

    except KeyboardInterrupt:
        node.get_logger().info("Delay-based DoS proxy stopped by the user.")

    except Exception as exc:
        node.get_logger().error(
            f"Delay-based DoS proxy terminated unexpectedly: {exc}"
        )
        raise SystemExit(1) from None

    finally:
        executor.shutdown()
        executor.remove_node(node)
        node.destroy_node()

        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
