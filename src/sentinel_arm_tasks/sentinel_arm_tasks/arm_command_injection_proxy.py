#!/usr/bin/env python3

# ROS 2 action proxy that can insert one bounded joint-offset trajectory before
# forwarding the legitimate UR5e command unchanged.

from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import threading
import time
import uuid
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

# Labels distinguish normal forwarding, an armed attack and an injected command.
PROXY_MODE_NORMAL = "normal_passthrough"
PROXY_MODE_INJECTION_ARMED = "command_injection_armed"
PROXY_MODE_INJECTION_TRIGGER = "command_injection_trigger"
PROXY_MODE_INJECTED = "command_injection"

COMMAND_INJECTION_ATTACK_TYPES = {
    "command_injection",
    "trajectory_command_injection",
    "unauthorised_command_injection",
    "unauthorized_command_injection",
}

COMMAND_INJECTION_VARIANTS = {
    "pre_command_joint_offset",
    "joint_offset_pre_command",
    "pre_command_offset",
}

# Safety limits constrain the offset size and number of injections in each run.
DEFAULT_MAXIMUM_ABSOLUTE_OFFSET_RADIANS = 0.25
DEFAULT_MAXIMUM_INJECTIONS_PER_RUN = 1

DEFAULT_PROXY_ACTION = "/sentinel/arm_proxy/follow_joint_trajectory"
DEFAULT_CONTROLLER_ACTION = (
    "/scaled_joint_trajectory_controller/follow_joint_trajectory"
)
DEFAULT_CONTEXT_TOPIC = "/sentinel/experiment/context"
DEFAULT_ATTACK_STATUS_TOPIC = "/sentinel/attack/status"


# Fixed column order shared with the downstream feature-preparation pipeline.
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


# Create consistent millisecond-resolution timestamps for context and trace rows.
def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


# Convert a ROS duration message into one floating-point seconds value.
def duration_to_seconds(duration: Any) -> float:
    return float(duration.sec) + float(duration.nanosec) / 1_000_000_000.0


# Convert ROS numeric sequences to JSON-serialisable Python floats.
def float_list(values: Sequence[Any]) -> list[float]:
    return [float(value) for value in values]


# Serialise one trajectory point while preserving its timing and motion fields.
def point_to_dict(point: Any) -> dict[str, Any]:
    return {
        "positions": float_list(point.positions),
        "velocities": float_list(point.velocities),
        "accelerations": float_list(point.accelerations),
        "effort": float_list(point.effort),
        "time_from_start_seconds": duration_to_seconds(point.time_from_start),
    }


# Convert a complete trajectory into the structure stored in command_trace.csv.
def trajectory_to_dict(trajectory: Any) -> dict[str, Any]:
    return {
        "header_frame_id": trajectory.header.frame_id,
        "header_stamp_seconds": (
            float(trajectory.header.stamp.sec)
            + float(trajectory.header.stamp.nanosec) / 1_000_000_000.0
        ),
        "joint_names": list(trajectory.joint_names),
        "points": [point_to_dict(point) for point in trajectory.points],
    }


# Read total planned duration from the final trajectory point.
def trajectory_duration_seconds(trajectory: Any) -> float:
    if not trajectory.points:
        return 0.0
    return duration_to_seconds(trajectory.points[-1].time_from_start)


# Produce deterministic compact JSON for stable CSV values.
def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# Normalise experiment labels before comparing attack types, variants and phases.
def clean_label(value: Any) -> str:
    return (
        str(value or "")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


# Parse the configured offset and convert degree values to radians.
def parse_offset_radians(raw_value: Any, raw_unit: Any) -> float:
    try:
        offset = float(str(raw_value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Command-injection attack_parameter_value must be numeric."
        ) from exc

    if not math.isfinite(offset):
        raise ValueError("Command-injection joint offset must be finite.")

    unit = clean_label(raw_unit)
    if unit in {"rad", "radian", "radians"}:
        return offset
    if unit in {"deg", "degree", "degrees"}:
        return math.radians(offset)

    raise ValueError(
        "Command-injection attack_parameter_unit must be rad/radians "
        "or deg/degrees."
    )


def context_text(
    payload: dict[str, Any], key: str, default: str = ""
) -> str:
    # Read and tidy a text value from the experiment context.

    value = str(payload.get(key, default)).strip()
    return value or default


# Append command records safely when several ROS callbacks run concurrently.
class CommandTraceWriter:

    # Resolve the trace path and open the append-only writer.
    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path.expanduser().resolve()
        self._lock = threading.Lock()
        self._file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None
        self._open()

    # Validate an existing header before appending new trace rows.
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

    # Fill absent optional fields and flush each completed row immediately.
    def append(self, row: dict[str, Any]) -> None:
        with self._lock:
            if self._writer is None or self._file is None:
                raise RuntimeError("The command trace writer is closed.")

            complete_row = {field: row.get(field, "") for field in CSV_FIELDS}
            self._writer.writerow(complete_row)
            self._file.flush()

    # Release the CSV handle during normal or exceptional node shutdown.
    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()
                self._file.close()
            self._file = None
            self._writer = None


# Expose a task-facing action server and forward accepted goals to the real
# trajectory controller, optionally executing a controlled injected goal first.
class ArmCommandInjectionProxy(Node):
    # Configure shared state, ROS interfaces and per-run safety counters.
    def __init__(
        self,
        *,
        proxy_action: str,
        controller_action: str,
        context_topic: str,
        attack_status_topic: str,
        command_trace_csv: Path,
        max_offset_radians: float,
        max_injections_per_run: int,
    ) -> None:
        super().__init__("sentinel_arm_command_injection_proxy")

        self.proxy_action = proxy_action
        self.controller_action = controller_action
        self.context_topic = context_topic
        self.attack_status_topic = attack_status_topic
        self._max_offset_radians = float(max_offset_radians)
        self._max_injections_per_run = int(max_injections_per_run)

        # Reject unsafe configuration before accepting any action goals.
        if self._max_offset_radians <= 0.0:
            raise ValueError(
                "maximum_absolute_offset_radians must be positive."
            )
        if self._max_injections_per_run <= 0:
            raise ValueError("maximum_injections_per_run must be positive.")

        self._callback_group = ReentrantCallbackGroup()
        self._trace_writer = CommandTraceWriter(command_trace_csv)

        # Protect the most recent experiment context from concurrent callbacks.
        self._experiment_context_lock = threading.RLock()
        self._experiment_context: dict[str, Any] = {
            "session_id": "",
            "run_key": "",
            "run_id": "",
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
            "attack_active": 0,
            "task_phase": "unassigned",
            "pose_name": "",
            "received_at": "",
            "received_monotonic": 0.0,
        }

        self._sequence_lock = threading.Lock()
        self._command_sequence_index = 0

        # Count successful reservations so the configured run limit is enforced.
        self._injection_count_lock = threading.Lock()
        self._injection_counts_by_run: dict[str, int] = {}

        context_qos = QoSProfile(depth=50)
        context_qos.reliability = ReliabilityPolicy.RELIABLE

        # Receive task/run metadata used to decide whether an attack should fire.
        self._context_subscription = self.create_subscription(
            String,
            self.context_topic,
            self._context_callback,
            context_qos,
            callback_group=self._callback_group,
        )

        # Publish exact attack start and stop boundaries for ground-truth logging.
        self._attack_status_publisher = self.create_publisher(
            String,
            self.attack_status_topic,
            context_qos,
            callback_group=self._callback_group,
        )

        # Forward trajectories through a client connected to the real controller.
        self._controller_client = ActionClient(
            self,
            FollowJointTrajectory,
            self.controller_action,
            callback_group=self._callback_group,
        )

        # Present the proxy action endpoint used by autonomous task scripts.
        self._proxy_server = ActionServer(
            self,
            FollowJointTrajectory,
            self.proxy_action,
            execute_callback=self._execute_callback,
            goal_callback=self._goal_callback,
            cancel_callback=self._cancel_callback,
            callback_group=self._callback_group,
        )

        logger = self.get_logger()
        logger.info("Command-injection arm proxy created.")
        logger.info(f"Task-facing action: {self.proxy_action}")
        logger.info(f"Real controller action: {self.controller_action}")
        logger.info(f"Experiment context topic: {self.context_topic}")
        logger.info(f"Attack status topic: {self.attack_status_topic}")
        logger.info(f"Command trace: {self._trace_writer.csv_path}")
        logger.info(
            "Proxy modes: normal passthrough and controlled pre-command "
            "trajectory injection."
        )
        logger.info("Command-injection variant: pre_command_joint_offset")
        logger.info(
            "Maximum absolute injection offset: "
            f"{self._max_offset_radians:.3f} rad"
        )
        logger.info(
            "Maximum injected commands per run: "
            f"{self._max_injections_per_run}"
        )

    # Wait for the controller action server before announcing proxy readiness.
    def wait_for_controller(self, timeout_seconds: float = 30.0) -> bool:
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

    # Close ROS action entities and the trace file during node destruction.
    def destroy_node(self) -> bool:
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

    # Validate and store the latest JSON experiment context atomically.
    def _context_callback(self, message: String) -> None:
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

        session_id = context_text(payload, "session_id")
        run_id = payload.get("run_id", "")
        run_key = context_text(payload, "run_key")
        if not run_key and session_id and str(run_id).strip():
            run_key = f"{session_id}:{run_id}"

        received_at = timestamp()
        received_monotonic = time.monotonic()

        # Keep one snapshot so the goal callback cannot read half an update.
        with self._experiment_context_lock:
            self._experiment_context = {
                "session_id": session_id,
                "run_key": run_key,
                "run_id": run_id,
                "task_type": context_text(payload, "task_type"),
                "condition": context_text(payload, "condition"),
                "attack_type": context_text(payload, "attack_type", "none"),
                "attack_variant": context_text(
                    payload, "attack_variant", "none"
                ),
                "attack_severity": context_text(
                    payload, "attack_severity", "none"
                ),
                "attack_target": context_text(
                    payload, "attack_target", "none"
                ),
                "attack_target_object": context_text(
                    payload, "attack_target_object", "none"
                ),
                "attack_target_phase": context_text(
                    payload, "attack_target_phase", "none"
                ),
                "attack_parameter_value": context_text(
                    payload, "attack_parameter_value"
                ),
                "attack_parameter_unit": context_text(
                    payload, "attack_parameter_unit"
                ),
                "attack_event_id": context_text(payload, "attack_event_id"),
                "attack_active": int(bool(payload.get("attack_active", 0))),
                "task_phase": context_text(
                    payload, "task_phase", "unassigned"
                ),
                "pose_name": context_text(payload, "pose_name"),
                "received_at": received_at,
                "received_monotonic": received_monotonic,
            }

    # Encode and publish one attack-status message.
    def _publish_attack_status(self, payload: dict[str, Any]) -> None:
        message = String()
        message.data = compact_json(payload)
        self._attack_status_publisher.publish(message)

    # Publish attack ground truth immediately before the injected goal is sent.
    def _publish_attack_start(
        self,
        *,
        context: dict[str, Any],
        command_id: str,
        attack_event_id: str = "",
    ) -> str:
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
                "source": "arm_command_injection_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )
        return event_id

    # Publish the matching stop event with the controller outcome.
    def _publish_attack_stop(
        self,
        *,
        context: dict[str, Any],
        attack_event_id: str,
        command_id: str,
        end_reason: str,
    ) -> None:
        self._publish_attack_status(
            {
                "action": "stop",
                "active": False,
                "session_id": context.get("session_id", ""),
                "run_id": context.get("run_id", ""),
                "run_key": context.get("run_key", ""),
                "attack_event_id": attack_event_id,
                "end_reason": end_reason,
                "source": "arm_command_injection_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )

    # Check whether the current context names a supported injection attack.
    def _injection_requested(self, context: dict[str, Any]) -> bool:
        return (
            clean_label(context.get("attack_type"))
            in COMMAND_INJECTION_ATTACK_TYPES
        )

    @staticmethod
    # Match one phase exactly while also supporting explicit wildcard targets.
    def _phase_matches(requested_phase: Any, current_phase: Any) -> bool:
        requested = clean_label(requested_phase)
        current = clean_label(current_phase)

        if requested in {"*", "all", "any"}:
            return bool(current)
        return bool(requested) and requested == current

    # Atomically reserve an injection slot without exceeding the per-run limit.
    def _reserve_injection_for_run(self, run_key: str) -> bool:
        if not run_key:
            return False

        with self._injection_count_lock:
            current = self._injection_counts_by_run.get(run_key, 0)
            if current >= self._max_injections_per_run:
                return False
            self._injection_counts_by_run[run_key] = current + 1
            return True

    # Validate attack settings and build a deep-copied offset trajectory when
    # the current run and task phase satisfy every trigger condition.
    def _prepare_injection_goal(
        self,
        *,
        context: dict[str, Any],
        original_goal: FollowJointTrajectory.Goal,
    ) -> tuple[FollowJointTrajectory.Goal | None, dict[str, Any]]:
        # Start with a normal pass-through plan. The checks below only change
        # it when this run and phase are meant to be attacked.
        plan: dict[str, Any] = {
            "requested": False,
            "apply": False,
            "proxy_mode": PROXY_MODE_NORMAL,
            "target_joint": "",
            "offset_radians": 0.0,
            "reason": "normal_run",
        }

        if not self._injection_requested(context):
            return None, plan

        plan["requested"] = True
        plan["proxy_mode"] = PROXY_MODE_INJECTION_ARMED
        plan["reason"] = "phase_not_targeted"

        run_key = str(context.get("run_key", "")).strip()
        if not run_key:
            plan["reason"] = "outside_measured_run"
            return None, plan

        target_phase = context.get("attack_target_phase", "")
        if clean_label(target_phase) in {"", "none"}:
            raise ValueError(
                "Command-injection attack_target_phase must identify a "
                "task phase."
            )

        if not self._phase_matches(
            target_phase, context.get("task_phase", "")
        ):
            return None, plan

        variant = clean_label(context.get("attack_variant", ""))
        if variant not in COMMAND_INJECTION_VARIANTS:
            raise ValueError(
                "Unsupported command-injection attack_variant. Use "
                "pre_command_joint_offset."
            )

        target_joint = str(context.get("attack_target", "")).strip()
        if clean_label(target_joint) in {"", "none"}:
            raise ValueError(
                "Command-injection attack_target must be a trajectory "
                "joint name."
            )

        joint_names = list(original_goal.trajectory.joint_names)
        if target_joint not in joint_names:
            raise ValueError(
                f'Command-injection target joint "{target_joint}" is not '
                f"present in trajectory joints: {joint_names}"
            )

        offset_radians = parse_offset_radians(
            context.get("attack_parameter_value", ""),
            context.get("attack_parameter_unit", ""),
        )

        if abs(offset_radians) > self._max_offset_radians:
            raise ValueError(
                "Requested command-injection offset exceeds the configured "
                "safety limit of "
                f"{self._max_offset_radians:.3f} rad."
            )
        if abs(offset_radians) < 1e-12:
            raise ValueError(
                "Command-injection joint offset must be non-zero."
            )

        if not self._reserve_injection_for_run(run_key):
            plan["reason"] = "per_run_injection_limit_reached"
            return None, plan

        injected_goal = copy.deepcopy(original_goal)
        joint_index = joint_names.index(target_joint)

        for point in injected_goal.trajectory.points:
            positions = list(point.positions)
            if len(positions) != len(joint_names):
                raise ValueError(
                    "Trajectory point position count does not match the "
                    "trajectory joint-name count."
                )

            injected_position = float(positions[joint_index]) + offset_radians
            if not math.isfinite(injected_position):
                raise ValueError(
                    "Command injection produced a non-finite joint target."
                )
            positions[joint_index] = injected_position
            point.positions = positions

        plan.update(
            {
                "apply": True,
                "proxy_mode": PROXY_MODE_INJECTION_TRIGGER,
                "target_joint": target_joint,
                "offset_radians": offset_radians,
                "reason": "target_phase_matched",
            }
        )
        return injected_goal, plan

    # Reject structurally invalid goals or goals received without a controller.
    def _goal_callback(self, goal_request: FollowJointTrajectory.Goal) -> GoalResponse:
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

    # Reject task cancellation because this proxy does not propagate it safely.
    def _cancel_callback(self, goal_handle: Any) -> CancelResponse:
        del goal_handle
        self.get_logger().warning(
            "A cancellation request was rejected by the command-injection "
            "proxy."
        )
        return CancelResponse.REJECT

    # Allocate a unique ordered index for each logged command.
    def _next_sequence_index(self) -> int:
        with self._sequence_lock:
            index = self._command_sequence_index
            self._command_sequence_index += 1
            return index

    # Copy context under its lock and calculate how old the snapshot is.
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

    # Wait briefly for pose-specific context that belongs to the incoming goal.
    def _wait_for_fresh_command_context(
        self,
        *,
        timeout_seconds: float = 1.0,
        maximum_age_seconds: float = 0.25,
    ) -> tuple[dict[str, Any], bool]:
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

    # Create a complete default trace row before controller fields are known.
    def _base_row(
        self,
        *,
        command_id: str,
        sequence_index: int,
        proxy_mode: str,
        context: dict[str, Any],
        received_at: str,
        original_goal: FollowJointTrajectory.Goal,
        forwarded_goal: FollowJointTrajectory.Goal,
    ) -> dict[str, Any]:
        original_trajectory = trajectory_to_dict(
            original_goal.trajectory
        )
        forwarded_trajectory = trajectory_to_dict(
            forwarded_goal.trajectory
        )
        original_duration = trajectory_duration_seconds(
            original_goal.trajectory
        )
        forwarded_duration = trajectory_duration_seconds(
            forwarded_goal.trajectory
        )

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
            "joint_names_json": compact_json(
                list(original_goal.trajectory.joint_names)
            ),
            "original_trajectory_json": compact_json(original_trajectory),
            "forwarded_trajectory_json": compact_json(forwarded_trajectory),
            "original_duration_seconds": f"{original_duration:.9f}",
            "forwarded_duration_seconds": f"{forwarded_duration:.9f}",
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

    # Forward one goal, await the controller result and update timing fields.
    async def _send_controller_goal(
        self,
        *,
        goal: FollowJointTrajectory.Goal,
        row: dict[str, Any],
        timing_origin: float,
        feedback_callback: Any = None,
    ) -> tuple[FollowJointTrajectory.Result, int]:
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
    # Convert a proxy-side validation failure into a ROS action result.
    def _error_result(message: str) -> FollowJointTrajectory.Result:
        result = FollowJointTrajectory.Result()
        result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
        result.error_string = message
        return result

    # Optionally run the injected command first, then always forward the original
    # command when the injected step and experiment context remain valid.
    async def _execute_callback(
        self, proxy_goal_handle: Any
    ) -> FollowJointTrajectory.Result:
        # The source command always gets its own row, even if the injected
        # command fails before the source can be forwarded.
        source_command_id = uuid.uuid4().hex
        source_sequence_index = self._next_sequence_index()
        source_received_monotonic = time.monotonic()
        source_received_at = timestamp()

        context, context_is_valid = self._wait_for_fresh_command_context()
        original_goal = copy.deepcopy(proxy_goal_handle.request)

        configuration_error = ""
        try:
            injected_goal, injection_plan = self._prepare_injection_goal(
                context=context, original_goal=original_goal
            )
        except ValueError as exc:
            injected_goal = None
            injection_plan = {
                "requested": self._injection_requested(context),
                "apply": False,
                "proxy_mode": PROXY_MODE_INJECTION_ARMED,
                "target_joint": "",
                "offset_radians": 0.0,
                "reason": "configuration_error",
            }
            configuration_error = str(exc)

        source_row = self._base_row(
            command_id=source_command_id,
            sequence_index=source_sequence_index,
            proxy_mode=str(
                injection_plan.get("proxy_mode", PROXY_MODE_NORMAL)
            ),
            context=context,
            received_at=source_received_at,
            original_goal=original_goal,
            forwarded_goal=original_goal,
        )

        self.get_logger().info(
            f"Legitimate command {source_sequence_index} received "
            f"({source_command_id[:8]}): "
            f"phase={source_row['task_phase']}, "
            f"pose={source_row['pose_name'] or 'unassigned'}, "
            f"mode={source_row['proxy_mode']}"
        )

        if not context_is_valid:
            source_row["completed_at"] = timestamp()
            source_row["proxy_total_seconds"] = (
                f"{time.monotonic() - source_received_monotonic:.9f}"
            )
            source_row["log_status"] = "context_error"
            source_row["log_error"] = (
                "A fresh pose-specific experiment context was not received "
                "before the trajectory goal."
            )
            self._trace_writer.append(source_row)
            self.get_logger().error(source_row["log_error"])
            proxy_goal_handle.abort()
            return self._error_result(source_row["log_error"])

        if configuration_error:
            source_row["completed_at"] = timestamp()
            source_row["proxy_total_seconds"] = (
                f"{time.monotonic() - source_received_monotonic:.9f}"
            )
            source_row["log_status"] = "attack_configuration_error"
            source_row["log_error"] = configuration_error
            self._trace_writer.append(source_row)
            self.get_logger().error(configuration_error)
            proxy_goal_handle.abort()
            return self._error_result(configuration_error)

        injection_applied = bool(injection_plan.get("apply", False))

        if injection_applied:
            assert injected_goal is not None

            injected_command_id = uuid.uuid4().hex
            injected_sequence_index = self._next_sequence_index()
            injected_received_monotonic = time.monotonic()
            injected_received_at = timestamp()
            target_joint = str(injection_plan["target_joint"])
            offset_radians = float(injection_plan["offset_radians"])

            injected_row = self._base_row(
                command_id=injected_command_id,
                sequence_index=injected_sequence_index,
                proxy_mode=PROXY_MODE_INJECTED,
                context=context,
                received_at=injected_received_at,
                original_goal=original_goal,
                forwarded_goal=injected_goal,
            )
            injected_row.update(
                {
                    "attack_active": 1,
                    "command_injected": 1,
                    "attack_applied": 1,
                    "modified_joint_names_json": compact_json(
                        [target_joint]
                    ),
                    "joint_offsets_json": compact_json(
                        {target_joint: offset_radians}
                    ),
                    "source_command_id": source_command_id,
                    "source_run_key": context.get("run_key", ""),
                }
            )

            attack_event_id = ""
            stop_published = False

            # Ensure every published start event receives at most one stop event.
            def publish_stop_once(end_reason: str) -> None:
                nonlocal stop_published
                if not attack_event_id or stop_published:
                    return
                self._publish_attack_stop(
                    context=context,
                    attack_event_id=attack_event_id,
                    command_id=injected_command_id,
                    end_reason=end_reason,
                )
                stop_published = True
                injected_row["attack_status_stop_published"] = 1

            try:
                attack_event_id = self._publish_attack_start(
                    context=context,
                    command_id=injected_command_id,
                    attack_event_id=str(
                        context.get("attack_event_id", "")
                    ).strip(),
                )
                injected_row["attack_event_id"] = attack_event_id
                injected_row["attack_status_start_published"] = 1

                self.get_logger().warning(
                    "COMMAND INJECTION applied: "
                    f"run={injected_row['run_key']}, "
                    f"phase={injected_row['task_phase']}, "
                    f"joint={target_joint}, "
                    f"offset={offset_radians:+.6f} rad, "
                    f"source={source_command_id[:8]}"
                )

                injected_result, injected_status = (
                    await self._send_controller_goal(
                        goal=injected_goal,
                        row=injected_row,
                        timing_origin=injected_received_monotonic,
                        feedback_callback=None,
                    )
                )

                if injected_status == GoalStatus.STATUS_SUCCEEDED:
                    injection_end_reason = "injected_controller_succeeded"
                elif injected_status == GoalStatus.STATUS_CANCELED:
                    injection_end_reason = "injected_controller_canceled"
                else:
                    injection_end_reason = "injected_controller_failed"

                publish_stop_once(injection_end_reason)
                self._trace_writer.append(injected_row)

                if injected_status != GoalStatus.STATUS_SUCCEEDED:
                    source_row["completed_at"] = timestamp()
                    source_row["proxy_total_seconds"] = (
                        f"{time.monotonic() - source_received_monotonic:.9f}"
                    )
                    source_row["log_status"] = "injected_command_failed"
                    source_row["log_error"] = (
                        "The injected trajectory failed before the "
                        "legitimate command could be forwarded."
                    )
                    self._trace_writer.append(source_row)
                    proxy_goal_handle.abort()
                    return injected_result

            except Exception as exc:
                injected_row["completed_at"] = timestamp()
                injected_row["proxy_total_seconds"] = (
                    f"{time.monotonic() - injected_received_monotonic:.9f}"
                )
                injected_row["log_status"] = "proxy_exception"
                injected_row["log_error"] = str(exc)
                publish_stop_once("proxy_exception")

                try:
                    self._trace_writer.append(injected_row)
                except Exception as logging_exc:
                    self.get_logger().error(
                        "The injected-command failure could not be logged: "
                        f"{logging_exc}"
                    )

                source_row["completed_at"] = timestamp()
                source_row["proxy_total_seconds"] = (
                    f"{time.monotonic() - source_received_monotonic:.9f}"
                )
                source_row["log_status"] = "injection_proxy_exception"
                source_row["log_error"] = str(exc)
                self._trace_writer.append(source_row)

                self.get_logger().error(
                    f"Injected command failed in the proxy: {exc}"
                )
                proxy_goal_handle.abort()
                return self._error_result(str(exc))

        try:
            feedback_callback = lambda feedback_message: (
                proxy_goal_handle.publish_feedback(feedback_message.feedback)
            )

            legitimate_result, legitimate_status = (
                await self._send_controller_goal(
                    goal=original_goal,
                    row=source_row,
                    timing_origin=source_received_monotonic,
                    feedback_callback=feedback_callback,
                )
            )

            self._trace_writer.append(source_row)

            if legitimate_status == GoalStatus.STATUS_SUCCEEDED:
                proxy_goal_handle.succeed()
            elif legitimate_status == GoalStatus.STATUS_CANCELED:
                proxy_goal_handle.canceled()
            else:
                proxy_goal_handle.abort()

            self.get_logger().info(
                f"Legitimate command {source_sequence_index} completed: "
                f"status={source_row['log_status']}, "
                f"error_code={source_row['result_error_code']}, "
                f"injection_triggered={int(injection_applied)}"
            )
            return legitimate_result

        except Exception as exc:
            source_row["completed_at"] = timestamp()
            source_row["proxy_total_seconds"] = (
                f"{time.monotonic() - source_received_monotonic:.9f}"
            )
            source_row["log_status"] = "proxy_exception"
            source_row["log_error"] = str(exc)

            try:
                self._trace_writer.append(source_row)
            except Exception as logging_exc:
                self.get_logger().error(
                    "The legitimate-command failure could not be logged: "
                    f"{logging_exc}"
                )

            self.get_logger().error(
                f"Legitimate command failed in the proxy: {exc}"
            )
            proxy_goal_handle.abort()
            return self._error_result(str(exc))


# Define command-line configuration while allowing ROS arguments to pass through.
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Sentinel Arm command-injection trajectory proxy."
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
        "--maximum-absolute-offset-radians",
        type=float,
        default=DEFAULT_MAXIMUM_ABSOLUTE_OFFSET_RADIANS,
        help=(
            "Safety limit for the absolute injected joint offset. "
            f"Default: {DEFAULT_MAXIMUM_ABSOLUTE_OFFSET_RADIANS} rad."
        ),
    )
    parser.add_argument(
        "--maximum-injections-per-run",
        type=int,
        default=DEFAULT_MAXIMUM_INJECTIONS_PER_RUN,
        help=(
            "Maximum number of extra commands injected in one run. "
            f"Default: {DEFAULT_MAXIMUM_INJECTIONS_PER_RUN}."
        ),
    )

    cli_args = remove_ros_args()[1:]
    return parser.parse_args(cli_args)


# Initialise ROS, run the multithreaded proxy and guarantee orderly shutdown.
def main(args: Sequence[str] | None = None) -> None:
    rclpy.init(args=args)
    config = parse_arguments()

    node = ArmCommandInjectionProxy(
        proxy_action=config.proxy_action,
        controller_action=config.controller_action,
        context_topic=config.context_topic,
        attack_status_topic=config.attack_status_topic,
        command_trace_csv=config.command_trace_csv,
        max_offset_radians=config.maximum_absolute_offset_radians,
        max_injections_per_run=config.maximum_injections_per_run,
    )

    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(node)
    exit_code = 0

    try:
        if not node.wait_for_controller(timeout_seconds=30.0):
            exit_code = 1
            return

        node.get_logger().info(
            "Command-injection proxy is ready. Keep this terminal running."
        )
        executor.spin()

    except KeyboardInterrupt:
        node.get_logger().info("Command-injection proxy stopped by the user.")

    except Exception as exc:
        exit_code = 1
        node.get_logger().error(
            f"Command-injection proxy terminated unexpectedly: {exc}"
        )

    finally:
        executor.shutdown()
        executor.remove_node(node)
        node.destroy_node()

        if rclpy.ok():
            rclpy.shutdown()

    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
