#!/usr/bin/env python3

# Sentinel Arm FollowJointTrajectory proxy with controlled MITM manipulation.
#
# The task controller sends arm goals to:
#
#     /sentinel/arm_proxy/follow_joint_trajectory
#
# The proxy forwards goals to:
#
#     /scaled_joint_trajectory_controller/follow_joint_trajectory
#
# Normal runs are forwarded unchanged. When the experiment context requests
# ``mitm_trajectory_manipulation``, the proxy can add a bounded joint-position
# offset to the selected command phase while preserving the original trajectory
# in ``command_trace.csv``.
#
# The attack is intentionally narrow and deterministic:
#
# - one configured target joint;
# - one configured target phase;
# - one bounded offset value;
# - one attack event per run by default.
#
# This keeps the attack safe for Gazebo experiments and produces clear ground
# truth for command, telemetry, event, and run-level datasets.

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


# Version written into each command-trace record.
SCHEMA_VERSION = "sentinel_command_trace_v2"

# Proxy modes distinguish normal forwarding, an armed MITM and manipulation.
PROXY_MODE_NORMAL = "normal_passthrough"
PROXY_MODE_MITM_ARMED = "mitm_trajectory_manipulation_armed"
PROXY_MODE_MITM_APPLIED = "mitm_trajectory_manipulation"

MITM_ATTACK_TYPES = {
    "mitm",
    "mitm_trajectory_manipulation",
    "trajectory_manipulation",
}
MITM_VARIANTS = {
    "joint_offset",
    "position_offset",
    "joint_position_offset",
}

# Safety limits bound the joint offset and attack count within each run.
DEFAULT_MAXIMUM_ABSOLUTE_OFFSET_RADIANS = 0.25
DEFAULT_MAXIMUM_ATTACKS_PER_RUN = 1

DEFAULT_PROXY_ACTION = (
    "/sentinel/arm_proxy/follow_joint_trajectory"
)
DEFAULT_CONTROLLER_ACTION = (
    "/scaled_joint_trajectory_controller/follow_joint_trajectory"
)
DEFAULT_CONTEXT_TOPIC = "/sentinel/experiment/context"
DEFAULT_ATTACK_STATUS_TOPIC = "/sentinel/attack/status"


# Fixed trace schema used by later feature extraction and IDS evaluation.
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

    return datetime.now().astimezone().isoformat(
        timespec="milliseconds",
    )


def duration_to_seconds(duration: Any) -> float:
    # Convert a builtin_interfaces/Duration message to seconds.

    return (
        float(duration.sec)
        + float(duration.nanosec) / 1_000_000_000.0
    )


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
        "time_from_start_seconds": duration_to_seconds(
            point.time_from_start
        ),
    }


def trajectory_to_dictionary(trajectory: Any) -> dict[str, Any]:
    # Convert a JointTrajectory message into JSON-serialisable data.

    return {
        "header_frame_id": trajectory.header.frame_id,
        "header_stamp_seconds": (
            float(trajectory.header.stamp.sec)
            + float(trajectory.header.stamp.nanosec)
            / 1_000_000_000.0
        ),
        "joint_names": list(trajectory.joint_names),
        "points": [
            point_to_dictionary(point)
            for point in trajectory.points
        ],
    }


def trajectory_duration_seconds(trajectory: Any) -> float:
    # Return the time-from-start value of the final trajectory point.

    if not trajectory.points:
        return 0.0

    return duration_to_seconds(
        trajectory.points[-1].time_from_start
    )


def compact_json(value: Any) -> str:
    # Encode a value using stable compact JSON.

    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    )


def normalise_label(value: Any) -> str:
    # Return a lowercase underscore-separated label.

    return (
        str(value or "")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def parse_offset_radians(
    raw_value: Any,
    raw_unit: Any,
) -> float:

    try:
        offset = float(str(raw_value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "MITM attack_parameter_value must be a numeric joint offset."
        ) from exc

    if not math.isfinite(offset):
        raise ValueError(
            "MITM joint offset must be finite."
        )

    unit = normalise_label(raw_unit)

    if unit in {"rad", "radian", "radians"}:
        return offset

    if unit in {"deg", "degree", "degrees"}:
        return math.radians(offset)

    raise ValueError(
        "MITM attack_parameter_unit must be rad/radians or deg/degrees."
    )


class CommandTraceWriter:
    # Thread-safe append-only CSV writer.

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path.expanduser().resolve()
        self._lock = threading.Lock()
        self._file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None

        self._open()

    def _open(self) -> None:
        self.csv_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if (
            self.csv_path.exists()
            and self.csv_path.stat().st_size > 0
        ):
            with self.csv_path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as existing_file:
                header = next(
                    csv.reader(existing_file),
                    [],
                )

            if header != CSV_FIELDS:
                raise RuntimeError(
                    "The existing command trace has an incompatible "
                    f"header:\n{self.csv_path}\n"
                    f"Expected: {CSV_FIELDS}\n"
                    f"Found:    {header}"
                )

        self._file = self.csv_path.open(
            "a",
            newline="",
            encoding="utf-8",
            buffering=1,
        )

        self._writer = csv.DictWriter(
            self._file,
            fieldnames=CSV_FIELDS,
        )

        if self.csv_path.stat().st_size == 0:
            self._writer.writeheader()
            self._file.flush()

    def append(self, row: dict[str, Any]) -> None:
        with self._lock:
            if self._writer is None or self._file is None:
                raise RuntimeError(
                    "The command trace writer is closed."
                )

            complete_row = {
                field: row.get(field, "")
                for field in CSV_FIELDS
            }

            self._writer.writerow(complete_row)
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()
                self._file.close()

            self._file = None
            self._writer = None


class ArmMitmProxy(Node):
    # Transparent trajectory-action proxy.
    #
    # The implementation uses a re-entrant callback group and a multi-threaded
    # executor because this node is both an action server and an action client.

    def __init__(
        self,
        *,
        proxy_action: str,
        controller_action: str,
        context_topic: str,
        attack_status_topic: str,
        command_trace_csv: Path,
        maximum_absolute_offset_radians: float,
        maximum_attacks_per_run: int,
    ) -> None:
        super().__init__("sentinel_arm_mitm_proxy")

        self.proxy_action = proxy_action
        self.controller_action = controller_action
        self.context_topic = context_topic
        self.attack_status_topic = attack_status_topic
        self.maximum_absolute_offset_radians = float(
            maximum_absolute_offset_radians
        )
        self.maximum_attacks_per_run = int(maximum_attacks_per_run)

        if self.maximum_absolute_offset_radians <= 0.0:
            raise ValueError(
                "maximum_absolute_offset_radians must be positive."
            )

        if self.maximum_attacks_per_run <= 0:
            raise ValueError(
                "maximum_attacks_per_run must be positive."
            )

        self._callback_group = ReentrantCallbackGroup()
        self._trace_writer = CommandTraceWriter(
            command_trace_csv
        )

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

        self._attack_count_lock = threading.Lock()
        self._attack_counts_by_run: dict[str, int] = {}

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

        self.get_logger().info(
            "Transparent arm MITM proxy created."
        )
        self.get_logger().info(
            f"Task-facing action: {self.proxy_action}"
        )
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
            f"Command trace: "
            f"{self._trace_writer.csv_path}"
        )
        self.get_logger().info(
            "Proxy modes: normal passthrough and controlled "
            "MITM trajectory manipulation."
        )
        self.get_logger().info(
            "MITM variant: joint_offset"
        )
        self.get_logger().info(
            "Maximum absolute MITM offset: "
            f"{self.maximum_absolute_offset_radians:.3f} rad"
        )
        self.get_logger().info(
            "Maximum MITM events per run: "
            f"{self.maximum_attacks_per_run}"
        )

    def wait_for_controller(
        self,
        timeout_seconds: float = 30.0,
    ) -> bool:
        # Wait until the real trajectory controller is available.

        self.get_logger().info(
            "Waiting for the real UR5e trajectory controller..."
        )

        available = self._controller_client.wait_for_server(
            timeout_sec=timeout_seconds,
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
        # Store the newest run and phase context from a task script.

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

        received_at = timestamp()
        received_monotonic = time.monotonic()

        session_id = str(
            payload.get("session_id", "")
        ).strip()
        run_id = payload.get("run_id", "")
        run_key = str(
            payload.get("run_key", "")
        ).strip()

        if (
            not run_key
            and session_id
            and str(run_id).strip()
        ):
            run_key = f"{session_id}:{run_id}"

        with self._experiment_context_lock:
            self._experiment_context = {
                "session_id": session_id,
                "run_key": run_key,
                "run_id": run_id,
                "task_type": str(
                    payload.get("task_type", "")
                ).strip(),
                "condition": str(
                    payload.get("condition", "")
                ).strip(),
                "attack_type": str(
                    payload.get("attack_type", "none")
                ).strip() or "none",
                "attack_variant": str(
                    payload.get("attack_variant", "none")
                ).strip() or "none",
                "attack_severity": str(
                    payload.get("attack_severity", "none")
                ).strip() or "none",
                "attack_target": str(
                    payload.get("attack_target", "none")
                ).strip() or "none",
                "attack_target_object": str(
                    payload.get("attack_target_object", "none")
                ).strip() or "none",
                "attack_target_phase": str(
                    payload.get("attack_target_phase", "none")
                ).strip() or "none",
                "attack_parameter_value": str(
                    payload.get("attack_parameter_value", "")
                ).strip(),
                "attack_parameter_unit": str(
                    payload.get("attack_parameter_unit", "")
                ).strip(),
                "attack_event_id": str(
                    payload.get("attack_event_id", "")
                ).strip(),
                "attack_active": int(bool(
                    payload.get("attack_active", 0)
                )),
                "task_phase": str(
                    payload.get(
                        "task_phase",
                        "unassigned",
                    )
                ).strip() or "unassigned",
                "pose_name": str(
                    payload.get("pose_name", "")
                ).strip(),
                "received_at": received_at,
                "received_monotonic": received_monotonic,
            }

    def _publish_attack_status(
        self,
        payload: dict[str, Any],
    ) -> None:
        # Publish attack ground truth for recorders and run summaries.

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
                "attack_variant": context.get(
                    "attack_variant",
                    "none",
                ),
                "attack_severity": context.get(
                    "attack_severity",
                    "none",
                ),
                "attack_target": context.get("attack_target", "none"),
                "attack_target_object": context.get(
                    "attack_target_object",
                    "none",
                ),
                "attack_target_phase": context.get(
                    "attack_target_phase",
                    "none",
                ),
                "attack_parameter_value": context.get(
                    "attack_parameter_value",
                    "",
                ),
                "attack_parameter_unit": context.get(
                    "attack_parameter_unit",
                    "",
                ),
                "source": "arm_mitm_proxy",
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
                "source": "arm_mitm_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )

    def _mitm_requested(
        self,
        context: dict[str, Any],
    ) -> bool:
        # Return True when the run context requests MITM manipulation.

        return (
            normalise_label(context.get("attack_type"))
            in MITM_ATTACK_TYPES
        )

    @staticmethod
    def _phase_matches(
        requested_phase: Any,
        current_phase: Any,
    ) -> bool:
        # Return whether the current command is an intended target.

        requested = normalise_label(requested_phase)
        current = normalise_label(current_phase)

        if requested in {"*", "all", "any"}:
            return bool(current)

        return bool(requested) and requested == current

    def _reserve_attack_for_run(
        self,
        run_key: str,
    ) -> bool:
        # Reserve one attack slot for a run without exceeding the limit.

        if not run_key:
            return False

        with self._attack_count_lock:
            current = self._attack_counts_by_run.get(run_key, 0)

            if current >= self.maximum_attacks_per_run:
                return False

            self._attack_counts_by_run[run_key] = current + 1
            return True

    def _prepare_mitm_goal(
        self,
        *,
        context: dict[str, Any],
        original_goal: FollowJointTrajectory.Goal,
    ) -> tuple[
        FollowJointTrajectory.Goal,
        dict[str, Any],
    ]:
        # Return a forwarded goal and deterministic MITM ground truth.
        #
        # Non-target commands remain unchanged. A configuration error raises
        # ValueError so mislabeled experimental data is never silently written.

        forwarded_goal = copy.deepcopy(original_goal)

        plan: dict[str, Any] = {
            "requested": False,
            "apply": False,
            "proxy_mode": PROXY_MODE_NORMAL,
            "target_joint": "",
            "offset_radians": 0.0,
            "reason": "normal_run",
        }

        if not self._mitm_requested(context):
            return forwarded_goal, plan

        plan["requested"] = True
        plan["proxy_mode"] = PROXY_MODE_MITM_ARMED
        plan["reason"] = "phase_not_targeted"

        run_key = str(context.get("run_key", "")).strip()

        if not run_key:
            plan["reason"] = "outside_measured_run"
            return forwarded_goal, plan

        target_phase = context.get("attack_target_phase", "")
        target_phase_label = normalise_label(target_phase)

        if target_phase_label in {"", "none"}:
            raise ValueError(
                "MITM attack_target_phase must identify a task phase."
            )

        if not self._phase_matches(
            target_phase,
            context.get("task_phase", ""),
        ):
            return forwarded_goal, plan

        variant = normalise_label(
            context.get("attack_variant", "")
        )

        if variant not in MITM_VARIANTS:
            raise ValueError(
                "Unsupported MITM attack_variant. Use joint_offset."
            )

        target_joint = str(
            context.get("attack_target", "")
        ).strip()

        if normalise_label(target_joint) in {"", "none"}:
            raise ValueError(
                "MITM attack_target must be a trajectory joint name."
            )

        joint_names = list(
            forwarded_goal.trajectory.joint_names
        )

        if target_joint not in joint_names:
            raise ValueError(
                f'MITM target joint "{target_joint}" is not present in '
                f"the trajectory joints: {joint_names}"
            )

        offset_radians = parse_offset_radians(
            context.get("attack_parameter_value", ""),
            context.get("attack_parameter_unit", ""),
        )

        if (
            abs(offset_radians)
            > self.maximum_absolute_offset_radians
        ):
            raise ValueError(
                "Requested MITM offset exceeds the configured safety "
                f"limit of {self.maximum_absolute_offset_radians:.3f} rad."
            )

        if abs(offset_radians) < 1e-12:
            raise ValueError(
                "MITM joint offset must be non-zero."
            )

        if not self._reserve_attack_for_run(run_key):
            plan["reason"] = "per_run_attack_limit_reached"
            return forwarded_goal, plan

        joint_index = joint_names.index(target_joint)

        for point in forwarded_goal.trajectory.points:
            positions = list(point.positions)

            if len(positions) != len(joint_names):
                raise ValueError(
                    "Trajectory point position count does not match "
                    "the trajectory joint-name count."
                )

            modified_position = (
                float(positions[joint_index])
                + offset_radians
            )

            if not math.isfinite(modified_position):
                raise ValueError(
                    "MITM produced a non-finite joint target."
                )

            positions[joint_index] = modified_position
            point.positions = positions

        plan.update(
            {
                "apply": True,
                "proxy_mode": PROXY_MODE_MITM_APPLIED,
                "target_joint": target_joint,
                "offset_radians": offset_radians,
                "reason": "target_phase_matched",
            }
        )

        return forwarded_goal, plan

    def _goal_callback(
        self,
        goal_request: FollowJointTrajectory.Goal,
    ) -> GoalResponse:
        # Accept valid goals only when the real controller is ready.

        if not goal_request.trajectory.joint_names:
            self.get_logger().error(
                "Rejected trajectory with no joint names."
            )
            return GoalResponse.REJECT

        if not goal_request.trajectory.points:
            self.get_logger().error(
                "Rejected trajectory with no points."
            )
            return GoalResponse.REJECT

        if not self._controller_client.server_is_ready():
            self.get_logger().error(
                "Rejected trajectory because the real controller "
                "is unavailable."
            )
            return GoalResponse.REJECT

        return GoalResponse.ACCEPT

    def _cancel_callback(
        self,
        goal_handle: Any,
    ) -> CancelResponse:
        del goal_handle

        self.get_logger().warning(
            "A cancellation request was rejected by the "
            "transparent proxy."
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
            snapshot.pop("received_monotonic", 0.0)
            or 0.0
        )

        if received_monotonic > 0.0:
            context_age = (
                time.monotonic() - received_monotonic
            )
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

        deadline = time.monotonic() + timeout_seconds
        latest = self._context_snapshot()

        while time.monotonic() < deadline:
            latest = self._context_snapshot()

            pose_name = str(
                latest.get("pose_name", "")
            ).strip()

            context_age = latest.get(
                "context_age_seconds",
                "",
            )

            try:
                context_age_value = float(context_age)
            except (TypeError, ValueError):
                context_age_value = float("inf")

            if (
                pose_name
                and context_age_value <= maximum_age_seconds
            ):
                return latest, True

            # The node uses a MultiThreadedExecutor, so another callback
            # thread can receive the context message while this one waits.
            time.sleep(0.005)

        return latest, False

    async def _execute_callback(
        self,
        proxy_goal_handle: Any,
    ) -> FollowJointTrajectory.Result:

        command_id = uuid.uuid4().hex
        sequence_index = self._next_sequence_index()

        received_monotonic = time.monotonic()
        received_at = timestamp()

        context, context_is_valid = (
            self._wait_for_fresh_command_context()
        )

        original_goal = copy.deepcopy(
            proxy_goal_handle.request
        )

        configuration_error = ""
        try:
            forwarded_goal, attack_plan = (
                self._prepare_mitm_goal(
                    context=context,
                    original_goal=original_goal,
                )
            )
        except ValueError as exc:
            forwarded_goal = copy.deepcopy(original_goal)
            attack_plan = {
                "requested": self._mitm_requested(context),
                "apply": False,
                "proxy_mode": PROXY_MODE_MITM_ARMED,
                "target_joint": "",
                "offset_radians": 0.0,
                "reason": "configuration_error",
            }
            configuration_error = str(exc)

        original_trajectory = trajectory_to_dictionary(
            original_goal.trajectory
        )
        forwarded_trajectory = trajectory_to_dictionary(
            forwarded_goal.trajectory
        )

        original_duration = trajectory_duration_seconds(
            original_goal.trajectory
        )
        forwarded_duration = trajectory_duration_seconds(
            forwarded_goal.trajectory
        )

        attack_applied = bool(attack_plan.get("apply", False))
        target_joint = str(
            attack_plan.get("target_joint", "")
        )
        offset_radians = float(
            attack_plan.get("offset_radians", 0.0)
        )

        row: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "command_id": command_id,
            "command_sequence_index": sequence_index,
            "proxy_mode": attack_plan.get(
                "proxy_mode",
                PROXY_MODE_NORMAL,
            ),
            "session_id": context.get("session_id", ""),
            "run_key": context.get("run_key", ""),
            "run_id": context.get("run_id", ""),
            "task_type": context.get("task_type", ""),
            "condition": context.get("condition", ""),
            "attack_type": context.get(
                "attack_type",
                "none",
            ),
            "attack_variant": context.get(
                "attack_variant",
                "none",
            ),
            "attack_severity": context.get(
                "attack_severity",
                "none",
            ),
            "attack_target": context.get(
                "attack_target",
                "none",
            ),
            "attack_target_object": context.get(
                "attack_target_object",
                "none",
            ),
            "attack_target_phase": context.get(
                "attack_target_phase",
                "none",
            ),
            "attack_parameter_value": context.get(
                "attack_parameter_value",
                "",
            ),
            "attack_parameter_unit": context.get(
                "attack_parameter_unit",
                "",
            ),
            "attack_event_id": context.get(
                "attack_event_id",
                "",
            ),
            "attack_active": int(attack_applied),
            "task_phase": context.get(
                "task_phase",
                "unassigned",
            ),
            "pose_name": context.get("pose_name", ""),
            "context_received_at": context.get(
                "received_at",
                "",
            ),
            "context_age_seconds": context.get(
                "context_age_seconds",
                "",
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
            "original_trajectory_json": compact_json(
                original_trajectory
            ),
            "forwarded_trajectory_json": compact_json(
                forwarded_trajectory
            ),
            "original_duration_seconds": (
                f"{original_duration:.9f}"
            ),
            "forwarded_duration_seconds": (
                f"{forwarded_duration:.9f}"
            ),
            "command_modified": int(attack_applied),
            "command_injected": 0,
            "command_replayed": 0,
            "command_delayed": 0,
            "command_dropped": 0,
            "attack_applied": int(attack_applied),
            "modified_joint_names_json": (
                compact_json([target_joint])
                if attack_applied
                else "[]"
            ),
            "joint_offsets_json": (
                compact_json(
                    {target_joint: offset_radians}
                )
                if attack_applied
                else "{}"
            ),
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

        self.get_logger().info(
            f"Command {sequence_index} received "
            f"({command_id[:8]}): "
            f"phase={row['task_phase']}, "
            f"pose={row['pose_name'] or 'unassigned'}, "
            f"mode={row['proxy_mode']}"
        )

        if not context_is_valid:
            row["completed_at"] = timestamp()
            row["proxy_total_seconds"] = (
                f"{time.monotonic() - received_monotonic:.9f}"
            )
            row["log_status"] = "context_error"
            row["log_error"] = (
                "A fresh pose-specific experiment context was not "
                "received before the trajectory goal."
            )

            self._trace_writer.append(row)
            self.get_logger().error(row["log_error"])

            result = FollowJointTrajectory.Result()
            result.error_code = (
                FollowJointTrajectory.Result.INVALID_GOAL
            )
            result.error_string = row["log_error"]

            proxy_goal_handle.abort()
            return result

        if configuration_error:
            row["completed_at"] = timestamp()
            row["proxy_total_seconds"] = (
                f"{time.monotonic() - received_monotonic:.9f}"
            )
            row["log_status"] = "attack_configuration_error"
            row["log_error"] = configuration_error

            self._trace_writer.append(row)
            self.get_logger().error(configuration_error)

            result = FollowJointTrajectory.Result()
            result.error_code = (
                FollowJointTrajectory.Result.INVALID_GOAL
            )
            result.error_string = configuration_error

            proxy_goal_handle.abort()
            return result

        attack_event_id = ""
        attack_stop_published = False

        def publish_attack_stop_once(
            end_reason: str,
        ) -> None:
            nonlocal attack_stop_published

            if (
                not attack_applied
                or not attack_event_id
                or attack_stop_published
            ):
                return

            self.publish_attack_stop(
                context=context,
                attack_event_id=attack_event_id,
                command_id=command_id,
                end_reason=end_reason,
            )
            attack_stop_published = True
            row["attack_status_stop_published"] = 1

        try:
            if attack_applied:
                attack_event_id = self.publish_attack_start(
                    context=context,
                    command_id=command_id,
                    attack_event_id=str(
                        context.get("attack_event_id", "")
                    ).strip(),
                )
                row["attack_event_id"] = attack_event_id
                row["attack_status_start_published"] = 1

                self.get_logger().warning(
                    "MITM applied: "
                    f"run={row['run_key']}, "
                    f"phase={row['task_phase']}, "
                    f"joint={target_joint}, "
                    f"offset={offset_radians:+.6f} rad"
                )

            forwarded_monotonic = time.monotonic()
            row["forwarded_at"] = timestamp()
            row["command_latency_ms"] = (
                f"{(
                    forwarded_monotonic
                    - received_monotonic
                ) * 1000.0:.6f}"
            )

            send_future = (
                self._controller_client.send_goal_async(
                    forwarded_goal,
                    feedback_callback=lambda feedback_message: (
                        proxy_goal_handle.publish_feedback(
                            feedback_message.feedback
                        )
                    ),
                )
            )

            controller_goal_handle = await send_future
            row["controller_accepted_at"] = timestamp()

            if (
                controller_goal_handle is None
                or not controller_goal_handle.accepted
            ):
                row["log_status"] = "controller_rejected"
                row["log_error"] = (
                    "The real trajectory controller rejected the goal."
                )
                row["completed_at"] = timestamp()
                row["proxy_total_seconds"] = (
                    f"{time.monotonic() - received_monotonic:.9f}"
                )

                publish_attack_stop_once(
                    "controller_rejected"
                )
                self._trace_writer.append(row)

                result = FollowJointTrajectory.Result()
                result.error_code = (
                    FollowJointTrajectory.Result.INVALID_GOAL
                )
                result.error_string = row["log_error"]

                proxy_goal_handle.abort()
                return result

            row["controller_goal_accepted"] = 1
            controller_execution_started = time.monotonic()

            wrapped_result = await (
                controller_goal_handle.get_result_async()
            )

            controller_execution_finished = time.monotonic()

            result = wrapped_result.result
            status = int(wrapped_result.status)

            row["completed_at"] = timestamp()
            row["controller_status"] = status
            row["result_error_code"] = int(
                result.error_code
            )
            row["result_error_string"] = (
                result.error_string
            )
            row["controller_execution_seconds"] = (
                f"{(
                    controller_execution_finished
                    - controller_execution_started
                ):.9f}"
            )
            row["proxy_total_seconds"] = (
                f"{(
                    controller_execution_finished
                    - received_monotonic
                ):.9f}"
            )

            if status == GoalStatus.STATUS_SUCCEEDED:
                row["log_status"] = "succeeded"
                end_reason = "controller_succeeded"
                proxy_goal_handle.succeed()
            elif status == GoalStatus.STATUS_CANCELED:
                row["log_status"] = "controller_canceled"
                end_reason = "controller_canceled"
                proxy_goal_handle.canceled()
            else:
                row["log_status"] = "controller_failed"
                end_reason = "controller_failed"
                proxy_goal_handle.abort()

            publish_attack_stop_once(end_reason)
            self._trace_writer.append(row)

            self.get_logger().info(
                f"Command {sequence_index} completed: "
                f"status={row['log_status']}, "
                f"error_code={row['result_error_code']}, "
                f"attack_applied={row['attack_applied']}"
            )

            return result

        except Exception as exc:
            row["completed_at"] = timestamp()
            row["proxy_total_seconds"] = (
                f"{time.monotonic() - received_monotonic:.9f}"
            )
            row["log_status"] = "proxy_exception"
            row["log_error"] = str(exc)

            publish_attack_stop_once("proxy_exception")

            try:
                self._trace_writer.append(row)
            except Exception as logging_exc:
                self.get_logger().error(
                    "The proxy failed and its failure could not be "
                    f"logged: {logging_exc}"
                )

            self.get_logger().error(
                f"Command {sequence_index} failed in the proxy: {exc}"
            )

            result = FollowJointTrajectory.Result()
            result.error_code = (
                FollowJointTrajectory.Result.INVALID_GOAL
            )
            result.error_string = str(exc)

            proxy_goal_handle.abort()
            return result


def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Run the transparent Sentinel Arm trajectory proxy."
        )
    )

    parser.add_argument(
        "--proxy-action",
        default=DEFAULT_PROXY_ACTION,
        help=(
            "Action exposed to task scripts. "
            f"Default: {DEFAULT_PROXY_ACTION}"
        ),
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
            "Safety limit for the absolute MITM joint offset. "
            f"Default: {DEFAULT_MAXIMUM_ABSOLUTE_OFFSET_RADIANS} rad."
        ),
    )

    parser.add_argument(
        "--maximum-attacks-per-run",
        type=int,
        default=DEFAULT_MAXIMUM_ATTACKS_PER_RUN,
        help=(
            "Maximum number of matching MITM commands modified in one "
            f"run. Default: {DEFAULT_MAXIMUM_ATTACKS_PER_RUN}."
        ),
    )

    arguments_without_ros = remove_ros_args()[1:]
    return parser.parse_args(arguments_without_ros)


def main(args: Sequence[str] | None = None) -> None:

    rclpy.init(args=args)
    arguments = parse_arguments()

    node = ArmMitmProxy(
        proxy_action=arguments.proxy_action,
        controller_action=arguments.controller_action,
        context_topic=arguments.context_topic,
        attack_status_topic=arguments.attack_status_topic,
        command_trace_csv=arguments.command_trace_csv,
        maximum_absolute_offset_radians=(
            arguments.maximum_absolute_offset_radians
        ),
        maximum_attacks_per_run=(
            arguments.maximum_attacks_per_run
        ),
    )

    executor = MultiThreadedExecutor(
        num_threads=4,
    )
    executor.add_node(node)

    exit_code = 0

    try:
        if not node.wait_for_controller(
            timeout_seconds=30.0,
        ):
            exit_code = 1
            return

        node.get_logger().info(
            "Proxy is ready. Keep this terminal running."
        )
        executor.spin()

    except KeyboardInterrupt:
        node.get_logger().info(
            "Proxy stopped by the user."
        )

    except Exception as exc:
        exit_code = 1
        node.get_logger().error(
            f"Proxy terminated unexpectedly: {exc}"
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
