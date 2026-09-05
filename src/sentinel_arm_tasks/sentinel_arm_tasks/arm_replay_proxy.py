#!/usr/bin/env python3

# ROS 2 action proxy that can replay a successful earlier trajectory before
# forwarding the current legitimate UR5e command.

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


# Version written into every command-trace record.
SCHEMA_VERSION = "sentinel_command_trace_v2"

# Proxy modes distinguish normal, armed, triggered and replayed commands.
PROXY_MODE_NORMAL = "normal_passthrough"
PROXY_MODE_REPLAY_ARMED = "replay_attack_armed"
PROXY_MODE_REPLAY_TRIGGER = "replay_attack_trigger"
PROXY_MODE_REPLAYED = "command_replay"

REPLAY_ATTACK_TYPES = {
    "replay_attack",
    "command_replay",
    "trajectory_replay",
}

REPLAY_VARIANTS = {
    "prior_command_replay",
    "previous_command_replay",
    "same_run_prior_command_replay",
}

# Bound replay frequency and retained history to keep experiments controlled.
DEFAULT_MAXIMUM_REPLAYS_PER_RUN = 1
DEFAULT_MAXIMUM_HISTORY_PER_RUN = 64

DEFAULT_PROXY_ACTION = "/sentinel/arm_proxy/follow_joint_trajectory"
DEFAULT_CONTROLLER_ACTION = (
    "/scaled_joint_trajectory_controller/follow_joint_trajectory"
)
DEFAULT_CONTEXT_TOPIC = "/sentinel/experiment/context"
DEFAULT_ATTACK_STATUS_TOPIC = "/sentinel/attack/status"


# Fixed trace schema consumed by feature preparation and evaluation scripts.
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


# Create timezone-aware millisecond timestamps for events and trace rows.
def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


# Convert a ROS duration message to floating-point seconds.
def duration_to_seconds(duration: Any) -> float:
    return float(duration.sec) + float(duration.nanosec) / 1_000_000_000.0


# Convert ROS numeric sequences into JSON-compatible floats.
def number_list(values: Sequence[Any]) -> list[float]:
    return [float(value) for value in values]


# Serialise one trajectory point and its time-from-start value.
def point_to_dictionary(point: Any) -> dict[str, Any]:
    return {
        "positions": number_list(point.positions),
        "velocities": number_list(point.velocities),
        "accelerations": number_list(point.accelerations),
        "effort": number_list(point.effort),
        "time_from_start_seconds": duration_to_seconds(point.time_from_start),
    }


# Convert a complete trajectory into the structure stored in the CSV trace.
def trajectory_to_dictionary(trajectory: Any) -> dict[str, Any]:
    return {
        "header_frame_id": trajectory.header.frame_id,
        "header_stamp_seconds": (
            float(trajectory.header.stamp.sec)
            + float(trajectory.header.stamp.nanosec) / 1_000_000_000.0
        ),
        "joint_names": list(trajectory.joint_names),
        "points": [point_to_dictionary(point) for point in trajectory.points],
    }


# Read a trajectory's planned duration from its final point.
def trajectory_duration_seconds(trajectory: Any) -> float:
    if not trajectory.points:
        return 0.0
    return duration_to_seconds(trajectory.points[-1].time_from_start)


# Encode values as deterministic compact JSON for stable CSV cells.
def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# Normalise free-text context values before matching configuration labels.
def normalise_label(value: Any) -> str:
    return (
        str(value or "")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


# Parse how many successful commands back the replay source should be.
def parse_commands_back(raw_value: Any, raw_unit: Any) -> int:
    try:
        numeric_value = float(str(raw_value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Replay attack_parameter_value must be a positive integer."
        ) from exc

    if not math.isfinite(numeric_value):
        raise ValueError("Replay commands-back value must be finite.")

    commands_back = int(numeric_value)
    if abs(numeric_value - commands_back) > 1e-9 or commands_back <= 0:
        raise ValueError(
            "Replay attack_parameter_value must be a positive integer."
        )

    unit = normalise_label(raw_unit)
    if unit not in {
        "command",
        "commands",
        "command_back",
        "commands_back",
    }:
        raise ValueError(
            "Replay attack_parameter_unit must be commands_back."
        )

    return commands_back


# Append trace rows safely from concurrent ROS callbacks.
class CommandTraceWriter:
    # Resolve and open the requested append-only trace file.
    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path.expanduser().resolve()
        self._lock = threading.Lock()
        self._file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None
        self._open()

    # Validate an existing header before adding new rows.
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

    # Fill optional columns and flush each completed trace row immediately.
    def append(self, row: dict[str, Any]) -> None:
        with self._lock:
            if self._writer is None or self._file is None:
                raise RuntimeError("The command trace writer is closed.")

            complete_row = {field: row.get(field, "") for field in CSV_FIELDS}
            self._writer.writerow(complete_row)
            self._file.flush()

    # Release the trace file during normal or exceptional shutdown.
    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()
                self._file.close()
            self._file = None
            self._writer = None


# Expose a task-facing action that can replay an earlier goal before the current command.
class ArmReplayProxy(Node):
    # Configure ROS interfaces, history storage and per-run safety state.
    def __init__(
        self,
        *,
        proxy_action: str,
        controller_action: str,
        context_topic: str,
        attack_status_topic: str,
        command_trace_csv: Path,
        maximum_replays_per_run: int,
        maximum_history_per_run: int,
    ) -> None:
        super().__init__("sentinel_arm_replay_proxy")

        self.proxy_action = proxy_action
        self.controller_action = controller_action
        self.context_topic = context_topic
        self.attack_status_topic = attack_status_topic
        self.maximum_replays_per_run = int(maximum_replays_per_run)
        self.maximum_history_per_run = int(maximum_history_per_run)

        # Reject unsafe history and replay limits before creating ROS entities.
        if self.maximum_replays_per_run <= 0:
            raise ValueError("maximum_replays_per_run must be positive.")
        if self.maximum_history_per_run <= 0:
            raise ValueError("maximum_history_per_run must be positive.")

        self._callback_group = ReentrantCallbackGroup()
        self._trace_writer = CommandTraceWriter(command_trace_csv)

        # Keep one lock-protected snapshot of the newest experiment context.
        self._experiment_context_lock = threading.Lock()
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

        # Count replay reservations independently for each measured run.
        self._replay_count_lock = threading.Lock()
        self._replay_counts_by_run: dict[str, int] = {}

        # Retain successful legitimate goals as possible same-run replay sources.
        self._history_lock = threading.Lock()
        self._legitimate_history_by_run: dict[
            str, list[dict[str, Any]]
        ] = {}

        # Track cancellation separately for every proxy action goal.
        self._cancel_state_lock = threading.RLock()
        self._cancel_state_by_proxy_goal: dict[int, dict[str, Any]] = {}

        context_qos = QoSProfile(depth=50)
        context_qos.reliability = ReliabilityPolicy.RELIABLE

        # Receive task context and publish attack ground-truth boundaries.
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

        # Connect the task-facing proxy action to the real controller action.
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

        self.get_logger().info("Replay-attack arm proxy created.")
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
            "Proxy modes: normal passthrough and controlled prior-command "
            "replay."
        )
        self.get_logger().info("Replay variant: prior_command_replay")
        self.get_logger().info(
            "Maximum replayed commands per run: "
            f"{self.maximum_replays_per_run}"
        )
        self.get_logger().info(
            "Maximum stored legitimate commands per run: "
            f"{self.maximum_history_per_run}"
        )

    # Wait for the real controller before accepting task execution.
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

    # Destroy action objects and close the trace writer cleanly.
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

    # Validate and atomically store the newest JSON experiment context.
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

        received_at = timestamp()
        received_monotonic = time.monotonic()

        session_id = str(payload.get("session_id", "")).strip()
        run_id = payload.get("run_id", "")
        run_key = str(payload.get("run_key", "")).strip()
        if not run_key and session_id and str(run_id).strip():
            run_key = f"{session_id}:{run_id}"

        with self._experiment_context_lock:
            self._experiment_context = {
                "session_id": session_id,
                "run_key": run_key,
                "run_id": run_id,
                "task_type": str(payload.get("task_type", "")).strip(),
                "condition": str(payload.get("condition", "")).strip(),
                "attack_type": str(
                    payload.get("attack_type", "none")
                ).strip()
                or "none",
                "attack_variant": str(
                    payload.get("attack_variant", "none")
                ).strip()
                or "none",
                "attack_severity": str(
                    payload.get("attack_severity", "none")
                ).strip()
                or "none",
                "attack_target": str(
                    payload.get("attack_target", "none")
                ).strip()
                or "none",
                "attack_target_object": str(
                    payload.get("attack_target_object", "none")
                ).strip()
                or "none",
                "attack_target_phase": str(
                    payload.get("attack_target_phase", "none")
                ).strip()
                or "none",
                "attack_parameter_value": str(
                    payload.get("attack_parameter_value", "")
                ).strip(),
                "attack_parameter_unit": str(
                    payload.get("attack_parameter_unit", "")
                ).strip(),
                "attack_event_id": str(
                    payload.get("attack_event_id", "")
                ).strip(),
                "attack_active": int(
                    bool(payload.get("attack_active", 0))
                ),
                "task_phase": str(
                    payload.get("task_phase", "unassigned")
                ).strip()
                or "unassigned",
                "pose_name": str(payload.get("pose_name", "")).strip(),
                "received_at": received_at,
                "received_monotonic": received_monotonic,
            }

    # Encode and publish one attack-status payload.
    def _publish_attack_status(self, payload: dict[str, Any]) -> None:
        message = String()
        message.data = compact_json(payload)
        self._attack_status_publisher.publish(message)

    # Announce the exact start of an applied replay event.
    def publish_attack_start(
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
                "source": "arm_replay_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )
        return event_id

    # Publish the matching replay stop event and completion reason.
    def publish_attack_stop(
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
                "source": "arm_replay_proxy",
                "source_timestamp": timestamp(),
                "command_id": command_id,
            }
        )

    # Check whether the context requests a supported replay attack.
    def _replay_requested(self, context: dict[str, Any]) -> bool:
        return (
            normalise_label(context.get("attack_type"))
            in REPLAY_ATTACK_TYPES
        )

    # Match an exact phase while supporting explicit wildcard targets.
    @staticmethod
    def _phase_matches(requested_phase: Any, current_phase: Any) -> bool:
        requested = normalise_label(requested_phase)
        current = normalise_label(current_phase)

        if requested in {"*", "all", "any"}:
            return bool(current)
        return bool(requested) and requested == current

    # Reserve one replay atomically without exceeding the per-run limit.
    def _reserve_replay_for_run(self, run_key: str) -> bool:
        if not run_key:
            return False

        with self._replay_count_lock:
            current = self._replay_counts_by_run.get(run_key, 0)
            if current >= self.maximum_replays_per_run:
                return False
            self._replay_counts_by_run[run_key] = current + 1
            return True

    # Store successful legitimate goals as trusted replay history.
    def _store_successful_legitimate_command(
        self,
        *,
        context: dict[str, Any],
        command_id: str,
        goal: FollowJointTrajectory.Goal,
    ) -> None:
        run_key = str(context.get("run_key", "")).strip()
        if not run_key:
            return

        record = {
            "command_id": command_id,
            "run_key": run_key,
            "task_phase": str(context.get("task_phase", "")),
            "pose_name": str(context.get("pose_name", "")),
            "goal": copy.deepcopy(goal),
        }

        with self._history_lock:
            history = self._legitimate_history_by_run.setdefault(
                run_key, []
            )
            history.append(record)
            if len(history) > self.maximum_history_per_run:
                del history[:-self.maximum_history_per_run]

    # Return a lock-protected copy of the selected run's command history.
    def _history_snapshot(self, run_key: str) -> list[dict[str, Any]]:
        with self._history_lock:
            return list(
                self._legitimate_history_by_run.get(run_key, [])
            )

    # Validate replay settings and select the requested earlier goal.
    def _prepare_replay_goal(
        self,
        *,
        context: dict[str, Any],
        original_goal: FollowJointTrajectory.Goal,
    ) -> tuple[FollowJointTrajectory.Goal | None, dict[str, Any]]:
        plan: dict[str, Any] = {
            "requested": False,
            "apply": False,
            "proxy_mode": PROXY_MODE_NORMAL,
            "commands_back": 0,
            "source_command_id": "",
            "source_run_key": "",
            "source_task_phase": "",
            "source_pose_name": "",
            "reason": "normal_run",
        }

        if not self._replay_requested(context):
            return None, plan

        plan["requested"] = True
        plan["proxy_mode"] = PROXY_MODE_REPLAY_ARMED
        plan["reason"] = "phase_not_targeted"

        run_key = str(context.get("run_key", "")).strip()
        if not run_key:
            plan["reason"] = "outside_measured_run"
            return None, plan

        target_phase = context.get("attack_target_phase", "")
        if normalise_label(target_phase) in {"", "none"}:
            raise ValueError(
                "Replay attack_target_phase must identify a task phase."
            )

        if not self._phase_matches(
            target_phase, context.get("task_phase", "")
        ):
            return None, plan

        variant = normalise_label(context.get("attack_variant", ""))
        if variant not in REPLAY_VARIANTS:
            raise ValueError(
                "Unsupported replay attack_variant. Use "
                "prior_command_replay."
            )

        target = normalise_label(context.get("attack_target", ""))
        if target not in {
            "arm_trajectory",
            "trajectory",
            "arm_command",
        }:
            raise ValueError(
                "Replay attack_target must be arm_trajectory."
            )

        commands_back = parse_commands_back(
            context.get("attack_parameter_value", ""),
            context.get("attack_parameter_unit", ""),
        )

        history = self._history_snapshot(run_key)
        if len(history) < commands_back:
            raise ValueError(
                "Replay source history is too short: requested "
                f"{commands_back} commands back, but only {len(history)} "
                "successful legitimate arm commands are available in "
                "this run."
            )

        source = history[-commands_back]
        replay_goal = copy.deepcopy(source["goal"])

        current_joint_names = list(original_goal.trajectory.joint_names)
        replay_joint_names = list(replay_goal.trajectory.joint_names)
        if current_joint_names != replay_joint_names:
            raise ValueError(
                "Replay source and current command use different "
                "joint-name orders."
            )

        if not self._reserve_replay_for_run(run_key):
            plan["reason"] = "per_run_replay_limit_reached"
            return None, plan

        plan.update(
            {
                "apply": True,
                "proxy_mode": PROXY_MODE_REPLAY_TRIGGER,
                "commands_back": commands_back,
                "source_command_id": str(source["command_id"]),
                "source_run_key": str(source["run_key"]),
                "source_task_phase": str(source["task_phase"]),
                "source_pose_name": str(source["pose_name"]),
                "reason": "target_phase_matched",
            }
        )
        return replay_goal, plan

    # Reject incomplete trajectories or goals received without a controller.
    def _goal_callback(
        self, goal_request: FollowJointTrajectory.Goal
    ) -> GoalResponse:
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
                "Rejected trajectory because the real controller is "
                "unavailable."
            )
            return GoalResponse.REJECT
        return GoalResponse.ACCEPT

    # Create per-goal cancellation state before execution begins.
    def _register_proxy_goal(self, proxy_goal_handle: Any) -> None:
        with self._cancel_state_lock:
            self._cancel_state_by_proxy_goal[id(proxy_goal_handle)] = {
                "cancel_requested": False,
                "controller_goal_handle": None,
            }

    # Remove cancellation tracking after a proxy goal finishes.
    def _unregister_proxy_goal(self, proxy_goal_handle: Any) -> None:
        with self._cancel_state_lock:
            self._cancel_state_by_proxy_goal.pop(
                id(proxy_goal_handle),
                None,
            )

    # Associate the real controller goal with its task-facing proxy goal.
    def _attach_controller_goal(
        self,
        proxy_goal_handle: Any,
        controller_goal_handle: Any,
    ) -> bool:
        # Attach the real goal and report prior cancellation.

        with self._cancel_state_lock:
            state = self._cancel_state_by_proxy_goal.setdefault(
                id(proxy_goal_handle),
                {
                    "cancel_requested": False,
                    "controller_goal_handle": None,
                },
            )
            state["controller_goal_handle"] = controller_goal_handle
            return bool(state["cancel_requested"])

    # Clear the controller handle after the forwarded goal completes.
    def _detach_controller_goal(self, proxy_goal_handle: Any) -> None:
        with self._cancel_state_lock:
            state = self._cancel_state_by_proxy_goal.get(
                id(proxy_goal_handle)
            )
            if state is not None:
                state["controller_goal_handle"] = None

    # Record cancellation and forward it when a controller goal exists.
    def _cancel_callback(self, goal_handle: Any) -> CancelResponse:
        controller_goal_handle = None

        with self._cancel_state_lock:
            state = self._cancel_state_by_proxy_goal.setdefault(
                id(goal_handle),
                {
                    "cancel_requested": False,
                    "controller_goal_handle": None,
                },
            )
            state["cancel_requested"] = True
            controller_goal_handle = state.get(
                "controller_goal_handle"
            )

        if controller_goal_handle is not None:
            try:
                controller_goal_handle.cancel_goal_async()
            except Exception as exc:
                self.get_logger().error(
                    "Could not forward cancellation to the real "
                    f"controller: {exc}"
                )

        self.get_logger().warning(
            "Cancellation accepted by the replay proxy and forwarded "
            "to the real controller."
        )
        return CancelResponse.ACCEPT

    # Allocate an ordered index for each legitimate or replayed command.
    def _next_sequence_index(self) -> int:
        with self._sequence_lock:
            index = self._command_sequence_index
            self._command_sequence_index += 1
            return index

    # Copy context under its lock and calculate snapshot age.
    def _context_snapshot(self) -> dict[str, Any]:
        with self._experiment_context_lock:
            snapshot = dict(self._experiment_context)

        received_monotonic = float(
            snapshot.pop("received_monotonic", 0.0) or 0.0
        )
        if received_monotonic > 0.0:
            context_age: float | str = (
                time.monotonic() - received_monotonic
            )
        else:
            context_age = ""
        snapshot["context_age_seconds"] = context_age
        return snapshot

    # Wait briefly for context belonging to the incoming goal.
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

    # Create a complete trace row before controller timing and results are known.
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
            "original_trajectory_json": compact_json(
                original_trajectory
            ),
            "forwarded_trajectory_json": compact_json(
                forwarded_trajectory
            ),
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

    # Forward one goal, propagate cancellation and record its outcome.
    async def _send_controller_goal(
        self,
        *,
        proxy_goal_handle: Any,
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

        cancel_already_requested = self._attach_controller_goal(
            proxy_goal_handle,
            controller_goal_handle,
        )
        if cancel_already_requested:
            await controller_goal_handle.cancel_goal_async()

        controller_execution_started = time.monotonic()
        try:
            wrapped_result = await controller_goal_handle.get_result_async()
        finally:
            self._detach_controller_goal(proxy_goal_handle)
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

    # Convert a proxy-side validation failure into a ROS action result.
    @staticmethod
    def _error_result(message: str) -> FollowJointTrajectory.Result:
        result = FollowJointTrajectory.Result()
        result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
        result.error_string = message
        return result

    # Track cancellation state around the complete execution lifecycle.
    async def _execute_callback(
        self, proxy_goal_handle: Any
    ) -> FollowJointTrajectory.Result:
        self._register_proxy_goal(proxy_goal_handle)
        try:
            return await self._execute_registered_goal(proxy_goal_handle)
        finally:
            self._unregister_proxy_goal(proxy_goal_handle)

    # Execute a replay first, then forward and store the current command.
    async def _execute_registered_goal(
        self, proxy_goal_handle: Any
    ) -> FollowJointTrajectory.Result:
        current_command_id = uuid.uuid4().hex
        current_sequence_index = self._next_sequence_index()
        current_received_monotonic = time.monotonic()
        current_received_at = timestamp()

        context, context_is_valid = self._wait_for_fresh_command_context()
        original_goal = copy.deepcopy(proxy_goal_handle.request)

        configuration_error = ""
        try:
            replay_goal, replay_plan = self._prepare_replay_goal(
                context=context,
                original_goal=original_goal,
            )
        except ValueError as exc:
            replay_goal = None
            replay_plan = {
                "requested": self._replay_requested(context),
                "apply": False,
                "proxy_mode": PROXY_MODE_REPLAY_ARMED,
                "commands_back": 0,
                "source_command_id": "",
                "source_run_key": "",
                "source_task_phase": "",
                "source_pose_name": "",
                "reason": "configuration_error",
            }
            configuration_error = str(exc)

        current_row = self._base_row(
            command_id=current_command_id,
            sequence_index=current_sequence_index,
            proxy_mode=str(
                replay_plan.get("proxy_mode", PROXY_MODE_NORMAL)
            ),
            context=context,
            received_at=current_received_at,
            original_goal=original_goal,
            forwarded_goal=original_goal,
        )

        self.get_logger().info(
            f"Legitimate command {current_sequence_index} received "
            f"({current_command_id[:8]}): "
            f"phase={current_row['task_phase']}, "
            f"pose={current_row['pose_name'] or 'unassigned'}, "
            f"mode={current_row['proxy_mode']}"
        )

        if not context_is_valid:
            current_row["completed_at"] = timestamp()
            current_row["proxy_total_seconds"] = (
                f"{time.monotonic() - current_received_monotonic:.9f}"
            )
            current_row["log_status"] = "context_error"
            current_row["log_error"] = (
                "A fresh pose-specific experiment context was not received "
                "before the trajectory goal."
            )
            self._trace_writer.append(current_row)
            self.get_logger().error(current_row["log_error"])
            proxy_goal_handle.abort()
            return self._error_result(current_row["log_error"])

        if configuration_error:
            current_row["completed_at"] = timestamp()
            current_row["proxy_total_seconds"] = (
                f"{time.monotonic() - current_received_monotonic:.9f}"
            )
            current_row["log_status"] = "attack_configuration_error"
            current_row["log_error"] = configuration_error
            self._trace_writer.append(current_row)
            self.get_logger().error(configuration_error)
            proxy_goal_handle.abort()
            return self._error_result(configuration_error)

        replay_applied = bool(replay_plan.get("apply", False))

        if replay_applied:
            assert replay_goal is not None

            replay_command_id = uuid.uuid4().hex
            replay_sequence_index = self._next_sequence_index()
            replay_received_monotonic = time.monotonic()
            replay_received_at = timestamp()

            replay_row = self._base_row(
                command_id=replay_command_id,
                sequence_index=replay_sequence_index,
                proxy_mode=PROXY_MODE_REPLAYED,
                context=context,
                received_at=replay_received_at,
                original_goal=replay_goal,
                forwarded_goal=replay_goal,
            )
            replay_row.update(
                {
                    "attack_active": 1,
                    "command_replayed": 1,
                    "attack_applied": 1,
                    "source_command_id": replay_plan[
                        "source_command_id"
                    ],
                    "source_run_key": replay_plan["source_run_key"],
                }
            )

            attack_event_id = ""
            stop_published = False

            # Ensure each replay start event receives at most one stop event.
            def publish_stop_once(end_reason: str) -> None:
                nonlocal stop_published
                if not attack_event_id or stop_published:
                    return
                self.publish_attack_stop(
                    context=context,
                    attack_event_id=attack_event_id,
                    command_id=replay_command_id,
                    end_reason=end_reason,
                )
                stop_published = True
                replay_row["attack_status_stop_published"] = 1

            try:
                attack_event_id = self.publish_attack_start(
                    context=context,
                    command_id=replay_command_id,
                    attack_event_id=str(
                        context.get("attack_event_id", "")
                    ).strip(),
                )
                replay_row["attack_event_id"] = attack_event_id
                replay_row["attack_status_start_published"] = 1

                self.get_logger().warning(
                    "REPLAY ATTACK applied: "
                    f"run={replay_row['run_key']}, "
                    f"target_phase={replay_row['task_phase']}, "
                    f"commands_back={replay_plan['commands_back']}, "
                    f"source_phase={replay_plan['source_task_phase']}, "
                    f"source_pose={replay_plan['source_pose_name']}, "
                    f"source="
                    f"{str(replay_plan['source_command_id'])[:8]}"
                )

                replay_result, replay_status = (
                    await self._send_controller_goal(
                        proxy_goal_handle=proxy_goal_handle,
                        goal=replay_goal,
                        row=replay_row,
                        timing_origin=replay_received_monotonic,
                        feedback_callback=None,
                    )
                )

                if replay_status == GoalStatus.STATUS_SUCCEEDED:
                    replay_end_reason = (
                        "replayed_controller_succeeded"
                    )
                elif replay_status == GoalStatus.STATUS_CANCELED:
                    replay_end_reason = (
                        "replayed_controller_canceled"
                    )
                else:
                    replay_end_reason = "replayed_controller_failed"

                publish_stop_once(replay_end_reason)
                self._trace_writer.append(replay_row)

                if replay_status != GoalStatus.STATUS_SUCCEEDED:
                    current_row["completed_at"] = timestamp()
                    current_row["proxy_total_seconds"] = (
                        f"{time.monotonic() - current_received_monotonic:.9f}"
                    )
                    current_row["log_status"] = (
                        "replayed_command_failed"
                    )
                    current_row["log_error"] = (
                        "The replayed trajectory failed before the "
                        "current legitimate command could be forwarded."
                    )
                    self._trace_writer.append(current_row)
                    proxy_goal_handle.abort()
                    return replay_result

            except Exception as exc:
                replay_row["completed_at"] = timestamp()
                replay_row["proxy_total_seconds"] = (
                    f"{time.monotonic() - replay_received_monotonic:.9f}"
                )
                replay_row["log_status"] = "proxy_exception"
                replay_row["log_error"] = str(exc)
                publish_stop_once("proxy_exception")

                try:
                    self._trace_writer.append(replay_row)
                except Exception as logging_exc:
                    self.get_logger().error(
                        "The replay-command failure could not be "
                        f"logged: {logging_exc}"
                    )

                current_row["completed_at"] = timestamp()
                current_row["proxy_total_seconds"] = (
                    f"{time.monotonic() - current_received_monotonic:.9f}"
                )
                current_row["log_status"] = "replay_proxy_exception"
                current_row["log_error"] = str(exc)
                self._trace_writer.append(current_row)

                self.get_logger().error(
                    f"Replayed command failed in the proxy: {exc}"
                )
                proxy_goal_handle.abort()
                return self._error_result(str(exc))

        try:
            feedback_callback = lambda feedback_message: (
                proxy_goal_handle.publish_feedback(
                    feedback_message.feedback
                )
            )

            legitimate_result, legitimate_status = (
                await self._send_controller_goal(
                    proxy_goal_handle=proxy_goal_handle,
                    goal=original_goal,
                    row=current_row,
                    timing_origin=current_received_monotonic,
                    feedback_callback=feedback_callback,
                )
            )

            if legitimate_status == GoalStatus.STATUS_SUCCEEDED:
                self._store_successful_legitimate_command(
                    context=context,
                    command_id=current_command_id,
                    goal=original_goal,
                )

            self._trace_writer.append(current_row)

            if legitimate_status == GoalStatus.STATUS_SUCCEEDED:
                proxy_goal_handle.succeed()
            elif legitimate_status == GoalStatus.STATUS_CANCELED:
                proxy_goal_handle.canceled()
            else:
                proxy_goal_handle.abort()

            self.get_logger().info(
                f"Legitimate command {current_sequence_index} completed: "
                f"status={current_row['log_status']}, "
                f"error_code={current_row['result_error_code']}, "
                f"replay_triggered={int(replay_applied)}"
            )
            return legitimate_result

        except Exception as exc:
            current_row["completed_at"] = timestamp()
            current_row["proxy_total_seconds"] = (
                f"{time.monotonic() - current_received_monotonic:.9f}"
            )
            current_row["log_status"] = "proxy_exception"
            current_row["log_error"] = str(exc)

            try:
                self._trace_writer.append(current_row)
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


# Define proxy options while excluding ROS-specific command-line arguments.
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Sentinel Arm prior-command replay proxy."
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
        "--maximum-replays-per-run",
        type=int,
        default=DEFAULT_MAXIMUM_REPLAYS_PER_RUN,
        help=(
            "Maximum number of old commands replayed in one run. "
            f"Default: {DEFAULT_MAXIMUM_REPLAYS_PER_RUN}."
        ),
    )
    parser.add_argument(
        "--maximum-history-per-run",
        type=int,
        default=DEFAULT_MAXIMUM_HISTORY_PER_RUN,
        help=(
            "Maximum successful legitimate commands retained per run. "
            f"Default: {DEFAULT_MAXIMUM_HISTORY_PER_RUN}."
        ),
    )

    arguments_without_ros = remove_ros_args()[1:]
    return parser.parse_args(arguments_without_ros)


# Initialise ROS, run the multithreaded proxy and guarantee orderly shutdown.
def main(args: Sequence[str] | None = None) -> None:
    rclpy.init(args=args)
    arguments = parse_arguments()

    node = ArmReplayProxy(
        proxy_action=arguments.proxy_action,
        controller_action=arguments.controller_action,
        context_topic=arguments.context_topic,
        attack_status_topic=arguments.attack_status_topic,
        command_trace_csv=arguments.command_trace_csv,
        maximum_replays_per_run=arguments.maximum_replays_per_run,
        maximum_history_per_run=arguments.maximum_history_per_run,
    )

    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(node)
    exit_code = 0

    try:
        if not node.wait_for_controller(timeout_seconds=30.0):
            exit_code = 1
            return

        node.get_logger().info(
            "Replay proxy is ready. Keep this terminal running."
        )
        executor.spin()

    except KeyboardInterrupt:
        node.get_logger().info("Replay proxy stopped by the user.")

    except Exception as exc:
        exit_code = 1
        node.get_logger().error(
            f"Replay proxy terminated unexpectedly: {exc}"
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
