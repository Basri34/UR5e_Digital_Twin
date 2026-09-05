#!/usr/bin/env python3

import csv
import json
import math
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import rclpy
from action_msgs.msg import GoalStatus
from ament_index_python.packages import get_package_share_directory
from control_msgs.action import FollowJointTrajectory
from rclpy.action import ActionClient, ActionServer
from rclpy.action.server import CancelResponse, GoalResponse
from rclpy.callback_groups import ReentrantCallbackGroup
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

from .features import JOINTS, JOINT_NAMES
from .model_runtime import validate_runtime_version


# Exact feature order expected by the serialized pre-execution model.  The model
# bundle is checked against this schema at startup to prevent silent misalignment.
FEATURE_COLUMNS = sorted(
    [
        "cyber_command_ordinal",
        "cyber_is_first_command",
        "cyber_time_since_previous_command_s",
        "cyber_context_age_seconds",
        "cyber_forwarded_duration_seconds",
        "cyber_target_delta_l1",
        "cyber_target_delta_l2",
    ]
    + [
        name
        for joint in JOINTS
        for name in (
            f"cyber_target_{joint}",
            f"cyber_target_delta_{joint}",
        )
    ]
)

# Complete audit trail for each gateway decision and downstream controller result.
LOG_FIELDS = [
    "decided_at",
    "decision_id",
    "run_key",
    "task_type",
    "task_phase",
    "pose_name",
    "prevention_mode",
    "model_label",
    "confidence",
    "normal_probability",
    "attack_probability",
    "class_probabilities_json",
    "block_confidence_threshold",
    "suspicious",
    "action",
    "reason",
    "inference_ms",
    "forwarded",
    "blocked",
    "controller_goal_sent",
    "controller_goal_accepted",
    "controller_status",
    "result_error_code",
    "result_error_string",
    "joint_names_json",
    "final_targets_json",
    "trajectory_duration_seconds",
    "context_age_seconds",
]


# Return a timezone-aware ISO timestamp with millisecond precision.
def timestamp():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


# Classify, optionally block, and otherwise forward trajectory goals.
class IdpsGateway(Node):
    def __init__(self):
        # Load the classifier and configure ROS actions, context and logging.
        super().__init__("sentinel_idps_gateway")

        share = Path(get_package_share_directory("sentinel_arm_ids"))
        # The gateway and controller use separate actions so the decision is made
        # before any trajectory is submitted to ros2_control.
        self.declare_parameter(
            "gateway_action",
            "/sentinel/idps/follow_joint_trajectory",
        )
        self.declare_parameter(
            "controller_action",
            "/scaled_joint_trajectory_controller/follow_joint_trajectory",
        )
        self.declare_parameter(
            "context_topic",
            "/sentinel/experiment/context",
        )
        self.declare_parameter(
            "decision_topic",
            "/sentinel/idps/decision",
        )
        self.declare_parameter(
            "decision_log_csv",
            "~/master_project/sentinel_arm_ws/data/idps_decisions.csv",
        )
        self.declare_parameter(
            "model_path",
            str(share / "models" / "best_preexecution_idps_model.joblib"),
        )
        self.declare_parameter("prevention_mode", "monitor")
        self.declare_parameter("block_confidence_threshold", 0.99)
        self.declare_parameter("controller_wait_timeout_seconds", 30.0)

        self.gateway_action = self.get_parameter("gateway_action").value
        self.controller_action = self.get_parameter("controller_action").value
        self.context_topic = self.get_parameter("context_topic").value
        self.decision_topic = self.get_parameter("decision_topic").value
        self.log_path = Path(
            self.get_parameter("decision_log_csv").value
        ).expanduser().resolve()
        self.prevention_mode = str(
            self.get_parameter("prevention_mode").value
        ).strip().lower()
        self.block_threshold = float(
            self.get_parameter("block_confidence_threshold").value
        )
        self.controller_wait_timeout = float(
            self.get_parameter("controller_wait_timeout_seconds").value
        )

        if self.prevention_mode not in {"monitor", "block"}:
            raise ValueError("prevention_mode must be 'monitor' or 'block'.")
        if not 0.0 < self.block_threshold <= 1.0:
            raise ValueError("block_confidence_threshold must be in (0, 1].")

        model_path = Path(
            self.get_parameter("model_path").value
        ).expanduser().resolve()
        # Refuse to load an incompatible artifact or feature order; either mismatch
        # could otherwise produce plausible but invalid security decisions.
        validate_runtime_version(model_path)
        bundle = joblib.load(model_path)
        if bundle["feature_columns"] != FEATURE_COLUMNS:
            raise RuntimeError(
                "The pre-execution model feature columns do not match the gateway."
            )
        self.model = bundle["model"]

        # A re-entrant callback group permits context updates, cancellation and
        # controller feedback while an action goal is awaiting completion.
        self._callback_group = ReentrantCallbackGroup()
        self._context_lock = threading.Lock()
        self._feature_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._goal_lock = threading.Lock()
        # Context and previous-command state are stored per run because timing and
        # target deltas are meaningful only within the same task execution.
        self._experiment_context = {}
        self._previous_targets = {}
        self._previous_arrivals = {}
        self._ordinals = {}
        self._controller_goals = {}
        self._pending_cancels = set()

        qos = QoSProfile(depth=50)
        qos.reliability = ReliabilityPolicy.RELIABLE
        self.create_subscription(
            String,
            self.context_topic,
            self._context_callback,
            qos,
            callback_group=self._callback_group,
        )
        self._decision_publisher = self.create_publisher(
            String,
            self.decision_topic,
            qos,
            callback_group=self._callback_group,
        )
        self._controller_client = ActionClient(
            self,
            FollowJointTrajectory,
            self.controller_action,
            callback_group=self._callback_group,
        )
        self._gateway_server = ActionServer(
            self,
            FollowJointTrajectory,
            self.gateway_action,
            execute_callback=self._execute_callback,
            goal_callback=self._goal_callback,
            cancel_callback=self._cancel_callback,
            callback_group=self._callback_group,
        )

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            with self.log_path.open("w", newline="", encoding="utf-8") as stream:
                csv.DictWriter(stream, fieldnames=LOG_FIELDS).writeheader()

        self.get_logger().info("Sentinel pre-execution IDPS gateway created.")
        self.get_logger().info(f"Proxy-facing action: {self.gateway_action}")
        self.get_logger().info(f"Real controller action: {self.controller_action}")
        self.get_logger().info(
            f"Prevention mode: {self.prevention_mode}; "
            f"block threshold: {self.block_threshold:.3f}"
        )
        self.get_logger().info(f"Decision log: {self.log_path}")

    def wait_for_controller(self):
        # Wait for the downstream UR5e controller before accepting gateway goals.
        self.get_logger().info("Waiting for the real UR5e trajectory controller...")
        ready = self._controller_client.wait_for_server(
            timeout_sec=self.controller_wait_timeout
        )
        if ready:
            self.get_logger().info("Real trajectory controller is available.")
        else:
            self.get_logger().error("Real trajectory controller is unavailable.")
        return ready

    def _context_callback(self, message):
        # Store the latest task phase and run metadata published by the task node.
        try:
            payload = json.loads(message.data)
        except json.JSONDecodeError as exc:
            self.get_logger().error(f"Invalid experiment-context JSON: {exc}")
            return
        if not isinstance(payload, dict):
            return
        payload["received_monotonic"] = time.monotonic()
        with self._context_lock:
            self._experiment_context = payload

    def _goal_callback(self, request):
        # Reject malformed goals or goals that cannot currently be forwarded.
        trajectory = request.trajectory
        if set(trajectory.joint_names) != set(JOINT_NAMES):
            self.get_logger().error(
                f"Rejected trajectory with unexpected joints: {trajectory.joint_names}"
            )
            return GoalResponse.REJECT
        if not trajectory.points:
            self.get_logger().error("Rejected trajectory with no points.")
            return GoalResponse.REJECT
        if any(
            len(point.positions) != len(trajectory.joint_names)
            for point in trajectory.points
        ):
            self.get_logger().error("Rejected trajectory with incomplete positions.")
            return GoalResponse.REJECT
        if not self._controller_client.server_is_ready():
            self.get_logger().error("Rejected trajectory: controller unavailable.")
            return GoalResponse.REJECT
        return GoalResponse.ACCEPT

    def _cancel_callback(self, goal_handle):
        # Propagate an upstream cancellation to its downstream controller goal.
        key = tuple(goal_handle.goal_id.uuid)
        with self._goal_lock:
            self._pending_cancels.add(key)
            controller_goal = self._controller_goals.get(key)
        if controller_goal is not None:
            controller_goal.cancel_goal_async()
        return CancelResponse.ACCEPT

    def _features(self, request):
        # Construct the command-only feature vector available before execution.
        now = time.monotonic()
        with self._context_lock:
            context = dict(self._experiment_context)

        run_key = str(context.get("run_key", "")).strip() or "unassigned"
        names = list(request.trajectory.joint_names)
        positions = list(request.trajectory.points[-1].positions)
        target_map = dict(zip(names, positions))
        targets = np.asarray([target_map[name] for name in JOINT_NAMES], dtype=float)

        # Update per-run history atomically because multiple action callbacks may be
        # active under the multi-threaded executor.
        with self._feature_lock:
            previous = self._previous_targets.get(run_key)
            previous_arrival = self._previous_arrivals.get(run_key)
            ordinal = self._ordinals.get(run_key, 0)
            delta = np.zeros(len(JOINTS)) if previous is None else targets - previous
            since_previous = (
                math.nan if previous_arrival is None else now - previous_arrival
            )
            self._previous_targets[run_key] = targets
            self._previous_arrivals[run_key] = now
            self._ordinals[run_key] = ordinal + 1

        point_time = request.trajectory.points[-1].time_from_start
        duration = float(point_time.sec) + float(point_time.nanosec) / 1e9
        context_received = float(context.get("received_monotonic", 0.0) or 0.0)
        context_age = now - context_received if context_received else math.nan

        # No physical telemetry is used here: every value is available at the
        # gateway before the controller receives the requested trajectory.
        features = {
            "cyber_command_ordinal": float(ordinal),
            "cyber_is_first_command": float(previous is None),
            "cyber_time_since_previous_command_s": since_previous,
            "cyber_context_age_seconds": context_age,
            "cyber_forwarded_duration_seconds": duration,
            "cyber_target_delta_l1": float(np.sum(np.abs(delta))),
            "cyber_target_delta_l2": float(np.sqrt(np.sum(np.square(delta)))),
        }
        for index, joint in enumerate(JOINTS):
            features[f"cyber_target_{joint}"] = float(targets[index])
            features[f"cyber_target_delta_{joint}"] = float(delta[index])
        return features, context, targets, duration, context_age

    def _predict(self, features):
        # Return the most likely class, confidence, probabilities and latency.
        frame = pd.DataFrame(
            [[features[name] for name in FEATURE_COLUMNS]],
            columns=FEATURE_COLUMNS,
        )
        started = time.perf_counter()
        probabilities = self.model.predict_proba(frame)[0]
        inference_ms = (time.perf_counter() - started) * 1000.0
        classes = [str(value) for value in self.model.classes_]
        best = int(np.argmax(probabilities))
        probability_map = {
            label: float(value)
            for label, value in zip(classes, probabilities, strict=True)
        }
        return (
            classes[best],
            float(probabilities[best]),
            probability_map,
            inference_ms,
        )

    def _write_log(self, row):
        # Append one complete decision under a lock to prevent interleaved writes.
        with self._log_lock:
            with self.log_path.open("a", newline="", encoding="utf-8") as stream:
                csv.DictWriter(stream, fieldnames=LOG_FIELDS).writerow(row)

    def _publish_decision(self, row):
        # Publish the operational subset of a decision as compact JSON.
        payload = {
            name: row[name]
            for name in (
                "decided_at",
                "decision_id",
                "run_key",
                "task_phase",
                "pose_name",
                "prevention_mode",
                "model_label",
                "confidence",
                "suspicious",
                "action",
                "reason",
                "inference_ms",
                "forwarded",
                "blocked",
            )
        }
        message = String()
        message.data = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        self._decision_publisher.publish(message)

    async def _execute_callback(self, goal_handle):
        # Classify a goal, enforce the mode policy and relay accepted commands.
        decision_id = uuid.uuid4().hex
        features, context, targets, duration, context_age = self._features(
            goal_handle.request
        )
        label, confidence, probabilities, inference_ms = self._predict(features)
        normal_probability = probabilities.get("normal", 0.0)
        has_context = bool(
            str(context.get("run_key", "")).strip()
            and str(context.get("pose_name", "")).strip()
        )
        # Blocking is deliberately conservative: valid task context, a non-normal
        # label and confidence at or above the threshold are all required.
        suspicious = bool(
            has_context
            and label != "normal"
            and confidence >= self.block_threshold
        )
        blocked = self.prevention_mode == "block" and suspicious

        if not has_context:
            reason = "insufficient_task_context"
        elif label != "normal" and confidence < self.block_threshold:
            reason = "attack_prediction_below_threshold"
        elif suspicious and self.prevention_mode == "monitor":
            reason = "attack_detected_monitor_mode"
        elif blocked:
            reason = "high_confidence_attack_prediction"
        else:
            reason = "normal_prediction"

        row = {
            "decided_at": timestamp(),
            "decision_id": decision_id,
            "run_key": context.get("run_key", ""),
            "task_type": context.get("task_type", ""),
            "task_phase": context.get("task_phase", "unassigned"),
            "pose_name": context.get("pose_name", ""),
            "prevention_mode": self.prevention_mode,
            "model_label": label,
            "confidence": f"{confidence:.9f}",
            "normal_probability": f"{normal_probability:.9f}",
            "attack_probability": f"{1.0 - normal_probability:.9f}",
            "class_probabilities_json": json.dumps(
                probabilities, separators=(",", ":"), sort_keys=True
            ),
            "block_confidence_threshold": f"{self.block_threshold:.9f}",
            "suspicious": int(suspicious),
            "action": "blocked" if blocked else "forwarded",
            "reason": reason,
            "inference_ms": f"{inference_ms:.3f}",
            "forwarded": int(not blocked),
            "blocked": int(blocked),
            "controller_goal_sent": 0,
            "controller_goal_accepted": 0,
            "controller_status": "",
            "result_error_code": "",
            "result_error_string": "",
            "joint_names_json": json.dumps(list(JOINT_NAMES), separators=(",", ":")),
            "final_targets_json": json.dumps(
                [float(value) for value in targets], separators=(",", ":")
            ),
            "trajectory_duration_seconds": f"{duration:.9f}",
            "context_age_seconds": (
                f"{context_age:.9f}" if math.isfinite(context_age) else ""
            ),
        }

        # Publish the decision before enforcement so monitoring observes blocked and
        # forwarded commands through the same interface.
        self._publish_decision(row)
        if blocked:
            result = FollowJointTrajectory.Result()
            result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
            result.error_string = (
                "Blocked by Sentinel IDPS: "
                f"predicted {label} with confidence {confidence:.3f}."
            )
            row["result_error_code"] = result.error_code
            row["result_error_string"] = result.error_string
            self._write_log(row)
            self.get_logger().warning(
                f"IDPS BLOCKED: run={row['run_key']}, phase={row['task_phase']}, "
                f"label={label}, confidence={confidence:.3f}, "
                "controller_goal_sent=0"
            )
            goal_handle.abort()
            return result

        self.get_logger().info(
            f"IDPS FORWARDED: run={row['run_key']}, phase={row['task_phase']}, "
            f"label={label}, confidence={confidence:.3f}, mode={self.prevention_mode}"
        )
        # Track the relationship between the gateway goal and real controller goal
        # so cancellation and final status propagate correctly across the boundary.
        key = tuple(goal_handle.goal_id.uuid)
        try:
            row["controller_goal_sent"] = 1
            send_future = self._controller_client.send_goal_async(
                goal_handle.request,
                feedback_callback=lambda message: goal_handle.publish_feedback(
                    message.feedback
                ),
            )
            controller_goal = await send_future
            if controller_goal is None or not controller_goal.accepted:
                result = FollowJointTrajectory.Result()
                result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
                result.error_string = (
                    "The real trajectory controller rejected the goal."
                )
                row["result_error_code"] = result.error_code
                row["result_error_string"] = result.error_string
                goal_handle.abort()
                self._write_log(row)
                return result

            row["controller_goal_accepted"] = 1
            with self._goal_lock:
                self._controller_goals[key] = controller_goal
                cancel_requested = key in self._pending_cancels
            if cancel_requested:
                controller_goal.cancel_goal_async()

            wrapped_result = await controller_goal.get_result_async()
            result = wrapped_result.result
            row["controller_status"] = int(wrapped_result.status)
            row["result_error_code"] = int(result.error_code)
            row["result_error_string"] = result.error_string
            if wrapped_result.status == GoalStatus.STATUS_SUCCEEDED:
                goal_handle.succeed()
            elif wrapped_result.status == GoalStatus.STATUS_CANCELED:
                goal_handle.canceled()
            else:
                goal_handle.abort()
            self._write_log(row)
            return result
        except Exception as exc:
            result = FollowJointTrajectory.Result()
            result.error_code = FollowJointTrajectory.Result.INVALID_GOAL
            result.error_string = f"IDPS gateway forwarding failed: {exc}"
            row["result_error_code"] = result.error_code
            row["result_error_string"] = result.error_string
            goal_handle.abort()
            self._write_log(row)
            self.get_logger().error(result.error_string)
            return result
        finally:
            with self._goal_lock:
                self._controller_goals.pop(key, None)
                self._pending_cancels.discard(key)

    def destroy_node(self):
        # Destroy both action endpoints before releasing the node.
        self._gateway_server.destroy()
        self._controller_client.destroy()
        return super().destroy_node()


# Run the gateway with concurrent action, context and feedback callbacks.
def main(args=None):
    rclpy.init(args=args)
    node = IdpsGateway()
    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(node)
    try:
        if not node.wait_for_controller():
            raise SystemExit(1)
        node.get_logger().info("IDPS gateway is ready. Keep this terminal running.")
        executor.spin()
    except KeyboardInterrupt:
        node.get_logger().info("IDPS gateway stopped by the user.")
    finally:
        executor.shutdown()
        executor.remove_node(node)
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()