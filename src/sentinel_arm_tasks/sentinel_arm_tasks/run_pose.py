#!/usr/bin/env python3

import argparse
import json
import sys
import threading
import time
from typing import Any, Dict, List

import rclpy

from control_msgs.action import (
    FollowJointTrajectory,
    ParallelGripperCommand,
)
from rclpy.action import ActionClient
from rclpy.node import Node
from rclpy.utilities import remove_ros_args
from std_msgs.msg import String
from trajectory_msgs.msg import JointTrajectoryPoint


ARM_ACTION = (
    '/sentinel/arm_proxy/'
    'follow_joint_trajectory'
)

REAL_ARM_ACTION = (
    '/scaled_joint_trajectory_controller/'
    'follow_joint_trajectory'
)

EXPERIMENT_CONTEXT_TOPIC = (
    '/sentinel/experiment/context'
)

ATTACK_STATUS_TOPIC = (
    '/sentinel/attack/status'
)

GRIPPER_ACTION = (
    '/robotiq_gripper_controller/'
    'gripper_cmd'
)

GRIPPER_JOINT = 'robotiq_85_left_knuckle_joint'


ARM_JOINTS: List[str] = [
    'shoulder_pan_joint',
    'shoulder_lift_joint',
    'elbow_joint',
    'wrist_1_joint',
    'wrist_2_joint',
    'wrist_3_joint',
]


ARM_POSES: Dict[str, List[float]] = {
    'home': [
        0.0,
        -1.57,
        0.0,
        -1.57,
        0.0,
        0.0,
    ],

    'pickup_side_test': [
        0.20,
        -1.57,
        0.0,
        -1.57,
        0.0,
        0.0,
    ],

    'placement_side_test': [
        -0.20,
        -1.57,
        0.0,
        -1.57,
        0.0,
        0.0,
    ],
}

try:
    from sentinel_arm_tasks.fixed_poses import FIXED_ARM_POSES
except ImportError:
    FIXED_ARM_POSES = {}

ARM_POSES.update(FIXED_ARM_POSES)


GRIPPER_POSES: Dict[str, float] = {
    'gripper_open': 0.0,
    'gripper_half': 0.35,
    'gripper_grasp': 0.52,
    'gripper_close': 0.70,
}


class SentinelTaskController(Node):

    def __init__(self) -> None:
        super().__init__('sentinel_task_controller')

        self.arm_client = ActionClient(
            self,
            FollowJointTrajectory,
            ARM_ACTION,
        )

        self.gripper_client = ActionClient(
            self,
            ParallelGripperCommand,
            GRIPPER_ACTION,
        )

        self.experiment_context_publisher = self.create_publisher(
            String,
            EXPERIMENT_CONTEXT_TOPIC,
            10,
        )

        self.attack_status_subscription = self.create_subscription(
            String,
            ATTACK_STATUS_TOPIC,
            self._attack_status_callback,
            20,
        )

        self._experiment_context: Dict[str, Any] = {
            'session_id': '',
            'run_key': '',
            'run_id': '',
            'task_type': '',
            'condition': '',
            'attack_type': 'none',
            'attack_variant': 'none',
            'attack_severity': 'none',
            'attack_target': 'none',
            'attack_target_object': 'none',
            'attack_target_phase': 'none',
            'attack_parameter_value': '',
            'attack_parameter_unit': '',
            'attack_event_id': '',
            'attack_active': 0,
            'task_phase': 'outside_measurement',
        }

        self._attack_status_lock = threading.RLock()
        self._seen_attack_event_ids: set[str] = set()
        self._attack_status_summary: Dict[str, Any] = {
            'attack_successfully_injected': 0,
            'attack_injection_count': 0,
            'attack_event_id': '',
            'attack_event_ids': [],
            'attack_active': 0,
            'last_attack_end_reason': '',
        }

        self.get_logger().info(
            f'Arm commands will use the Sentinel proxy: {ARM_ACTION}'
        )

    def configure_experiment_context(
        self,
        *,
        session_id: str,
        run_id: int,
        task_type: str,
        condition: str,
        attack_type: str,
        initial_phase: str,
        attack_variant: str = 'none',
        attack_severity: str = 'none',
        attack_target: str = 'none',
        attack_target_object: str = 'none',
        attack_target_phase: str = 'none',
        attack_parameter_value: object = '',
        attack_parameter_unit: str = '',
        attack_event_id: str = '',
    ) -> None:

        self._experiment_context = {
            'session_id': str(session_id),
            'run_key': f'{session_id}:{run_id}',
            'run_id': int(run_id),
            'task_type': str(task_type),
            'condition': str(condition),
            'attack_type': str(attack_type),
            'attack_variant': str(attack_variant),
            'attack_severity': str(attack_severity),
            'attack_target': str(attack_target),
            'attack_target_object': str(attack_target_object),
            'attack_target_phase': str(attack_target_phase),
            'attack_parameter_value': str(attack_parameter_value),
            'attack_parameter_unit': str(attack_parameter_unit),
            'attack_event_id': str(attack_event_id),
            'attack_active': 0,
            'task_phase': str(initial_phase),
        }

        with self._attack_status_lock:
            self._seen_attack_event_ids.clear()
            self._attack_status_summary = {
                'attack_successfully_injected': 0,
                'attack_injection_count': 0,
                'attack_event_id': '',
                'attack_event_ids': [],
                'attack_active': 0,
                'last_attack_end_reason': '',
            }

        self.publish_experiment_context(
            pose_name='',
        )

    def _attack_status_callback(self, message: String) -> None:
        try:
            payload = json.loads(message.data)
        except json.JSONDecodeError as exc:
            self.get_logger().error(
                f'Invalid attack-status JSON: {exc}'
            )
            return

        if not isinstance(payload, dict):
            return

        current_session = str(
            self._experiment_context.get('session_id', '')
        )
        current_run = str(
            self._experiment_context.get('run_id', '')
        )
        payload_session = str(payload.get('session_id', ''))
        payload_run = str(payload.get('run_id', ''))

        if payload_session and payload_session != current_session:
            return

        if payload_run and payload_run != current_run:
            return

        action = str(payload.get('action', '')).strip().lower()
        is_start = action in {'start', 'begin', 'active'} or bool(
            payload.get('active', False)
        )
        is_stop = action in {'stop', 'end', 'inactive'}
        event_id = str(payload.get('attack_event_id', '')).strip()

        with self._attack_status_lock:
            if is_start:
                if event_id and event_id not in self._seen_attack_event_ids:
                    self._seen_attack_event_ids.add(event_id)
                    self._attack_status_summary[
                        'attack_injection_count'
                    ] = len(self._seen_attack_event_ids)
                    self._attack_status_summary[
                        'attack_event_ids'
                    ] = sorted(self._seen_attack_event_ids)

                self._attack_status_summary[
                    'attack_successfully_injected'
                ] = 1
                self._attack_status_summary['attack_active'] = 1

                if event_id:
                    self._attack_status_summary[
                        'attack_event_id'
                    ] = event_id
                    self._experiment_context[
                        'attack_event_id'
                    ] = event_id

                self._experiment_context['attack_active'] = 1

            elif is_stop:
                self._attack_status_summary['attack_active'] = 0
                self._attack_status_summary[
                    'last_attack_end_reason'
                ] = str(payload.get('end_reason', ''))
                self._experiment_context['attack_active'] = 0

    def get_attack_status_summary(self) -> Dict[str, Any]:
        with self._attack_status_lock:
            summary = dict(self._attack_status_summary)
            summary['attack_event_ids'] = list(
                self._attack_status_summary.get(
                    'attack_event_ids',
                    [],
                )
            )
            return summary

    def set_task_phase(self, task_phase: str) -> None:
        self._experiment_context['task_phase'] = str(task_phase)

    def clear_experiment_context(self) -> None:
        self._experiment_context = {
            'session_id': '',
            'run_key': '',
            'run_id': '',
            'task_type': '',
            'condition': 'preparation',
            'attack_type': 'none',
            'attack_variant': 'none',
            'attack_severity': 'none',
            'attack_target': 'none',
            'attack_target_object': 'none',
            'attack_target_phase': 'none',
            'attack_parameter_value': '',
            'attack_parameter_unit': '',
            'attack_event_id': '',
            'attack_active': 0,
            'task_phase': 'outside_measurement',
        }

        self.publish_experiment_context(
            pose_name='',
        )

    def publish_experiment_context(self, *, pose_name: str) -> None:
        payload = dict(self._experiment_context)
        payload['pose_name'] = str(pose_name)

        message = String()
        message.data = json.dumps(
            payload,
            separators=(',', ':'),
            sort_keys=True,
        )

        self.experiment_context_publisher.publish(message)

    def move_arm(self, pose_name: str, positions: List[float], duration: float) -> bool:
        if len(positions) != len(ARM_JOINTS):
            self.get_logger().error(
                f'Pose "{pose_name}" has {len(positions)} values; '
                f'{len(ARM_JOINTS)} are required.'
            )
            return False

        self.publish_experiment_context(
            pose_name=pose_name,
        )

        time.sleep(0.03)

        self.get_logger().info(
            f'Waiting for Sentinel arm proxy for "{pose_name}"...'
        )

        if not self.arm_client.wait_for_server(timeout_sec=10.0):
            self.get_logger().error(
                f'Arm proxy action server unavailable: {ARM_ACTION}'
            )
            self.get_logger().error(
                'Start arm_mitm_proxy.py before running a task. '
                f'The real controller remains at {REAL_ARM_ACTION}.'
            )
            return False

        goal = FollowJointTrajectory.Goal()
        goal.trajectory.joint_names = ARM_JOINTS

        point = JointTrajectoryPoint()
        point.positions = [
            float(position)
            for position in positions
        ]

        whole_seconds = int(duration)
        fractional_seconds = duration - whole_seconds

        point.time_from_start.sec = whole_seconds
        point.time_from_start.nanosec = int(
            fractional_seconds * 1_000_000_000
        )

        goal.trajectory.points = [point]

        self.get_logger().info(
            f'Moving arm to "{pose_name}" over '
            f'{duration:.1f} seconds.'
        )

        send_future = self.arm_client.send_goal_async(goal)
        rclpy.spin_until_future_complete(self, send_future)

        goal_handle = send_future.result()

        if goal_handle is None or not goal_handle.accepted:
            self.get_logger().error(
                f'Arm pose "{pose_name}" was rejected.'
            )
            return False

        result_future = goal_handle.get_result_async()

        rclpy.spin_until_future_complete(
            self,
            result_future,
            timeout_sec=duration + 10.0,
        )

        if not result_future.done():
            self.get_logger().error(
                f'Arm movement "{pose_name}" timed out.'
            )

            cancel_future = goal_handle.cancel_goal_async()
            rclpy.spin_until_future_complete(
                self,
                cancel_future,
                timeout_sec=3.0,
            )
            return False

        wrapped_result = result_future.result()

        if wrapped_result is None:
            self.get_logger().error(
                'No arm result was returned.'
            )
            return False

        result = wrapped_result.result

        if result.error_code != (
            FollowJointTrajectory.Result.SUCCESSFUL
        ):
            self.get_logger().error(
                f'Arm movement failed: '
                f'{result.error_code} '
                f'{result.error_string}'
            )
            return False

        self.get_logger().info(
            f'Arm pose "{pose_name}" reached.'
        )
        return True

    def move_gripper(self, pose_name: str, position: float) -> bool:
        self.get_logger().info(
            f'Waiting for gripper controller for '
            f'"{pose_name}"...'
        )

        if not self.gripper_client.wait_for_server(
            timeout_sec=10.0
        ):
            self.get_logger().error(
                f'Gripper action server unavailable: '
                f'{GRIPPER_ACTION}'
            )
            return False

        goal = ParallelGripperCommand.Goal()

        goal.command.name = [
            GRIPPER_JOINT,
        ]

        goal.command.position = [
            float(position),
        ]

        self.get_logger().info(
            f'Moving gripper to "{pose_name}" '
            f'at {position:.3f} radians.'
        )

        send_future = self.gripper_client.send_goal_async(goal)
        rclpy.spin_until_future_complete(
            self,
            send_future,
        )

        goal_handle = send_future.result()

        if goal_handle is None or not goal_handle.accepted:
            self.get_logger().error(
                f'Gripper pose "{pose_name}" was rejected.'
            )
            return False

        if pose_name == 'gripper_grasp':
            self.get_logger().info(
                'Applying grasp pressure for 1.5 seconds.'
            )

            deadline = time.monotonic() + 1.5

            while rclpy.ok() and time.monotonic() < deadline:
                rclpy.spin_once(
                    self,
                    timeout_sec=0.05,
                )

            self.get_logger().info(
                'Grasp command applied; continuing while '
                'the controller holds the cube.'
            )
            return True

        result_future = goal_handle.get_result_async()

        rclpy.spin_until_future_complete(
            self,
            result_future,
            timeout_sec=8.0,
        )

        if not result_future.done():
            self.get_logger().error(
                f'Gripper command "{pose_name}" timed out.'
            )

            cancel_future = goal_handle.cancel_goal_async()
            rclpy.spin_until_future_complete(
                self,
                cancel_future,
                timeout_sec=3.0,
            )
            return False

        wrapped_result = result_future.result()

        if wrapped_result is None:
            self.get_logger().error(
                'No gripper result was returned.'
            )
            return False

        result = wrapped_result.result

        result_fields = {
            field_name: getattr(result, field_name)
            for field_name in result.get_fields_and_field_types()
        }

        self.get_logger().info(
            f'Gripper result: {result_fields}'
        )

        reached_goal = bool(
            getattr(result, 'reached_goal', False)
        )

        stalled = bool(
            getattr(result, 'stalled', False)
        )

        if reached_goal:
            self.get_logger().info(
                f'Gripper pose "{pose_name}" reached.'
            )
            return True

        if stalled and pose_name == 'gripper_grasp':
            self.get_logger().info(
                'The gripper stopped against the cube; '
                'grasp accepted.'
            )
            return True

        if stalled:
            self.get_logger().error(
                'The gripper stalled without reaching '
                'the requested position.'
            )
        else:
            self.get_logger().error(
                'The gripper did not reach the requested '
                'position.'
            )

        return False


def parse_arguments() -> argparse.Namespace:
    available_commands = sorted(
        list(ARM_POSES.keys())
        + list(GRIPPER_POSES.keys())
    )

    parser = argparse.ArgumentParser(
        description=(
            'Move the Sentinel UR5e arm or '
            'Robotiq gripper.'
        )
    )

    parser.add_argument(
        'command',
        choices=available_commands,
        help='Named arm or gripper pose.',
    )

    parser.add_argument(
        '--duration',
        type=float,
        default=5.0,
        help=(
            'Arm movement duration in seconds. '
            'Ignored for gripper commands.'
        ),
    )

    arguments_without_ros = remove_ros_args(
        args=sys.argv
    )[1:]

    parsed = parser.parse_args(
        arguments_without_ros
    )

    if parsed.duration <= 0.0:
        parser.error(
            '--duration must be greater than zero.'
        )

    return parsed


def main(args=None) -> None:
    parsed = parse_arguments()

    rclpy.init(args=args)
    node = SentinelTaskController()
    success = False

    try:
        if parsed.command in ARM_POSES:
            success = node.move_arm(
                pose_name=parsed.command,
                positions=ARM_POSES[parsed.command],
                duration=parsed.duration,
            )
        else:
            success = node.move_gripper(
                pose_name=parsed.command,
                position=GRIPPER_POSES[
                    parsed.command
                ],
            )

    except KeyboardInterrupt:
        node.get_logger().warning(
            'Command interrupted by the user.'
        )

    finally:
        node.destroy_node()
        rclpy.shutdown()

    raise SystemExit(
        0 if success else 1
    )


if __name__ == '__main__':
    main()