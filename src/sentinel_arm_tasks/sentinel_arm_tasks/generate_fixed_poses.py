#!/usr/bin/env python3

import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import rclpy

from geometry_msgs.msg import PoseStamped
from moveit_msgs.srv import GetPositionIK
from rclpy.node import Node
from sensor_msgs.msg import JointState


ARM_JOINTS = [
    'shoulder_pan_joint',
    'shoulder_lift_joint',
    'elbow_joint',
    'wrist_1_joint',
    'wrist_2_joint',
    'wrist_3_joint',
]

GROUP_NAME = 'ur_manipulator'
IK_LINK = 'tool0'
REFERENCE_FRAME = 'base_link'

FINGERTIP_OFFSET = 0.109

PICK_X = 0.60
PICK_Y = 0.00

PLACE_X = 0.60
PLACE_Y = 0.18

TOOL_ORIENTATION = (
    0.70710678,   # x
    0.70710678,   # y
    0.0,          # z
    0.0,          # w
)


def tool_height(fingertip_height: float) -> float:
    return fingertip_height + FINGERTIP_OFFSET


TARGETS: Dict[str, Tuple[float, float, float]] = {
    'pre_pick': (
        PICK_X,
        PICK_Y,
        tool_height(0.240),
    ),
    'approach_pick': (
        PICK_X,
        PICK_Y,
        tool_height(0.120),
    ),
    'pick': (
        PICK_X,
        PICK_Y,
        tool_height(0.040),
    ),
    'lift': (
        PICK_X,
        PICK_Y,
        tool_height(0.240),
    ),
    'pre_place': (
        PLACE_X,
        PLACE_Y,
        tool_height(0.240),
    ),
    'approach_place': (
        PLACE_X,
        PLACE_Y,
        tool_height(0.120),
    ),
    'place': (
        PLACE_X,
        PLACE_Y,
        tool_height(0.040),
    ),
    'retreat': (
        PLACE_X,
        PLACE_Y,
        tool_height(0.240),
    ),
}


class FixedPoseGenerator(Node):
    def __init__(self) -> None:
        super().__init__('sentinel_fixed_pose_generator')

        self.current_positions: Optional[List[float]] = None

        self.joint_subscription = self.create_subscription(
            JointState,
            '/joint_states',
            self.joint_state_callback,
            10,
        )

        self.ik_client = self.create_client(
            GetPositionIK,
            '/compute_ik',
        )

    def joint_state_callback(self, message: JointState) -> None:

        position_map = {
            name: float(position)
            for name, position in zip(
                message.name,
                message.position,
            )
        }

        if not all(
            name in position_map
            for name in ARM_JOINTS
        ):
            return

        self.current_positions = [
            position_map[name]
            for name in ARM_JOINTS
        ]

    def wait_for_current_state(self) -> bool:

        deadline = time.monotonic() + 10.0

        while (
            rclpy.ok()
            and self.current_positions is None
            and time.monotonic() < deadline
        ):
            rclpy.spin_once(
                self,
                timeout_sec=0.2,
            )

        if self.current_positions is None:
            self.get_logger().error(
                'No complete UR5e joint state was received.'
            )
            return False

        return True

    def solve_ik(
        self,
        pose_name: str,
        target: Sequence[float],
        seed: Sequence[float],
    ) -> Optional[List[float]]:

        request = GetPositionIK.Request()

        request.ik_request.group_name = GROUP_NAME
        request.ik_request.ik_link_name = IK_LINK
        request.ik_request.avoid_collisions = False

        request.ik_request.timeout.sec = 4
        request.ik_request.timeout.nanosec = 0

        request.ik_request.robot_state.joint_state.name = list(
            ARM_JOINTS
        )
        request.ik_request.robot_state.joint_state.position = [
            float(value)
            for value in seed
        ]

        pose = PoseStamped()
        pose.header.frame_id = REFERENCE_FRAME

        pose.pose.position.x = float(target[0])
        pose.pose.position.y = float(target[1])
        pose.pose.position.z = float(target[2])

        pose.pose.orientation.x = TOOL_ORIENTATION[0]
        pose.pose.orientation.y = TOOL_ORIENTATION[1]
        pose.pose.orientation.z = TOOL_ORIENTATION[2]
        pose.pose.orientation.w = TOOL_ORIENTATION[3]

        request.ik_request.pose_stamped = pose

        self.get_logger().info(
            f'Calculating "{pose_name}" at '
            f'x={target[0]:.3f}, '
            f'y={target[1]:.3f}, '
            f'z={target[2]:.3f}'
        )

        future = self.ik_client.call_async(request)

        rclpy.spin_until_future_complete(
            self,
            future,
            timeout_sec=8.0,
        )

        response = future.result()

        if response is None:
            self.get_logger().error(
                f'No IK response for "{pose_name}".'
            )
            return None

        if response.error_code.val != 1:
            self.get_logger().error(
                f'IK failed for "{pose_name}" with '
                f'error code {response.error_code.val}.'
            )
            return None

        solution_map = {
            name: float(position)
            for name, position in zip(
                response.solution.joint_state.name,
                response.solution.joint_state.position,
            )
        }

        if not all(
            name in solution_map
            for name in ARM_JOINTS
        ):
            self.get_logger().error(
                f'IK result for "{pose_name}" did not '
                'contain all six UR5e joints.'
            )
            return None

        solution = [
            solution_map[name]
            for name in ARM_JOINTS
        ]

        self.get_logger().info(
            f'"{pose_name}" = ['
            + ', '.join(
                f'{value:.8f}'
                for value in solution
            )
            + ']'
        )

        return solution


def write_pose_module(
    poses: Dict[str, List[float]],
    output_file: Path,
) -> None:

    lines = [
        '',
        'FIXED_ARM_POSES = {',
    ]

    for pose_name, positions in poses.items():
        lines.append(f"    '{pose_name}': [")

        for value in positions:
            lines.append(f'        {value:.10f},')

        lines.append('    ],')

    lines.append('}')
    lines.append('')

    output_file.write_text(
        '\n'.join(lines)
    )


def main(args=None) -> None:

    rclpy.init(args=args)
    node = FixedPoseGenerator()
    success = False

    try:
        if not node.wait_for_current_state():
            return

        node.get_logger().info(
            'Waiting for the MoveIt IK service...'
        )

        if not node.ik_client.wait_for_service(
            timeout_sec=15.0
        ):
            node.get_logger().error(
                '/compute_ik is unavailable. '
                'Start the Sentinel MoveIt launch first.'
            )
            return

        # A few possible first-pose seeds.
        seed_candidates = [
            list(node.current_positions),
            [
                0.0,
                -1.20,
                1.60,
                -1.95,
                -1.57,
                0.0,
            ],
            [
                0.0,
                -1.00,
                1.40,
                -1.95,
                -1.57,
                0.0,
            ],
        ]

        generated: Dict[str, List[float]] = {}
        previous_solution: Optional[List[float]] = None

        for pose_name, target in TARGETS.items():
            solution = None

            if previous_solution is not None:
                solution = node.solve_ik(
                    pose_name,
                    target,
                    previous_solution,
                )
            else:
                for seed in seed_candidates:
                    solution = node.solve_ik(
                        pose_name,
                        target,
                        seed,
                    )

                    if solution is not None:
                        break

            if solution is None:
                node.get_logger().error(
                    f'Could not generate all fixed poses. '
                    f'Failed at "{pose_name}".'
                )
                return

            generated[pose_name] = solution
            previous_solution = solution

        output_file = (
            Path.cwd()
            / 'src'
            / 'sentinel_arm_tasks'
            / 'sentinel_arm_tasks'
            / 'fixed_poses.py'
        )

        write_pose_module(
            generated,
            output_file,
        )

        node.get_logger().info(
            f'Saved fixed poses to {output_file}'
        )

        success = True

    except KeyboardInterrupt:
        node.get_logger().warning(
            'Pose generation interrupted.'
        )

    finally:
        node.destroy_node()
        rclpy.shutdown()

    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
