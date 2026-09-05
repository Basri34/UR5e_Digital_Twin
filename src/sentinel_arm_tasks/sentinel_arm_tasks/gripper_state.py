#!/usr/bin/env python3

import time

import rclpy
from rclpy.node import Node
from sensor_msgs.msg import JointState


GRIPPER_PREFIX = 'robotiq_85_'


class GripperStateReader(Node):

    def __init__(self) -> None:
        super().__init__('sentinel_gripper_state_reader')

        self.received = False

        self.subscription = self.create_subscription(
            JointState,
            '/joint_states',
            self.joint_state_callback,
            10,
        )

    def joint_state_callback(self, message: JointState) -> None:

        matching_indices = [
            index
            for index, name in enumerate(message.name)
            if name.startswith(GRIPPER_PREFIX)
        ]

        if not matching_indices:
            return

        self.get_logger().info(
            'Current Robotiq joint states:'
        )

        for index in matching_indices:
            name = message.name[index]

            position = (
                message.position[index]
                if index < len(message.position)
                else float('nan')
            )

            velocity = (
                message.velocity[index]
                if index < len(message.velocity)
                else float('nan')
            )

            self.get_logger().info(
                f'{name}: '
                f'position={position:.6f}, '
                f'velocity={velocity:.6f}'
            )

        self.received = True


def main(args=None) -> None:
    rclpy.init(args=args)
    node = GripperStateReader()

    deadline = time.monotonic() + 5.0

    try:
        while (
            rclpy.ok()
            and not node.received
            and time.monotonic() < deadline
        ):
            rclpy.spin_once(
                node,
                timeout_sec=0.2,
            )

        if not node.received:
            node.get_logger().error(
                'No Robotiq joint states were received '
                'within five seconds.'
            )
            success = False
        else:
            success = True

    except KeyboardInterrupt:
        success = False
        node.get_logger().warning(
            'Gripper-state reading interrupted.'
        )

    finally:
        node.destroy_node()
        rclpy.shutdown()

    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
