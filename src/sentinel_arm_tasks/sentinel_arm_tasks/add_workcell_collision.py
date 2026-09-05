#!/usr/bin/env python3

from typing import Sequence

import rclpy
from geometry_msgs.msg import Pose
from moveit_msgs.msg import CollisionObject, PlanningScene
from moveit_msgs.srv import ApplyPlanningScene
from rclpy.node import Node
from shape_msgs.msg import SolidPrimitive


PLANNING_FRAME = 'base_link'


def create_box(
    object_id: str,
    size: Sequence[float],
    position: Sequence[float],
) -> CollisionObject:

    collision_object = CollisionObject()
    collision_object.header.frame_id = PLANNING_FRAME
    collision_object.id = object_id

    primitive = SolidPrimitive()
    primitive.type = SolidPrimitive.BOX
    primitive.dimensions = list(size)

    pose = Pose()
    pose.position.x = float(position[0])
    pose.position.y = float(position[1])
    pose.position.z = float(position[2])
    pose.orientation.w = 1.0

    collision_object.primitives = [primitive]
    collision_object.primitive_poses = [pose]
    collision_object.operation = CollisionObject.ADD

    return collision_object


class WorkcellCollisionLoader(Node):

    def __init__(self) -> None:
        super().__init__('sentinel_workcell_collision_loader')

        self.client = self.create_client(
            ApplyPlanningScene,
            '/apply_planning_scene',
        )

    def apply_workcell(self) -> bool:
        """Add the tabletop and pickup cube to MoveIt."""

        self.get_logger().info(
            'Waiting for MoveIt planning-scene service...'
        )

        if not self.client.wait_for_service(timeout_sec=15.0):
            self.get_logger().error(
                'The /apply_planning_scene service is unavailable. '
                'Check that move_group is running.'
            )
            return False

        tabletop = create_box(
            object_id='sentinel_tabletop',
            size=(0.90, 0.60, 0.05),
            position=(0.30, 0.00, -0.026),
        )

        # The cube settles on the tabletop.
        # Its centre is approximately:
        #   world x=0.55, y=0.00, z=0.50
        pickup_cube = create_box(
            object_id='pickup_cube',
            size=(0.05, 0.05, 0.05),
            position=(0.60, 0.00, 0.024),
        )

        planning_scene = PlanningScene()
        planning_scene.is_diff = True
        planning_scene.world.collision_objects = [
            tabletop,
            pickup_cube,
        ]

        request = ApplyPlanningScene.Request()
        request.scene = planning_scene

        self.get_logger().info(
            'Adding the tabletop and pickup cube to MoveIt...'
        )

        future = self.client.call_async(request)
        rclpy.spin_until_future_complete(
            self,
            future,
            timeout_sec=15.0,
        )

        response = future.result()

        if response is None:
            self.get_logger().error(
                'MoveIt returned no planning-scene response.'
            )
            return False

        if not response.success:
            self.get_logger().error(
                'MoveIt rejected the planning-scene update.'
            )
            return False

        self.get_logger().info(
            'Sentinel workcell added to MoveIt successfully.'
        )
        return True


def main(args=None) -> None:
    rclpy.init(args=args)
    node = WorkcellCollisionLoader()
    success = False

    try:
        success = node.apply_workcell()
    except KeyboardInterrupt:
        node.get_logger().warning(
            'Planning-scene update interrupted.'
        )
    finally:
        node.destroy_node()
        rclpy.shutdown()

    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
