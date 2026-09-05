#!/usr/bin/env python3

"""Launch the Sentinel UR5e workcell without MoveIt or RViz."""

from launch import LaunchDescription
from launch.actions import IncludeLaunchDescription
from launch.launch_description_sources import (
    PythonLaunchDescriptionSource,
)
from launch.substitutions import PathJoinSubstitution

from launch_ros.actions import Node
from launch_ros.substitutions import FindPackageShare


def generate_launch_description() -> LaunchDescription:
    """Launch Gazebo, the UR5e, controllers and camera bridge."""

    combined_description = PathJoinSubstitution([
        FindPackageShare('sentinel_arm_description'),
        'urdf',
        'sentinel_ur5e_robotiq.urdf.xacro',
    ])

    combined_controllers = PathJoinSubstitution([
        FindPackageShare('sentinel_arm_gazebo'),
        'config',
        'sentinel_ur5e_controllers.yaml',
    ])

    sentinel_simulation = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            PathJoinSubstitution([
                FindPackageShare('sentinel_arm_gazebo'),
                'launch',
                'sentinel_ur5e.launch.py',
            ])
        ),
        launch_arguments={
            'ur_type': 'ur5e',
            'description_file': combined_description,
            'controllers_file': combined_controllers,
            'gazebo_gui': 'true',

            # Do not start the basic UR RViz window.
            'launch_rviz': 'false',
        }.items(),
    )

    # Load and activate the Robotiq controller automatically.
    gripper_controller_spawner = Node(
        package='controller_manager',
        executable='spawner',
        name='robotiq_gripper_controller_spawner',
        output='screen',
        arguments=[
            'robotiq_gripper_controller',
            '--controller-manager',
            '/controller_manager',
            '--controller-manager-timeout',
            '60',
        ],
    )

    # Bridge the Gazebo overhead-camera topics into ROS 2.
    camera_bridge = Node(
        package='ros_gz_bridge',
        executable='parameter_bridge',
        name='sentinel_camera_bridge',
        output='screen',
        arguments=[
            (
                '/sentinel/overhead_camera/image'
                '@sensor_msgs/msg/Image'
                '[gz.msgs.Image'
            ),
            (
                '/sentinel/overhead_camera/camera_info'
                '@sensor_msgs/msg/CameraInfo'
                '[gz.msgs.CameraInfo'
            ),
        ],
    )

    return LaunchDescription([
        sentinel_simulation,
        gripper_controller_spawner,
        camera_bridge,
    ])