#!/usr/bin/env python3

from launch import LaunchDescription
from launch.actions import (
    IncludeLaunchDescription,
    RegisterEventHandler,
)
from launch.event_handlers import OnProcessExit
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import Command, FindExecutable, PathJoinSubstitution

from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue
from launch_ros.substitutions import FindPackageShare


def generate_launch_description():

    description_share = FindPackageShare(
        package='sentinel_arm_description'
    )

    gazebo_share = FindPackageShare(
        package='sentinel_arm_gazebo'
    )

    ros_gz_sim_share = FindPackageShare(
        package='ros_gz_sim'
    )

    xacro_file = PathJoinSubstitution([
        description_share,
        'urdf',
        'sentinel_arm.urdf.xacro'
    ])

    world_file = PathJoinSubstitution([
        gazebo_share,
        'worlds',
        'sentinel_lab.sdf'
    ])

    robot_description = ParameterValue(
        Command([
            FindExecutable(name='xacro'),
            ' ',
            xacro_file
        ]),
        value_type=str
    )

    robot_state_publisher = Node(
        package='robot_state_publisher',
        executable='robot_state_publisher',
        name='robot_state_publisher',
        output='screen',
        parameters=[{
            'robot_description': robot_description,
            'use_sim_time': True
        }]
    )

    gazebo = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            PathJoinSubstitution([
                ros_gz_sim_share,
                'launch',
                'gz_sim.launch.py'
            ])
        ),
        launch_arguments={
            # Keep it headless while testing the controllers.
            'gz_args': ['-s -r -v 4 ', world_file]
        }.items()
    )

    clock_bridge = Node(
        package='ros_gz_bridge',
        executable='parameter_bridge',
        name='clock_bridge',
        output='screen',
        arguments=[
            '/clock@rosgraph_msgs/msg/Clock[gz.msgs.Clock'
        ]
    )

    spawn_robot = Node(
        package='ros_gz_sim',
        executable='create',
        name='spawn_sentinel_arm',
        output='screen',
        arguments=[
            '-topic', '/robot_description',
            '-name', 'sentinel_arm',
            '-allow_renaming', 'false',
            '-x', '0.0',
            '-y', '0.0',
            '-z', '0.0'
        ]
    )

    joint_state_broadcaster_spawner = Node(
        package='controller_manager',
        executable='spawner',
        name='joint_state_broadcaster_spawner',
        output='screen',
        arguments=[
            'joint_state_broadcaster',
            '--controller-manager',
            '/controller_manager',
            '--controller-manager-timeout',
            '60'
        ]
    )

    arm_controller_spawner = Node(
        package='controller_manager',
        executable='spawner',
        name='arm_controller_spawner',
        output='screen',
        arguments=[
            'arm_controller',
            '--controller-manager',
            '/controller_manager',
            '--controller-manager-timeout',
            '60'
        ]
    )

    gripper_controller_spawner = Node(
        package='controller_manager',
        executable='spawner',
        name='gripper_controller_spawner',
        output='screen',
        arguments=[
            'gripper_controller',
            '--controller-manager',
            '/controller_manager',
            '--controller-manager-timeout',
            '60'
        ]
    )

    # Load the joint-state broadcaster only after robot spawning finishes.
    start_joint_state_broadcaster = RegisterEventHandler(
        OnProcessExit(
            target_action=spawn_robot,
            on_exit=[joint_state_broadcaster_spawner]
        )
    )

    # Load the arm controller only after the broadcaster finishes loading.
    start_arm_controller = RegisterEventHandler(
        OnProcessExit(
            target_action=joint_state_broadcaster_spawner,
            on_exit=[arm_controller_spawner]
        )
    )

    # Load the gripper after the arm controller finishes loading.
    start_gripper_controller = RegisterEventHandler(
        OnProcessExit(
            target_action=arm_controller_spawner,
            on_exit=[gripper_controller_spawner]
        )
    )

    return LaunchDescription([
        robot_state_publisher,
        gazebo,
        clock_bridge,

        # Register these before starting their target processes.
        start_joint_state_broadcaster,
        start_arm_controller,
        start_gripper_controller,

        spawn_robot
    ])