from pathlib import Path

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description() -> LaunchDescription:
    package_share = Path(get_package_share_directory("sentinel_arm_ids"))
    default_config = str(package_share / "config" / "live_ids.yaml")

    config_file = LaunchConfiguration("config_file")
    return LaunchDescription(
        [
            DeclareLaunchArgument(
                "config_file",
                default_value=default_config,
                description="Path to the live IDS ROS parameter file.",
            ),
            Node(
                package="sentinel_arm_ids",
                executable="live_ids_node",
                name="sentinel_live_ids",
                output="screen",
                parameters=[config_file],
            ),
        ]
    )
