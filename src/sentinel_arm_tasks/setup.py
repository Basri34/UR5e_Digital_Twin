from setuptools import find_packages, setup


package_name = "sentinel_arm_tasks"


setup(
    name=package_name,
    version="0.0.0",
    packages=find_packages(
        exclude=["test"],
    ),
    data_files=[
        (
            "share/ament_index/resource_index/packages",
            ["resource/" + package_name],
        ),
        (
            "share/" + package_name,
            ["package.xml"],
        ),
    ],
    install_requires=[
        "setuptools",
    ],
    zip_safe=True,
    maintainer="omar",
    maintainer_email="omar@example.com",
    description="Autonomous tasks and telemetry collection for Sentinel Arm.",
    license="Apache-2.0",
    tests_require=[
        "pytest",
    ],
    entry_points={
        "console_scripts": [
            "run_pose = sentinel_arm_tasks.run_pose:main",
            "repeat_short_task = sentinel_arm_tasks.repeat_short_task:program_entry_point",
            "repeat_long_task = sentinel_arm_tasks.repeat_long_task:program_entry_point",
            "object_detector = sentinel_arm_tasks.object_detector:main",
        ],
    },
)