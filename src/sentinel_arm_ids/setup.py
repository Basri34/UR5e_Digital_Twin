from glob import glob

from setuptools import find_packages, setup


PACKAGE_NAME = "sentinel_arm_ids"


setup(
    name=PACKAGE_NAME,
    version="0.1.0",
    packages=find_packages(exclude=("test",)),
    data_files=[
        (
            "share/ament_index/resource_index/packages",
            [f"resource/{PACKAGE_NAME}"],
        ),
        (f"share/{PACKAGE_NAME}", ["package.xml", "requirements.txt"]),
        (f"share/{PACKAGE_NAME}/launch", glob("launch/*.launch.py")),
        (f"share/{PACKAGE_NAME}/config", glob("config/*.yaml")),
        (f"share/{PACKAGE_NAME}/models", glob("models/*")),
    ],
    install_requires=["setuptools"],
    zip_safe=False,
    maintainer="Sentinel Arm Researcher",
    maintainer_email="researcher@example.com",
    description=(
        "Command-aligned intrusion detection and prevention for the Sentinel "
        "Arm ROS 2 digital twin."
    ),
    license="MIT",
    entry_points={
        "console_scripts": [
            "idps_gateway = sentinel_arm_ids.idps_gateway:main",
            "live_ids_node = sentinel_arm_ids.live_ids_node:main",
        ],
    },
)
