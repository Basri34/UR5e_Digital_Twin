#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import inspect
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

import rclpy

from sentinel_arm_tasks import run_pose as run_pose_module
from sentinel_arm_tasks.fixed_poses import FIXED_ARM_POSES
from sentinel_arm_tasks.telemetry_recorder import TelemetryRecorder

SentinelTaskController = run_pose_module.SentinelTaskController

# Location to go home
HOME_JOINTS = [
    0.0000,
    -1.5708,
    0.0000,
    -1.5708,
    0.0000,
    0.0000,
]

ARM_POSES = {
    name: list(positions)
    for name, positions in FIXED_ARM_POSES.items()
}

ARM_POSES["home"] = HOME_JOINTS


REQUIRED_SHORT_POSES = [
    "long_left_pick_high",
    "long_left_pick_near",
    "long_left_pick_lift",
    "long_cube_place_high",
    "long_cube_place_mid",
    "long_cube_place_near",
]

# Gripper positions
DEFAULT_GRIPPER_OPEN_POSITION = 0.0
DEFAULT_GRIPPER_GRASP_POSITION = 0.52

# Function to attempt to find the correct numerical positions for opening and closing the Robotiq gripper
def discover_gripper_positions() -> tuple[float, float]:
    candidate_names = [
        "GRIPPER_COMMANDS",
        "GRIPPER_POSES",
        "GRIPPER_POSITIONS",
    ]

    for attribute_name in candidate_names:
        mapping = getattr(
            run_pose_module,
            attribute_name,
            None,
        )

        if not isinstance(mapping, dict):
            continue

        open_position = None
        grasp_position = None

        for key in ("gripper_open", "open"):
            if key in mapping:
                open_position = float(mapping[key])
                break

        for key in (
            "gripper_grasp",
            "grasp",
            "close",
            "gripper_close",
        ):
            if key in mapping:
                grasp_position = float(mapping[key])
                break

        if (
            open_position is not None
            and grasp_position is not None
        ):
            return open_position, grasp_position

    return (
        DEFAULT_GRIPPER_OPEN_POSITION,
        DEFAULT_GRIPPER_GRASP_POSITION,
    )


(
    GRIPPER_OPEN_POSITION,
    GRIPPER_GRASP_POSITION,
) = discover_gripper_positions()


GRIPPER_ACTIONS = {
    "gripper_open": {
        "position": GRIPPER_OPEN_POSITION,
    },
    "gripper_grasp": {
        "position": GRIPPER_GRASP_POSITION,
    },
}

# The Gazebo objects used in the experiment

CUBE_NAME = "pickup_cube"

CUBE_POSITION = (
    0.4250,
    0.0800,
    0.5000,
)

STOP_REQUESTED = False
TASK_NODE: Any | None = None

# Sends information about the current experiment to the task controller, which includes the following:

def configure_task_context(
    *,
    session_id: str,
    run_id: int,
    task_type: str,
    condition: str,
    attack_type: str,
    initial_phase: str,
    attack_variant: str = "none",
    attack_severity: str = "none",
    attack_target: str = "none",
    attack_target_object: str = "none",
    attack_target_phase: str = "none",
    attack_parameter_value: object = "",
    attack_parameter_unit: str = "",
    attack_event_id: str = "",
) -> None:
    if TASK_NODE is None:
        raise RuntimeError(
            "The Sentinel task controller has not been initialised."
        )

    TASK_NODE.configure_experiment_context(
        session_id=session_id,
        run_id=run_id,
        task_type=task_type,
        condition=condition,
        attack_type=attack_type,
        initial_phase=initial_phase,
        attack_variant=attack_variant,
        attack_severity=attack_severity,
        attack_target=attack_target,
        attack_target_object=attack_target_object,
        attack_target_phase=attack_target_phase,
        attack_parameter_value=attack_parameter_value,
        attack_parameter_unit=attack_parameter_unit,
        attack_event_id=attack_event_id,
    )

# Clears the task 
# This function is important because movements such as going back home happen outside the experiment, so clearing the context prevents commands from being associated with previous measured runs
def clear_task_context() -> None:
    if TASK_NODE is not None:
        TASK_NODE.clear_experiment_context()

# Changes the current phase label 
def set_task_phase(telemetry_recorder: TelemetryRecorder, task_phase: str) -> None:
    telemetry_recorder.set_phase(task_phase)

    if TASK_NODE is None:
        raise RuntimeError(
            "The Sentinel task controller has not been initialised."
        )

    TASK_NODE.set_task_phase(task_phase)

# This function is responsible for handling OS signals such as stopping through Ctrl + C and requests from another process to terminate - standard function to include 
def handle_signal(signum: int, frame: object) -> None:
    del signum
    del frame

    global STOP_REQUESTED

    if not STOP_REQUESTED:
        print(
            "\n[SHORT TASK] Stop requested. "
            "Finishing the current controller command.",
            flush=True,
        )

    STOP_REQUESTED = True

# Function to return the current local date and time including ms and timezone used for constructing data
def timestamp() -> str:
    return datetime.now().astimezone().isoformat(
        timespec="milliseconds",
    )

# Runs an external Linux command from python
def run_command(command: Sequence[str], description: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    if STOP_REQUESTED:
        raise KeyboardInterrupt

    print(
        f"\n[SHORT TASK] {description}",
        flush=True,
    )

    print(
        f"[COMMAND] {' '.join(command)}",
        flush=True,
    )

    result = subprocess.run(
        list(command),
        check=False,
        text=True,
        capture_output=capture_output,
    )

    if capture_output:
        if result.stdout.strip():
            print(result.stdout.strip(), flush=True)

        if result.stderr.strip():
            print(
                result.stderr.strip(),
                file=sys.stderr,
                flush=True,
            )

    if result.returncode != 0:
        raise RuntimeError(
            f"{description} failed with return code "
            f"{result.returncode}."
        )

    return result

# This function calls the arm controller's `move_arm()` method and the compilation is that different controller versions may define this function differently
def call_move_arm(pose_name: str, positions: list[float], duration: float) -> bool | None:
    if TASK_NODE is None:
        raise RuntimeError(
            "The Sentinel task controller has not been initialised."
        )

    method = TASK_NODE.move_arm
    # The function examines the installed method using the following and then builds the augments based on certain parameters of interest
    signature = inspect.signature(method)

    parameters = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    ]

    arguments: list[Any] = []

    for index, parameter in enumerate(parameters):
        parameter_name = parameter.name.lower()

        if (
            "duration" in parameter_name
            or "time" in parameter_name
        ):
            arguments.append(duration)

        elif (
            "pose_name" in parameter_name
            or parameter_name == "name"
            or "command_name" in parameter_name
        ):
            arguments.append(pose_name)

        elif (
            "position" in parameter_name
            or "joint" in parameter_name
            or parameter_name == "pose"
        ):
            arguments.append(positions)

        elif len(parameters) == 3:
            arguments.append(
                [pose_name, positions, duration][index]
            )

        elif len(parameters) == 2:
            arguments.append(
                [positions, duration][index]
            )

        elif len(parameters) == 1:
            arguments.append(positions)

        else:
            raise RuntimeError(
                f"Unsupported move_arm signature: {signature}"
            )
    # Calls a compatibility wrapper to let the main task code continue
    return method(*arguments)

# Same concept for the arm but now for the gripper
def call_move_gripper(command_name: str, position: float) -> bool | None:
    if TASK_NODE is None:
        raise RuntimeError(
            "The Sentinel task controller has not been initialised."
        )

    method = TASK_NODE.move_gripper
    signature = inspect.signature(method)

    parameters = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    ]

    arguments: list[Any] = []

    for index, parameter in enumerate(parameters):
        parameter_name = parameter.name.lower()

        if (
            "position" in parameter_name
            or "target" in parameter_name
            or "value" in parameter_name
        ):
            arguments.append(position)

        elif (
            "command" in parameter_name
            or "name" in parameter_name
            or "action" in parameter_name
            or "pose" in parameter_name
        ):
            arguments.append(command_name)

        elif len(parameters) == 2:
            arguments.append(
                [command_name, position][index]
            )

        elif len(parameters) == 1:
            arguments.append(position)

        else:
            raise RuntimeError(
                f"Unsupported move_gripper signature: {signature}"
            )

    return method(*arguments)

# Executes one named robotic action which can be an arm pose from ARM_POSES or a gripper action from GRIPPER_ACTIONS
def run_pose(pose_name: str, duration: float | None = None, ignore_stop: bool = False) -> None:
    if STOP_REQUESTED and not ignore_stop:
        raise KeyboardInterrupt

    if TASK_NODE is None:
        raise RuntimeError(
            "The Sentinel task controller has not been initialised."
        )

    print(
        f"\n[SHORT TASK] Running pose: {pose_name}",
        flush=True,
    )

    if pose_name in ARM_POSES:
        movement_duration = (
            4.0
            if duration is None
            else duration
        )

        success = call_move_arm(
            pose_name=pose_name,
            positions=ARM_POSES[pose_name],
            duration=movement_duration,
        )

    elif pose_name in GRIPPER_ACTIONS:
        gripper_action = GRIPPER_ACTIONS[pose_name]

        success = call_move_gripper(
            command_name=pose_name,
            position=gripper_action["position"],
        )

    else:
        available_names = sorted(
            list(ARM_POSES.keys())
            + list(GRIPPER_ACTIONS.keys())
        )

        raise ValueError(
            f'Unknown pose or command "{pose_name}". '
            f"Available names: {available_names}"
        )

    # Some controller methods return None after succeeding.
    # Only an explicit False is treated as failure.
    if success is False:
        raise RuntimeError(
            f'Pose or command "{pose_name}" failed.'
        )

# Function to find the Gazebo service needed to reset objects which is mostly used to reset the environment for the next run of a measured experiment
def discover_set_pose_service() -> str:
    result = run_command(
        command=["gz", "service", "-l"],
        description="Finding the Gazebo set-pose service",
        capture_output=True,
    )

    services = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    matching_services = [
        service
        for service in services
        if re.fullmatch(
            r"/world/[^/]+/set_pose",
            service,
        )
    ]

    if not matching_services:
        raise RuntimeError(
            "No Gazebo '/world/<world>/set_pose' service was found."
        )

    for preferred in (
        "/world/sentinel_lab/set_pose",
        "/world/default/set_pose",
    ):
        if preferred in matching_services:
            print(
                f"[SHORT TASK] Using service: {preferred}",
                flush=True,
            )
            return preferred

    if len(matching_services) == 1:
        return matching_services[0]

    raise RuntimeError(
        "More than one Gazebo set-pose service was found:\n"
        + "\n".join(matching_services)
    )

# Function to reset the cube only
def reset_cube(set_pose_service: str, settle_seconds: float, max_attempts: int = 5, retry_delay_seconds: float = 1.0) -> None:
    x, y, z = CUBE_POSITION

    request = (
        f'name: "{CUBE_NAME}" '
        f"position: {{"
        f"x: {x:.6f}, "
        f"y: {y:.6f}, "
        f"z: {z:.6f}"
        f"}} "
        "orientation: {"
        "w: 1.0, "
        "x: 0.0, "
        "y: 0.0, "
        "z: 0.0"
        "}"
    )

    last_error = "No response received."

    for attempt in range(1, max_attempts + 1):
        if STOP_REQUESTED:
            raise KeyboardInterrupt

        try:
            result = run_command(
                command=[
                    "gz",
                    "service",
                    "-s",
                    set_pose_service,
                    "--reqtype",
                    "gz.msgs.Pose",
                    "--reptype",
                    "gz.msgs.Boolean",
                    "--timeout",
                    "10000",
                    "--req",
                    request,
                ],
                description=(
                    f"Resetting {CUBE_NAME} "
                    f"(attempt {attempt}/{max_attempts})"
                ),
                capture_output=True,
            )

            response = (
                f"{result.stdout}\n{result.stderr}"
            ).strip()

            if "data: true" in response.lower():
                print(
                    f"[SHORT TASK] {CUBE_NAME} reset confirmed.",
                    flush=True,
                )
                break

            last_error = response or "Gazebo returned an empty response."

        except RuntimeError as exc:
            last_error = str(exc)

        if attempt < max_attempts:
            print(
                "[SHORT TASK] Cube reset was not confirmed. "
                f"Waiting {retry_delay_seconds:.1f} seconds before retrying.",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(retry_delay_seconds)

    else:
        raise RuntimeError(
            "Gazebo did not confirm that the cube was reset after "
            f"{max_attempts} attempts.\n"
            f"Last response:\n{last_error}"
        )

    print(
        f"[SHORT TASK] Waiting {settle_seconds:.2f} seconds "
        "for the cube to settle.",
        flush=True,
    )

    time.sleep(settle_seconds)


# Runs one complete short sorting task, it starts by checking the camera to ensure objects are there and then runs the fixed sequence
def run_short_cycle(telemetry_recorder: TelemetryRecorder) -> None:
    print(
        "\n========== SHORT CUBE TASK ==========",
        flush=True,
    )

    set_task_phase(telemetry_recorder, "cube_approach")

    run_pose(
        "long_left_pick_high",
        duration=1.00,
    )

    run_pose(
        "long_left_pick_near",
        duration=1.00,
    )

    set_task_phase(telemetry_recorder, "cube_grasp")

    time.sleep(0.30)
    run_pose("gripper_grasp")
    time.sleep(0.30)

    set_task_phase(telemetry_recorder, "cube_lift")

    run_pose(
        "long_left_pick_lift",
        duration=0.80,
    )

    time.sleep(0.20)

    run_pose(
        "long_left_pick_high",
        duration=0.80,
    )

    set_task_phase(telemetry_recorder, "cube_transport")

    run_pose(
        "long_cube_place_high",
        duration=0.80,
    )

    set_task_phase(telemetry_recorder, "cube_placement")

    run_pose(
        "long_cube_place_mid",
        duration=0.55,
    )

    run_pose(
        "long_cube_place_near",
        duration=0.55,
    )

    set_task_phase(telemetry_recorder, "cube_release")

    run_pose("gripper_open")
    time.sleep(0.20)

    set_task_phase(telemetry_recorder, "cube_retreat")

    run_pose(
        "long_cube_place_mid",
        duration=0.45,
    )

    run_pose(
        "long_cube_place_high",
        duration=0.55,
    )


CSV_FIELDS = [
    "schema_version",
    "session_id",
    "run_key",
    "run_id",
    "task_type",
    "condition",
    "attack_type",
    "attack_variant",
    "attack_severity",
    "attack_target",
    "attack_target_object",
    "attack_target_phase",
    "attack_parameter_value",
    "attack_parameter_unit",
    "attack_event_id",
    "attack_successfully_injected",
    "attack_injection_count",
    "task_outcome",
    "started_at",
    "finished_at",
    "duration_seconds",
    "telemetry_samples",
    "status",
    "error",
]

# Prepares the one row per run experiment summary CSV, where it creates the parent directory if necessary, checks for duplication, reads existing headers, 
# confirms that the header matches the fields then creates a new file and writes the header if needed 
def prepare_csv(csv_path: Path) -> None:
    csv_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        csv_path.exists()
        and csv_path.stat().st_size > 0
    ):
        with csv_path.open(
            "r",
            newline="",
            encoding="utf-8",
        ) as csv_file:
            reader = csv.reader(csv_file)
            existing_header = next(reader, [])

        if existing_header != CSV_FIELDS:
            raise RuntimeError(
                "The existing CSV header does not match this script.\n"
                f"Expected: {CSV_FIELDS}\n"
                f"Found:    {existing_header}"
            )

        return

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        csv.DictWriter(
            csv_file,
            fieldnames=CSV_FIELDS,
        ).writeheader()

# Determines the ID to use for the next experiment run and reads the existing summary CSV to find the highest valid run_id
def find_next_run_id(csv_path: Path) -> int:
    if (
        not csv_path.exists()
        or csv_path.stat().st_size == 0
    ):
        return 1

    highest_run_id = 0

    with csv_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            try:
                highest_run_id = max(
                    highest_run_id,
                    int(row.get("run_id", "0")),
                )
            except ValueError:
                continue

    return highest_run_id + 1

# Writes one completed experiment run to the summary CSV
def append_run_result(
    csv_path: Path,
    session_id: str,
    run_id: int,
    condition: str,
    attack_type: str,
    attack_variant: str,
    attack_severity: str,
    attack_target: str,
    attack_target_object: str,
    attack_target_phase: str,
    attack_parameter_value: str,
    attack_parameter_unit: str,
    attack_event_id: str,
    attack_successfully_injected: int,
    attack_injection_count: int,
    started_at: str,
    finished_at: str,
    duration_seconds: float,
    telemetry_samples: int,
    status: str,
    error: str,
) -> None:

    task_outcome = "completed" if status == "success" else status

    with csv_path.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=CSV_FIELDS,
        )

        writer.writerow(
            {
                "schema_version": "sentinel_experiment_runs_v2",
                "session_id": session_id,
                "run_key": f"{session_id}:{run_id}",
                "run_id": run_id,
                "task_type": "short_cube_pick_place",
                "condition": condition,
                "attack_type": attack_type,
                "attack_variant": attack_variant,
                "attack_severity": attack_severity,
                "attack_target": attack_target,
                "attack_target_object": attack_target_object,
                "attack_target_phase": attack_target_phase,
                "attack_parameter_value": attack_parameter_value,
                "attack_parameter_unit": attack_parameter_unit,
                "attack_event_id": attack_event_id,
                "attack_successfully_injected": (
                    attack_successfully_injected
                ),
                "attack_injection_count": attack_injection_count,
                "task_outcome": task_outcome,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_seconds": f"{duration_seconds:.3f}",
                "telemetry_samples": telemetry_samples,
                "status": status,
                "error": error,
            }
        )

# Checks whether the Gazebo command-line program is available
def verify_environment() -> None:
    # Catches a missing Gazebo environment before the experiment begins
    if shutil.which("gz") is None:
        raise RuntimeError(
            "The 'gz' command was not found."
        )

    missing_poses = [
        name
        for name in REQUIRED_SHORT_POSES
        if name not in ARM_POSES
    ]

    if missing_poses:
        raise RuntimeError(
            "The following short-task poses are missing from "
            "fixed_poses.py: "
            + ", ".join(missing_poses)
        )

# Prepares the environment before the first measured run
def prepare_first_run(set_pose_service: str, settle_seconds: float) -> None:
    print(
        "\n[SHORT TASK] Preparing the first run.",
        flush=True,
    )

    run_pose("gripper_open")

    reset_cube(
        set_pose_service=set_pose_service,
        settle_seconds=settle_seconds,
    )

    print(
        "[SHORT TASK] Robot is at home and cube is ready.",
        flush=True,
    )

# Prepares the environment between measured runs
def prepare_next_run(set_pose_service: str, settle_seconds: float) -> None:
    print(
        "\n[SHORT TASK] Preparing the next repetition.",
        flush=True,
    )

    run_pose(
        "home",
        duration=1.20,
    )

    # The cylinder release leaves the gripper open, but opening it again
    # here guarantees a consistent starting state without affecting the
    # measured duration.
    run_pose("gripper_open")

    reset_cube(
        set_pose_service=set_pose_service,
        settle_seconds=settle_seconds,
    )

# Tries to place the robot in a safe state after an error or interruption and attempts to open the gripper and return the original position/home
def attempt_safe_recovery() -> None:
    print(
        "\n[SHORT TASK] Attempting safe recovery.",
        flush=True,
    )

    try:
        run_pose(
            "gripper_open",
            ignore_stop=True,
        )
    except Exception as exc:
        print(
            f"[SHORT TASK] Could not open gripper: {exc}",
            file=sys.stderr,
            flush=True,
        )

    try:
        run_pose(
            "home",
            duration=1.20,
            ignore_stop=True,
        )
    except Exception as exc:
        print(
            f"[SHORT TASK] Could not return home: {exc}",
            file=sys.stderr,
            flush=True,
        )


# Reads and validates command-line options
def parse_arguments() -> argparse.Namespace:
    data_directory = Path.cwd() / "data"

    parser = argparse.ArgumentParser(
        description=(
            "Repeat the Sentinel Arm short cube task, record one "
            "summary row per run, and capture continuous joint telemetry."
        )
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=2,
        help=(
            "Number of measured runs. Use 0 to continue until Ctrl+C. "
            "Default: 2."
        ),
    )

    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=1.0,
        help=(
            "Cube settling time before each run. This is outside the "
            "measured duration. Default: 1.0."
        ),
    )

    parser.add_argument(
        "--condition",
        default="normal",
        help="Condition written to both CSV files. Default: normal.",
    )

    parser.add_argument(
        "--attack-type",
        default="none",
        help="Attack label written to both CSV files. Default: none.",
    )

    parser.add_argument(
        "--attack-variant",
        default="none",
        help="Attack variant label. Default: none.",
    )

    parser.add_argument(
        "--attack-severity",
        default="none",
        choices=("none", "low", "medium", "high"),
        help="Attack severity label. Default: none.",
    )

    parser.add_argument(
        "--attack-target",
        default="none",
        help="Target joint, command or component. Default: none.",
    )

    parser.add_argument(
        "--attack-target-object",
        default="none",
        help="Target object such as cube or cylinder. Default: none.",
    )

    parser.add_argument(
        "--attack-target-phase",
        default="none",
        help="Task phase in which the attack should activate. Default: none.",
    )

    parser.add_argument(
        "--attack-parameter-value",
        default="",
        help="Attack parameter value stored as text. Default: empty.",
    )

    parser.add_argument(
        "--attack-parameter-unit",
        default="",
        help="Unit for the attack parameter. Default: empty.",
    )

    parser.add_argument(
        "--attack-event-id",
        default="",
        help=(
            "Optional deterministic attack-event ID from an experiment "
            "manifest. Default: generated by the attack node."
        ),
    )

    parser.add_argument(
        "--summary-csv",
        type=Path,
        default=data_directory / "experiment_runs.csv",
        help=(
            "One-row-per-run experiment summary CSV. "
            "Default: data/experiment_runs.csv"
        ),
    )

    parser.add_argument(
        "--telemetry-csv",
        type=Path,
        default=data_directory / "joint_telemetry.csv",
        help=(
            "Continuous joint telemetry CSV. "
            "Default: data/joint_telemetry.csv"
        ),
    )

    parser.add_argument(
        "--attack-events-csv",
        type=Path,
        default=data_directory / "attack_events.csv",
        help=(
            "Attack ground-truth event CSV. "
            "Default: data/attack_events.csv"
        ),
    )

    arguments = parser.parse_args()

    if arguments.runs < 0:
        parser.error(
            "--runs must be zero or a positive integer."
        )

    if arguments.settle_seconds < 0:
        parser.error(
            "--settle-seconds cannot be negative."
        )

    return arguments

# Controls the complete repeated experiment of the long task 
def main(telemetry_recorder: TelemetryRecorder) -> int:
    signal.signal(
        signal.SIGINT,
        handle_signal,
    )

    signal.signal(
        signal.SIGTERM,
        handle_signal,
    )

    arguments = parse_arguments()

    # The recorder is created before argparse is evaluated, so update its
    # destination to the path selected for this experiment before recording.
    telemetry_recorder.csv_path = (
        arguments.telemetry_csv.expanduser().resolve()
    )
    telemetry_recorder.attack_events_csv_path = (
        arguments.attack_events_csv.expanduser().resolve()
    )

    try:
        verify_environment()
        prepare_csv(arguments.summary_csv)

        next_run_id = find_next_run_id(
            arguments.summary_csv,
        )

        session_id = datetime.now().strftime(
            "%Y%m%d_%H%M%S",
        )

        set_pose_service = discover_set_pose_service()

        print(
            "\n[SHORT TASK] Controller configuration:",
            flush=True,
        )

        print(
            f"[SHORT TASK] Gripper open position: "
            f"{GRIPPER_OPEN_POSITION}",
            flush=True,
        )

        print(
            f"[SHORT TASK] Gripper grasp position: "
            f"{GRIPPER_GRASP_POSITION}",
            flush=True,
        )

        print(
            f"[SHORT TASK] Summary CSV: "
            f"{arguments.summary_csv}",
            flush=True,
        )

        print(
            f"[SHORT TASK] Telemetry CSV: "
            f"{arguments.telemetry_csv}",
            flush=True,
        )

        prepare_first_run(
            set_pose_service=set_pose_service,
            settle_seconds=arguments.settle_seconds,
        )

        completed_runs = 0
        last_run_succeeded = False

        while (
            not STOP_REQUESTED
            and (
                arguments.runs == 0
                or completed_runs < arguments.runs
            )
        ):
            run_id = next_run_id
            next_run_id += 1

            print(
                "\n"
                "========================================\n"
                f"STARTING SHORT RUN {run_id}\n"
                "========================================",
                flush=True,
            )

            started_at = timestamp()
            start_time = time.monotonic()

            status = "success"
            error_message = ""
            telemetry_samples = 0
            telemetry_started = False
            attack_summary = {
                "attack_successfully_injected": 0,
                "attack_injection_count": 0,
                "attack_event_id": "",
            }

            try:
                telemetry_recorder.start_run(
                    session_id=session_id,
                    run_id=run_id,
                    task_type="short_cube_pick_place",
                    condition=arguments.condition,
                    attack_type=arguments.attack_type,
                    initial_phase="cube_approach",
                    attack_variant=arguments.attack_variant,
                    attack_severity=arguments.attack_severity,
                    attack_target=arguments.attack_target,
                    attack_target_object=arguments.attack_target_object,
                    attack_target_phase=arguments.attack_target_phase,
                    attack_parameter_value=(
                        arguments.attack_parameter_value
                    ),
                    attack_parameter_unit=(
                        arguments.attack_parameter_unit
                    ),
                )

                configure_task_context(
                    session_id=session_id,
                    run_id=run_id,
                    task_type="short_cube_pick_place",
                    condition=arguments.condition,
                    attack_type=arguments.attack_type,
                    initial_phase="cube_approach",
                    attack_variant=arguments.attack_variant,
                    attack_severity=arguments.attack_severity,
                    attack_target=arguments.attack_target,
                    attack_target_object=arguments.attack_target_object,
                    attack_target_phase=arguments.attack_target_phase,
                    attack_parameter_value=(
                        arguments.attack_parameter_value
                    ),
                    attack_parameter_unit=(
                        arguments.attack_parameter_unit
                    ),
                    attack_event_id=arguments.attack_event_id,
                )

                telemetry_started = True

                run_short_cycle(
                    telemetry_recorder=telemetry_recorder,
                )

            except KeyboardInterrupt:
                status = "interrupted"
                error_message = "Run interrupted by the user."

            except Exception as exc:
                status = "failed"
                error_message = str(exc)

            finally:
                if telemetry_started:
                    telemetry_samples = telemetry_recorder.stop_run()

                if TASK_NODE is not None:
                    attack_summary = (
                        TASK_NODE.get_attack_status_summary()
                    )

                clear_task_context()

            last_run_succeeded = status == "success"

            duration_seconds = (
                time.monotonic() - start_time
            )

            finished_at = timestamp()

            append_run_result(
                csv_path=arguments.summary_csv,
                session_id=session_id,
                run_id=run_id,
                condition=arguments.condition,
                attack_type=arguments.attack_type,
                attack_variant=arguments.attack_variant,
                attack_severity=arguments.attack_severity,
                attack_target=arguments.attack_target,
                attack_target_object=arguments.attack_target_object,
                attack_target_phase=arguments.attack_target_phase,
                attack_parameter_value=(
                    arguments.attack_parameter_value
                ),
                attack_parameter_unit=(
                    arguments.attack_parameter_unit
                ),
                attack_event_id=str(
                    attack_summary.get("attack_event_id", "")
                    or arguments.attack_event_id
                ),
                attack_successfully_injected=int(
                    attack_summary.get(
                        "attack_successfully_injected",
                        0,
                    )
                ),
                attack_injection_count=int(
                    attack_summary.get("attack_injection_count", 0)
                ),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=duration_seconds,
                telemetry_samples=telemetry_samples,
                status=status,
                error=error_message,
            )

            print(
                "\n"
                f"[SHORT TASK] Run {run_id}: {status}\n"
                f"[SHORT TASK] Measured duration: "
                f"{duration_seconds:.3f} seconds\n"
                f"[SHORT TASK] Telemetry samples: "
                f"{telemetry_samples}\n"
                f"[SHORT TASK] Summary CSV: "
                f"{arguments.summary_csv}\n"
                f"[SHORT TASK] Telemetry CSV: "
                f"{arguments.telemetry_csv}",
                flush=True,
            )

            if (
                status == "success"
                and duration_seconds > 10.0
            ):
                print(
                    "[SHORT TASK] Warning: measured duration exceeded "
                    "the 10-second target.",
                    flush=True,
                )

            if status != "success":
                attempt_safe_recovery()
                break

            completed_runs += 1

            another_run_required = (
                not STOP_REQUESTED
                and (
                    arguments.runs == 0
                    or completed_runs < arguments.runs
                )
            )

            if another_run_required:
                prepare_next_run(
                    set_pose_service=set_pose_service,
                    settle_seconds=arguments.settle_seconds,
                )

        if (
            last_run_succeeded
            and not STOP_REQUESTED
        ):
            print(
                "\n[SHORT TASK] Returning home after the final run.",
                flush=True,
            )

            run_pose(
                "home",
                duration=1.20,
            )

        print(
            "\n[SHORT TASK] Repetition finished.",
            flush=True,
        )

        return 0

    except KeyboardInterrupt:
        print(
            "\n[SHORT TASK] Stopped by user.",
            flush=True,
        )

        telemetry_recorder.stop_run()
        attempt_safe_recovery()
        return 130

    except Exception as exc:
        print(
            f"\n[SHORT TASK] Fatal error: {exc}",
            file=sys.stderr,
            flush=True,
        )

        telemetry_recorder.stop_run()
        attempt_safe_recovery()
        return 1

# Initialises and shuts down the ROS parts of the project
def program_entry_point() -> int:
    global TASK_NODE

    telemetry_recorder: TelemetryRecorder | None = None

    rclpy.init(args=None)
    TASK_NODE = SentinelTaskController()
    TASK_NODE.clear_experiment_context()

    try:
        # main() updates this path from the parsed --telemetry-csv argument
        # before the first call to start_run()
        telemetry_recorder = TelemetryRecorder(
            csv_path=Path.cwd() / "data" / "joint_telemetry.csv",
            max_sample_rate_hz=50.0,
        )

        if not telemetry_recorder.wait_for_joint_states(
            timeout_seconds=5.0,
        ):
            raise RuntimeError(
                "No /joint_states messages were received."
            )

        return main(
            telemetry_recorder=telemetry_recorder,
        )

    finally:
        if telemetry_recorder is not None:
            telemetry_recorder.shutdown()

        if TASK_NODE is not None:
            TASK_NODE.destroy_node()
            TASK_NODE = None

        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    raise SystemExit(
        program_entry_point()
    )   