# Sentinel Arm live ROS 2 IDS and IDPS

This package deploys the trained Sentinel Arm behavioural intrusion detection
models as a ROS 2 Jazzy node. It observes `/joint_states` and new completed rows
in `command_trace.csv`; it never reads the attack labels or attack-active ground
truth used during evaluation.

Each completed controller command produces:

- a five-class supervised prediction: `normal`,
  `mitm_trajectory_manipulation`, `command_injection`, `replay_attack`, or
  `denial_of_service`;
- normal-only PCA novelty scores for attacks outside the four trained classes;
- one JSON message on `/sentinel/ids/prediction`;
- an additional JSON message on `/sentinel/ids/alert` when the verdict is not
  normal; and
- one row in `data/live_ids_predictions.csv`.

The node makes a command-level decision immediately after the controller command
finishes. This matches the observation unit used to train and validate the
models; it is not a pre-execution trajectory blocker.

The separate `idps_gateway` executable is the synchronous prevention path. It
accepts the final `FollowJointTrajectory` goal from an attack proxy, classifies
19 command-only features, and only then forwards an allowed goal to the real
controller. It does not use controller results, joint telemetry, attack labels,
or the passive IDS CSV polling path.

## Where the package goes

Copy the whole `sentinel_arm_ids` directory to:

```text
~/master_project/sentinel_arm_ws/src/sentinel_arm_ids/
```

The resulting workspace should contain:

```text
~/master_project/sentinel_arm_ws/src/sentinel_arm_ids/
├── config/live_ids.yaml
├── launch/live_ids.launch.py
├── models/*.joblib
├── resource/sentinel_arm_ids
├── sentinel_arm_ids/
│   ├── __init__.py
│   ├── features.py
│   ├── idps_gateway.py
│   ├── live_ids_node.py
│   └── model_runtime.py
├── package.xml
├── requirements.txt
├── setup.cfg
└── setup.py
```

Do not place the Python files inside `arm_mitm_proxy` or
`telemetry_recorder`. This is a separate ROS package and requires no source
changes to those nodes.

## Build with system Python

This edition uses `/usr/bin/python3` for ROS, model training and the installed
entry points. From the workspace root, run the supplied preparation script:

```bash
cd ~/master_project/sentinel_arm_ws
./prepare_system_python.sh
source /opt/ros/jazzy/setup.bash
source install/setup.bash
```

The script checks the system dependencies, rebuilds the pre-execution model
with the same scikit-learn installation used by ROS, records model-version
metadata and builds `sentinel_arm_ids` and `sentinel_arm_tasks`.

## Run

Start the proxy and simulator as usual. Start the IDS before starting the next
pick-and-place run so `skip_existing_commands: true` ignores historical rows:

```bash
source /opt/ros/jazzy/setup.bash
source ~/master_project/sentinel_arm_ws/install/setup.bash
ros2 launch sentinel_arm_ids live_ids.launch.py
```

If the proxy writes its trace somewhere else, edit
`config/live_ids.yaml`, or run the node directly with a parameter override:

```bash
ros2 run sentinel_arm_ids live_ids_node --ros-args \
  -p command_trace_csv:=$HOME/master_project/sentinel_arm_ws/data/command_trace.csv
```

Monitor decisions and alerts in separate terminals:

```bash
ros2 topic echo /sentinel/ids/prediction
ros2 topic echo /sentinel/ids/alert
```

Run the IDPS gateway after Gazebo has brought up the real controller:

```bash
ros2 run sentinel_arm_ids idps_gateway --ros-args \
  --params-file "$HOME/master_project/sentinel_arm_ws/install/sentinel_arm_ids/share/sentinel_arm_ids/config/live_ids.yaml" \
  -p prevention_mode:=block
```

Each attack proxy must then use the gateway as its downstream controller:

```bash
python3 src/sentinel_arm_tasks/sentinel_arm_tasks/arm_mitm_proxy.py \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv data/command_trace.csv
```

Use only one attack proxy at a time. The task-facing endpoint remains
`/sentinel/arm_proxy/follow_joint_trajectory`; the real controller endpoint is
unchanged.

Confirm the input path if no decisions appear:

```bash
ros2 param get /sentinel_live_ids command_trace_csv
ros2 topic hz /joint_states
tail -f ~/master_project/sentinel_arm_ws/data/command_trace.csv
```

## Decision policy

The supervised model handles the four attack classes already represented in the
dataset. An alert is a known attack when the highest-probability class is not
normal and its probability is at least `supervised_attack_threshold`.

The normal-only models provide an open-set fallback. A command is considered
novel when the causal three-command anomaly score crosses its calibrated command
threshold, or when the maximum base anomaly score within the run crosses its
calibrated run threshold. The output preserves each raw score and threshold for
auditing.

## Limitations

- A result is available after a command completes, not before its motion begins.
- The models were trained in the same UR5e/Gazebo digital-twin setup. Validate
  false-positive rates again before treating results from a physical robot as
  operational safety decisions.
- A missing or incompatible `/joint_states` stream causes physical values to be
  imputed and reduces confidence in the behavioural interpretation.
- This node detects and reports. It deliberately does not stop the robot.
- The IDPS can only prevent goals routed through its gateway. ROS 2 access
  control is still required to stop another client from directly addressing
  the real controller action.
