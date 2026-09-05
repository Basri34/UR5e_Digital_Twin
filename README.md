# Sentinel Arm: Robotic Digital Twin with Behavioural IDS and IDPS

MSc Cybersecurity project — Omar Albasri, University of Glasgow.

Sentinel Arm is a ROS 2/Gazebo UR5e workcell that performs repeatable pick-and-place tasks, simulates four command-layer attacks, records command and physical telemetry, and evaluates machine-learning intrusion detection and pre-execution trajectory blocking.

The short task moves the cube. The long task moves the cube and then the cylinder. The project compares passive behavioural detection, pre-execution monitoring, and pre-execution blocking at a confidence threshold of **0.99**.

> Documentation status: the runtime instructions below were checked against the supplied ROS source, but have not been executed on a fresh ROS installation. The source archive supplied for this README contained an empty `ml/` directory and omitted model files and root setup/evaluation scripts. Offline training and batch-evaluation commands therefore remain to be verified; see [Reproducing the evaluation](#reproducing-the-evaluation). The recorded results below come from the supplied project summary, not a new evaluation.

## Contents

- [Demonstrations](#demonstrations)
- [How the system works](#how-the-system-works)
- [Repository and source guide](#repository-and-source-guide)
- [Dependencies and build](#dependencies-and-build)
- [Model files](#model-files)
- [Run the workcell](#run-the-workcell)
- [Run normal tasks](#run-normal-tasks)
- [Run attack experiments](#run-attack-experiments)
- [Monitor decisions and interpret outcomes](#monitor-decisions-and-interpret-outcomes)
- [Data and recorded results](#data-and-recorded-results)
- [Reproducing the evaluation](#reproducing-the-evaluation)
- [Troubleshooting](#troubleshooting)
- [Repository maintenance](#repository-maintenance)

## Demonstrations

The recordings show normal operation and each attack in monitor and block mode. In the filenames, `1` means the short/cube task and `2` means the long task with the cylinder targeted. The long task still executes the cube sequence first.

MKV links provide access to the recordings; downloading and opening them in a compatible video player may be necessary. The filenames below preserve the originals, including `MITIM_MONITOR1.mkv`.

| Normal operation | Recording |
|---|---|
| Short task: cube | [Watch/download](videos/short_task.mkv) |
| Long task: cube then cylinder | [Watch/download](videos/long_task.mkv) |

| Attack | Cube: monitor | Cube: block | Cylinder: monitor | Cylinder: block |
|---|---|---|---|---|
| Command injection | [Recording](videos/CI_MONITOR1.mkv) | [Recording](videos/CI_BLOCK1.mkv) | [Recording](videos/CI_MONITOR2.mkv) | [Recording](videos/CI_BLOCK2.mkv) |
| MITM trajectory manipulation | [Recording](videos/MITIM_MONITOR1.mkv) | [Recording](videos/MITM_BLOCK1.mkv) | [Recording](videos/MITM_MONITOR2.mkv) | [Recording](videos/MITM_BLOCK2.mkv) |
| Replay | [Recording](videos/REPLAY_MONITOR1.mkv) | [Recording](videos/REPLAY_BLOCK1.mkv) | [Recording](videos/REPLAY_MONITOR2.mkv) | [Recording](videos/REPLAY_BLOCK2.mkv) |
| Delay DoS | [Recording](videos/DOS_MONITOR1.mkv) | [Recording](videos/DOS_BLOCK1.mkv) | [Recording](videos/DOS_MONITOR2.mkv) | [Recording](videos/DOS_BLOCK2.mkv) |

Motion alone does not establish whether a particular command was detected or blocked. Pair the recordings with gateway decisions and experiment logs when interpreting security outcomes. The example settings later in this README are runnable configurations; the recordings' exact severities must be checked against their original experiment logs.

## How the system works

### Command routing

| Stage | Interface | Role |
|---|---|---|
| Task to attack proxy | `/sentinel/arm_proxy/follow_joint_trajectory` | The task submits a legitimate arm trajectory. |
| Attack proxy to IDPS | `/sentinel/idps/follow_joint_trajectory` | The selected proxy submits its final trajectory for classification. |
| IDPS to controller | `/scaled_joint_trajectory_controller/follow_joint_trajectory` | The gateway submits allowed trajectories to the real simulated arm controller. |
| Task to gripper | `/robotiq_gripper_controller/gripper_cmd` | Gripper commands use a separate `ParallelGripperCommand` action. |
| Task context | `/sentinel/experiment/context` | JSON identifies the run, phase, pose and configured experimental conditions. |
| Attack ground truth | `/sentinel/attack/status` | Proxies publish attack events for recording and evaluation. |
| Physical observation | `/joint_states` | Joint position, velocity and effort observations. |

Only **one attack proxy** may serve the task-facing action at a time. All four proxies pass normal commands through when their attack is not requested. Starting an attack proxy alone does not activate an attack: the task supplies the attack configuration through experiment context.

The task runners execute fixed joint poses from `fixed_poses.py`, operate the gripper, reset Gazebo objects between runs, publish task phases and write experiment data. The overhead detector uses colour segmentation and contours to report object locations; the supplied task sequences use fixed poses rather than visual servoing.

### Passive IDS

`live_ids_node.py` watches newly completed rows in the proxy's command-trace CSV and aligns them with buffered `/joint_states` observations. `features.py` constructs command features, physical summaries, tracking residuals and causal three-command temporal features. `model_runtime.py` loads the supervised classifier and two normal-only PCA novelty bundles.

A known-attack alert requires a non-normal winning class with confidence at least **0.50** by default. The novelty fallback uses a calibrated temporal command threshold or the maximum base novelty score within a run. It suppresses repeated unknown-attack alerts within a run and records cumulative run compromise state.

Predictions appear on `/sentinel/ids/prediction`, alerts on `/sentinel/ids/alert`, and decisions are logged to CSV. This path uses completed-command evidence and does not block trajectories. The 0.50 passive threshold is separate from the gateway's 0.99 threshold.

### Pre-execution IDPS

`idps_gateway.py` extracts **19 command-only features** before sending a goal to the controller: command ordinal, first-command indicator, arrival timing, context age, requested duration, six final joint targets, six per-joint target changes, and L1/L2 target-change magnitudes.

It does not classify using attack labels, controller results or physical telemetry. Run context groups command history and determines whether sufficient context exists for enforcement.

| Mode | Behaviour |
|---|---|
| `monitor` | Classify and record each valid trajectory, then forward it. |
| `block` | Abort a trajectory when valid run/pose context exists, its winning class is non-normal, and confidence is at least **0.99**. Otherwise forward it. |

A non-normal prediction below 0.99 is forwarded in block mode. Missing task context also prevents blocking. The printed class alone is therefore insufficient to establish enforcement.

The gateway protects arm trajectories routed through its action. It does not gate the separate gripper action or prevent a client from addressing the real controller directly. In Delay DoS, the proxy waits before submitting the trajectory to the gateway: blocking that goal does **not** undo time already lost to the upstream delay.

## Repository and source guide

Paths below are relative to the repository root.

| Path | Purpose |
|---|---|
| `src/sentinel_arm_description/` | Robot Xacro descriptions and RViz configuration. `sentinel_ur5e_robotiq.urdf.xacro` combines the UR5e and Robotiq 2F-85. |
| `src/sentinel_arm_gazebo/` | Workcell world, combined controller YAML and Gazebo launch files. |
| `src/sentinel_arm_control/` | Additional controller configuration; the combined UR5e launch uses the YAML in `sentinel_arm_gazebo/config/`. |
| `src/sentinel_arm_tasks/` | Task execution, attack proxies, telemetry recording and support utilities. |
| `src/sentinel_arm_ids/` | Passive IDS, gateway, feature construction, configuration and deployed models. |
| `ml/` | Offline ML work and model/results directories in the project workspace; training scripts were absent from the documentation archive. |
| `data/` | Experimental CSVs and validation sessions. |
| `results/final_data/` | Collected tables, figures and final evaluation outputs. |
| `attack_files/data/` | Earlier experiment and development-smoke data in the supplied archive. Not required by the runtime commands below. |
| `videos/` | The 18 demonstration recordings. |
| `final_results_summary.md` | Detailed project results narrative. |

Within `src/sentinel_arm_tasks/sentinel_arm_tasks/`:

| File | What it does |
|---|---|
| `run_pose.py` | Defines arm/gripper actions and poses; sends trajectory and gripper goals and publishes experiment context. |
| `fixed_poses.py` | Stored joint configurations used by the repeatable tasks. |
| `repeat_short_task.py` | Runs the cube sequence, resets the cube, manages measured runs and CSV destinations. |
| `repeat_long_task.py` | Runs cube and cylinder sequences and manages their experiment lifecycle. |
| `telemetry_recorder.py` | Records joint telemetry and attack events. Instantiated by the task runners; no separate recorder terminal is required. |
| `arm_mitm_proxy.py` | Offsets a selected joint in a targeted legitimate trajectory. |
| `arm_command_injection_proxy.py` | Inserts an extra offset trajectory before the legitimate one. |
| `arm_replay_proxy.py` | Replays a successful earlier same-run trajectory before the current one. |
| `arm_delay_dos_proxy.py` | Delays a selected trajectory and forwards its positions unchanged. |
| `object_detector.py` | Publishes colour-based cube/cylinder detections and an annotated camera image. |
| `gripper_state.py` | Diagnostic joint-state reader for the gripper. |
| `add_workcell_collision.py` | Adds workcell collision objects to a MoveIt planning scene. Not needed for fixed-pose replay. |
| `generate_fixed_poses.py` | Uses MoveIt's `/compute_ik` service to regenerate `fixed_poses.py`. This overwrites that source file and is not part of routine execution. |

`sentinel_ur5e_moveit.launch.py` is the complete workcell wrapper. **Despite its filename, the supplied version does not launch MoveIt or RViz.** It launches Gazebo with the combined robot description, starts the gripper controller and bridges the camera. `sentinel_ur5e.launch.py` is the lower-level launcher; using its defaults alone selects the standard UR description rather than the combined gripper model. The older `simulation.launch.py`, display launch and backup Xacros are not used by the workflow below.

## Dependencies and build

The project environment uses ROS 2 Jazzy, Gazebo Sim 8/Harmonic and system Python on Linux Mint 22.x. These instructions assume ROS 2 Jazzy and the corresponding ROS package repositories are already installed. On a fresh system, complete the ROS installation before running them.

Clone the repository into the conventional workspace location, replacing the URL:

```bash
mkdir -p ~/master_project
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git ~/master_project/sentinel_arm_ws
cd ~/master_project/sentinel_arm_ws
git lfs install
git lfs pull
```

Skip cloning if working in the existing workspace. Install `git-lfs` first if unavailable.

Resolve package dependencies with ROS's dependency manager. The runtime's requirements file intentionally directs users to system packages rather than a pip environment:

```bash
sudo apt update
sudo apt install python3-colcon-common-extensions python3-rosdep git-lfs
source /opt/ros/jazzy/setup.bash
```

On a machine where rosdep has never been initialized, run `sudo rosdep init` once. Then:

```bash
rosdep update
cd ~/master_project/sentinel_arm_ws
rosdep install --from-paths src --ignore-src -r -y
```

For Mint 22.x, if rosdep cannot resolve the Mint distribution, use its Ubuntu 24.04 base explicitly:

```bash
rosdep install --from-paths src --ignore-src -r -y --os=ubuntu:noble
```

The combined workcell also needs controller plugins and OpenCV. Make sure they are installed in the Jazzy environment:

```bash
sudo apt install \
  ros-jazzy-ros2-controllers \
  ros-jazzy-gz-ros2-control \
  ros-jazzy-ur-controllers \
  python3-opencv
```

Check the external description and simulation packages:

```bash
ros2 pkg prefix ur_description
ros2 pkg prefix ur_simulation_gz
ros2 pkg prefix robotiq_description
```

The Robotiq package must provide `urdf/ur_to_robotiq_adapter.urdf.xacro` and `urdf/robotiq_2f_85_macro.urdf.xacro`, with the macro arguments used by the combined robot description. Exact upstream package revisions were not supplied with this archive, so a fresh-machine build must verify compatibility with those interfaces.

Place the required model artifacts described below in the source package before building:

```bash
cd ~/master_project/sentinel_arm_ws
source /opt/ros/jazzy/setup.bash
colcon build --symlink-install --cmake-args -DPython3_EXECUTABLE=/usr/bin/python3
source install/setup.bash
```

Use `/usr/bin/python3` for direct module execution. Avoid activating another Python environment over ROS. The package README mentions `prepare_system_python.sh`, but that script was not included in the supplied source archive; its training/setup behaviour has not been verified here.

## Model files

The deployed package needs these files in `src/sentinel_arm_ids/models/`:

| File | Used by |
|---|---|
| `best_multiclass_ids_model.joblib` | Passive supervised IDS |
| `best_novelty_ids_model.joblib` | Passive base PCA novelty detector |
| `best_temporal_novelty_ids_model.joblib` | Passive temporal PCA novelty detector |
| `best_preexecution_idps_model.joblib` | Pre-execution gateway |
| `model_versions.json` | Required scikit-learn version manifest for the models |

`setup.py` installs the model directory into the package share directory. The runtime requires the manifest to contain an entry mapping each model filename to its training scikit-learn version; that version must equal the current runtime version. The gateway additionally checks the exact feature-column list in its model bundle.

Inspect the installed artifacts after building:

```bash
ls "$(ros2 pkg prefix --share sentinel_arm_ids)/models"
/usr/bin/python3 -c 'import sklearn; print(sklearn.__version__)'
```

Model binaries and their manifest were deliberately omitted from the documentation archive and could not be validated here. Retain the trained artifacts in the full repository. Do not fabricate or edit version metadata simply to bypass a mismatch: use the compatible runtime or the verified training workflow.

A binary-classification model used offline is not a substitute for `best_preexecution_idps_model.joblib`.

## Run the workcell

### Common setup in every terminal

Open separate terminals for the long-running processes. Run this preamble in each terminal from the workspace:

```bash
cd ~/master_project/sentinel_arm_ws
source /opt/ros/jazzy/setup.bash
source install/setup.bash
RUN_DIR="$PWD/data/readme_demo/monitor"
mkdir -p "$RUN_DIR"
```

All terminals for a session must use the **same absolute `RUN_DIR`**. This keeps new demonstrations separate from the collected dissertation data. For block-mode experiments use `data/readme_demo/block` in every terminal instead. Existing CSVs may be appended to; choose a new directory if a completely fresh session is needed.

### Terminal 1 — simulator and controllers

```bash
ros2 launch sentinel_arm_gazebo sentinel_ur5e_moveit.launch.py
```

Wait for the controllers to activate. In another prepared terminal:

```bash
ros2 control list_controllers
ros2 action list -t
```

Expect active `joint_state_broadcaster`, `scaled_joint_trajectory_controller` and `robotiq_gripper_controller`, plus the arm and gripper action endpoints listed earlier.

### Terminal 2 — gateway

For monitor mode:

```bash
ros2 run sentinel_arm_ids idps_gateway --ros-args \
  -p prevention_mode:=monitor \
  -p block_confidence_threshold:=0.99 \
  -p decision_log_csv:="$RUN_DIR/idps_decisions.csv"
```

For block mode, stop that gateway with Ctrl+C, select the block session directory in each terminal, and restart it with:

```bash
ros2 run sentinel_arm_ids idps_gateway --ros-args \
  -p prevention_mode:=block \
  -p block_confidence_threshold:=0.99 \
  -p decision_log_csv:="$RUN_DIR/idps_decisions.csv"
```

Use only one gateway at a time. Restart to change mode; the supplied implementation reads its enforcement settings at startup.

### Terminal 3 — one proxy

For normal operation or MITM experiments:

```bash
/usr/bin/python3 -m sentinel_arm_tasks.arm_mitm_proxy \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv "$RUN_DIR/command_trace.csv"
```

For the other attack families, replace this process with the appropriate proxy from the next section. Do not run several proxies together.

### Terminal 4 — passive IDS

Start this before running a task:

```bash
ros2 run sentinel_arm_ids live_ids_node --ros-args \
  -p command_trace_csv:="$RUN_DIR/command_trace.csv" \
  -p prediction_log_csv:="$RUN_DIR/live_ids_predictions.csv" \
  -p supervised_attack_threshold:=0.50
```

By default the IDS skips pre-existing command rows. It monitors live `/joint_states`; merely pointing it to an old trace does not reproduce historical physical-feature analysis.

### Optional terminal — overhead object detector

```bash
ros2 run sentinel_arm_tasks object_detector
```

The node publishes `/sentinel/object_detection/detections` and `/sentinel/object_detection/image`. It supports visual inspection but is not required by the fixed-pose task commands below.

## Run normal tasks

In another terminal with the common setup, run one of these. Keep the simulator, gateway, normal pass-through proxy and passive IDS running.

Short/cube task:

```bash
ros2 run sentinel_arm_tasks repeat_short_task --runs 1 \
  --condition normal --attack-type none \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

Long/cube-then-cylinder task:

```bash
ros2 run sentinel_arm_tasks repeat_long_task --runs 1 \
  --condition normal --attack-type none \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

`--runs 25` repeats the selected configuration 25 times. `--runs 0` continues until interrupted. This repeats one configuration; it does not recreate a balanced experimental manifest automatically.

For a simulation-only baseline without loading IDS models, omit the gateway and passive IDS, and start the MITM proxy with `--controller-action /scaled_joint_trajectory_controller/follow_joint_trajectory`. Keep `--attack-type none` on the tasks. Restore the gateway endpoint before claiming any prevention result.

## Run attack experiments

### Select one proxy in Terminal 3

Stop the previous proxy only after the task has finished. Start the matching process:

**Command injection**

```bash
/usr/bin/python3 -m sentinel_arm_tasks.arm_command_injection_proxy \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv "$RUN_DIR/command_trace.csv"
```

**MITM manipulation**

```bash
/usr/bin/python3 -m sentinel_arm_tasks.arm_mitm_proxy \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv "$RUN_DIR/command_trace.csv"
```

**Replay**

```bash
/usr/bin/python3 -m sentinel_arm_tasks.arm_replay_proxy \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv "$RUN_DIR/command_trace.csv"
```

**Delay DoS**

```bash
/usr/bin/python3 -m sentinel_arm_tasks.arm_delay_dos_proxy \
  --controller-action /sentinel/idps/follow_joint_trajectory \
  --command-trace-csv "$RUN_DIR/command_trace.csv"
```

### Configure and run a task

The commands below use medium examples for cube and high examples for cylinder. They are valid parameterizations of the supplied source, not verified reconstructions of the video capture settings.

| Attack | Variant | Target | Phase suffix | Medium example | High example |
|---|---|---|---|---|---|
| Injection | `pre_command_joint_offset` | `shoulder_pan_joint` | `transport` | 0.10 rad | 0.15 rad |
| MITM | `joint_offset` | `shoulder_pan_joint` | `transport` | 0.10 rad | 0.15 rad |
| Replay | `prior_command_replay` | `arm_trajectory` | `retreat` | 3 commands back | 5 commands back |
| Delay DoS | `command_delay` | `arm_trajectory` | `transport` | 750 ms | 1500 ms |

`--attack-severity` is a descriptive label. The numerical `--attack-parameter-value` controls the implemented magnitude, so changing the severity label alone does not change the attack. Use consistent labels and values.

Replay requires enough successful legitimate commands earlier in the same run. Targeting retreat provides history; replaying five commands back at the start of a run will fail validation.

These task commands are identical in monitor and block modes. The gateway process determines enforcement. Run the desired task with the monitor gateway, then repeat with the block gateway and the separate block log directory.

### Command injection: task commands

**Short task — cube targeted**

```bash
ros2 run sentinel_arm_tasks repeat_short_task --runs 1 \
  --condition attack \
  --attack-type command_injection \
  --attack-variant pre_command_joint_offset \
  --attack-severity medium \
  --attack-target shoulder_pan_joint \
  --attack-target-object cube \
  --attack-target-phase cube_transport \
  --attack-parameter-value 0.10 \
  --attack-parameter-unit rad \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

**Long task — cylinder targeted**

```bash
ros2 run sentinel_arm_tasks repeat_long_task --runs 1 \
  --condition attack \
  --attack-type command_injection \
  --attack-variant pre_command_joint_offset \
  --attack-severity high \
  --attack-target shoulder_pan_joint \
  --attack-target-object cylinder \
  --attack-target-phase cylinder_transport \
  --attack-parameter-value 0.15 \
  --attack-parameter-unit rad \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

### MITM manipulation: task commands

**Short task — cube targeted**

```bash
ros2 run sentinel_arm_tasks repeat_short_task --runs 1 \
  --condition attack \
  --attack-type mitm_trajectory_manipulation \
  --attack-variant joint_offset \
  --attack-severity medium \
  --attack-target shoulder_pan_joint \
  --attack-target-object cube \
  --attack-target-phase cube_transport \
  --attack-parameter-value 0.10 \
  --attack-parameter-unit rad \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

**Long task — cylinder targeted**

```bash
ros2 run sentinel_arm_tasks repeat_long_task --runs 1 \
  --condition attack \
  --attack-type mitm_trajectory_manipulation \
  --attack-variant joint_offset \
  --attack-severity high \
  --attack-target shoulder_pan_joint \
  --attack-target-object cylinder \
  --attack-target-phase cylinder_transport \
  --attack-parameter-value 0.15 \
  --attack-parameter-unit rad \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

### Replay: task commands

**Short task — cube targeted**

```bash
ros2 run sentinel_arm_tasks repeat_short_task --runs 1 \
  --condition attack \
  --attack-type replay_attack \
  --attack-variant prior_command_replay \
  --attack-severity medium \
  --attack-target arm_trajectory \
  --attack-target-object cube \
  --attack-target-phase cube_retreat \
  --attack-parameter-value 3 \
  --attack-parameter-unit commands_back \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

**Long task — cylinder targeted**

```bash
ros2 run sentinel_arm_tasks repeat_long_task --runs 1 \
  --condition attack \
  --attack-type replay_attack \
  --attack-variant prior_command_replay \
  --attack-severity high \
  --attack-target arm_trajectory \
  --attack-target-object cylinder \
  --attack-target-phase cylinder_retreat \
  --attack-parameter-value 5 \
  --attack-parameter-unit commands_back \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

### Delay DoS: task commands

**Short task — cube targeted**

```bash
ros2 run sentinel_arm_tasks repeat_short_task --runs 1 \
  --condition attack \
  --attack-type denial_of_service \
  --attack-variant command_delay \
  --attack-severity medium \
  --attack-target arm_trajectory \
  --attack-target-object cube \
  --attack-target-phase cube_transport \
  --attack-parameter-value 750 \
  --attack-parameter-unit ms \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

**Long task — cylinder targeted**

```bash
ros2 run sentinel_arm_tasks repeat_long_task --runs 1 \
  --condition attack \
  --attack-type denial_of_service \
  --attack-variant command_delay \
  --attack-severity high \
  --attack-target arm_trajectory \
  --attack-target-object cylinder \
  --attack-target-phase cylinder_transport \
  --attack-parameter-value 1500 \
  --attack-parameter-unit ms \
  --summary-csv "$RUN_DIR/experiment_runs.csv" \
  --telemetry-csv "$RUN_DIR/joint_telemetry.csv" \
  --attack-events-csv "$RUN_DIR/attack_events.csv"
```

## Monitor decisions and interpret outcomes

Use separate prepared terminals as needed:

```bash
ros2 topic echo /sentinel/idps/decision
```

```bash
ros2 topic echo /sentinel/ids/alert
```

```bash
ros2 topic echo /sentinel/ids/prediction
```

Check the effective gateway policy:

```bash
ros2 param get /sentinel_idps_gateway prevention_mode
ros2 param get /sentinel_idps_gateway block_confidence_threshold
```

| Observation | Interpretation |
|---|---|
| `suspicious=1`, `action=forwarded`, monitor mode | High-confidence attack detected; the trajectory is allowed for observation. |
| Non-normal class below 0.99, `attack_prediction_below_threshold` | The gateway forwards it under the configured threshold policy. |
| `reason=insufficient_task_context` | No complete run/pose context; the gateway does not block. |
| `blocked=1`, `controller_goal_sent=0` | The gateway withheld this trajectory from the arm controller. |
| Proxy says an attack was armed/applied | Experimental attack status; not by itself evidence of IDPS enforcement. |
| Passive IDS produces an alert | A completed-command observation triggered detection; this is not a blocking action. |
| Task aborts after a blocked goal | May be an expected consequence of withholding a trajectory. It is not evidence that pick-and-place completed successfully. |

For injection and replay, distinguish the added trajectory from the legitimate trajectory that follows it. Inspect matching run keys, phases, targets and decision rows rather than interpreting one terminal line as the outcome of the entire run.

Stop the task first, allow its cleanup to finish, then stop the IDS, proxy, gateway and simulator. Task cleanup may attempt to open the gripper and return home. Do not launch another experiment while an earlier task or cleanup motion is still active.

## Data and recorded results

| File within a session | Writer | Contents |
|---|---|---|
| `experiment_runs.csv` | Task runner | Run-level configuration, timing and outcome records. |
| `joint_telemetry.csv` | Embedded telemetry recorder | Time-stamped joint observations, phase and evaluation metadata. |
| `attack_events.csv` | Embedded telemetry recorder | Attack ground-truth events received from the proxies. |
| `command_trace.csv` | Selected proxy | Command sequence, trajectories, timing, downstream results and attack-related trace fields. |
| `live_ids_predictions.csv` | Passive IDS | Supervised/novelty outputs and run-level detection state. |
| `idps_decisions.csv` | Gateway | Class probabilities, confidence, policy reason, forwarding/blocking and controller outcome fields. |

Ground-truth columns are for evaluation. Their presence in a recorded CSV does not imply they are classifier inputs. The supplied runtime builders explicitly select their feature values. Verifying the offline exclusion rules requires the missing ML source.

The supplied `final_results_summary.md` reports the following live results, with 25 normal runs and 25 runs per attack family in each of monitor and block mode:

| Approach | Attack outcome | Normal-run error |
|---|---|---|
| IDPS monitor | 80/100 attacks detected | 2/25 normal runs alerted |
| Passive IDS, evaluated on monitor runs | 97/100 attacks detected | 10/25 normal runs alerted |
| IDPS block | 83/100 attacks reported prevented | 1/25 normal runs blocked |

The summary also reports 99.29% fused multiclass macro F1 under represented offline conditions, and 94.75% novelty attack-event recall with 14.50% normal-run false positives. These are different evaluation settings and should not be read as interchangeable estimates of live prevention performance.

The live block result should be interpreted using the study's prevention definition. In particular, an upstream DoS delay can already have happened before the gateway withholds the delayed controller goal.

See [the detailed results summary](final_results_summary.md) and the final results directories for the associated analysis. The supplied summary contains absolute `/home/omar/...` image paths; those must be converted to repository-relative links for its figures to display on GitHub.

## Reproducing the evaluation

The documented runtime commands reproduce individual normal and attacked task configurations and create fresh logs. They do not by themselves reproduce the complete dissertation dataset, train the models or rerun all statistical evaluations.

The project summary describes binary and multiclass detection, normal-only novelty detection, configuration holdout, leave-one-attack-out, feature-group ablation, attack-impact analysis and matched live monitor/block validation. Complete offline reproduction additionally requires:

- The actual feature-building, training, evaluation and plotting scripts, including their command-line arguments and execution order.
- The input datasets and original run/configuration manifests or split definitions.
- The relevant dependency versions, saved model bundles and genuine version manifest.
- The scripts defining live event matching and the prevention/detection metrics.

The supplied documentation archive contained no files inside `ml/`, and no root `prepare_system_python.sh` or batch-validation scripts. Exact commands for these missing components cannot be verified from this archive. Add and review those sources before presenting this README as a complete offline reproduction guide.

Do not retrain or change the 0.99 threshold merely to make a demonstration block successfully. Preserve the evaluated settings and document misses and false positives.

## Troubleshooting

| Symptom | Check or action |
|---|---|
| `Package not found` or module import error | Source `/opt/ros/jazzy/setup.bash`, build the workspace and source `install/setup.bash` in that terminal. |
| No gripper or tasks wait for gripper | Use the complete `sentinel_ur5e_moveit.launch.py` wrapper and inspect `ros2 control list_controllers`. |
| Missing Robotiq Xacro/macro error | Check the installed `robotiq_description` files and compatibility with the combined Xacro. |
| Missing model/version manifest | Put the genuine trained bundle and `model_versions.json` in the source model directory, then rebuild. |
| scikit-learn mismatch | Match the recorded training runtime or use the verified preparation/training workflow. Do not bypass the manifest check. |
| Proxy cannot find its downstream action | Start the gateway after the controller and use the exact gateway action as `--controller-action`. |
| Task waits for arm action | Start exactly one proxy on `/sentinel/arm_proxy/follow_joint_trajectory`. |
| Gateway prints nothing | Verify proxy routing; a proxy pointed directly at the controller bypasses the gateway. |
| Attack remains armed | Check attack type, variant, numeric value, unit, target phase and measured-run context. |
| Replay history is too short | Target a later phase and use a history depth available within that run. |
| Passive IDS has no new decisions | Match its trace path to the proxy, start it before the task, and confirm `/joint_states` is active. |
| CSV header mismatch | Use a new session directory rather than mixing trace schemas or deleting the original data. |
| Robot stalls/fails after a block | Inspect the blocked decision and task outcome; withholding a goal can stop the task sequence. |
| Gazebo reset fails | Confirm `gz` is available and the intended world is running; allow the task's reset/settling sequence to finish. |

Useful diagnostics:

```bash
ros2 action list -t
ros2 control list_controllers
ros2 topic hz /joint_states
ros2 param get /sentinel_live_ids command_trace_csv
```

Optional gripper diagnostic:

```bash
/usr/bin/python3 -m sentinel_arm_tasks.gripper_state
```

Do not run `generate_fixed_poses.py` as a normal startup step. It requires a separately configured MoveIt IK service and writes new poses into the source tree. The supplied workcell wrapper does not start that service.
