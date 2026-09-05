# Dissertation Outline

The project aims to test whether command and physical telemetry from a digital twin can be used to detect and prevent cyber-induced behavioural anomalies during autonomous pick-and-place operations.

The 4 attacks evaluated are:

1. Command Injection - an additional malicious trajectory command is introduced.
2. MITM - a legitimate trajectory is modified while being forwarded.
3. Replay - a previously valid command is present outside it's original temporal or task context.
4. Delay DoS - command delivery or execution is deliberately delayed.

The evaluation compares cyber-command features, physical joint features and their fusion. It examines recognition under known conditions, novelty detection, generalisation to unseen configurations and live detection and prevention.

# Evaluation Approach

The offline experiments used complete robot runs as the grouping unit. Commands from one execution were therefore kept within the same training/testing partition, which reduces the leakage caused by correlated observations from the same trajectory. 

The offline evaluation included:

- Binary Classification
- Multiclass Classification
- five-fold normal-only novelty detection
- leave-one-attack-out testing
- leave-one-configuration-out testing
- comparison of cyber-only, physical-only and fused feature sets
- feature importance and feature-group ablation


Each attack family therefore had **25 monitor trials and 25 block trials**, giving 200 attacked runs across the complete live experiment.

Three operational security paths were measured:

- **IDPS monitor:** makes a pre-execution decision and raises an alert without blocking the command.
- **Passive IDS:** detects anomalous behaviour after command execution using command and physical evidence.
- **IDPS block:** makes a pre-execution decision and prevents a suspicious command from reaching the controller.

# Offline Results

### Binary Classification

The closed-set models achieved approximately 99.9% classification performance when training and testing contained the same attack families and experimental configuration space. 

![alt text](/home/omar/master_project/sentinel_arm_ws/results/final_data/offline_evaluation/binary/binary_model_comparison.png)

The result shows that the implemented attacks are highly distinguishable when examples serves are representatives during training. It is treated as a supporting baseline rather than the principal result because closed-set performance does not establish detection of a new attack family or perforamnce under an unseen configuration. 

### Multiclass Classification

Again, the closed-set models could distinguish normal behaviour from the 4 attacks pretty well. However, unlike binary classification, which only predicts whether an observation is normal/attack, multiclass classificationa lso predcits the specific attack category.

| Feature set   | Best model           |   Accuracy | Balanced accuracy |   Macro F1 |
| ------------- | -------------------- | ---------: | ----------------: | ---------: |
| Cyber-only    | Random Forest        |     99.84% |            97.60% |     98.23% |
| Physical-only | HistGradientBoosting |     98.61% |            77.80% |     77.88% |
| Fused         | HistGradientBoosting | **99.91%** |        **99.19%** | **99.29%** |

| Class             | Precision |  Recall |      F1 |
| ----------------- | --------: | ------: | ------: |
| Normal            |    99.95% |  99.96% |  99.95% |
| MITM manipulation |    97.06% |  99.00% |  98.02% |
| Command injection |   100.00% |  98.00% |  98.99% |
| Replay            |   100.00% | 100.00% | 100.00% |
| Delay DoS         |   100.00% |  99.00% |  99.50% |

The fused model achieved the strongest performance, showing that knonw attacks produced sufficinetly distinct command and physical patterns for attack-type identification. Cyber-only models also did well, whereas phyiscal only performance was weaker when measured using balanced accuracy and macro F1.

These results are closed-set beccause every attack family was represented during model development. They demonstrate recognition of known attacks but do not establish whether the model can detect an attack excluded from training.

![](/home/omar/master_project/sentinel_arm_ws/results/final_data/offline_evaluation/multiclass/multiclass_model_comparison.png)


### Novelty Detection

Novelty detection is defined as an evaluation model that "identifies new or unseen data points, pattern or events that differ from a model's normal training data." 

| Metric | Result | Interpretation |
|---|---:|---|
| Attack-event recall | **94.75%** | Proportion of attack-active events identified as anomalous |
| Attacked-run recall | **95.75%** | Proportion of attacked executions producing an alert |
| Normal-run false-positive rate | **14.50%** | Proportion of normal executions producing an alert |

| Fold | Attack-event recall | Normal-run false-positive rate |
|---:|---:|---:|
| 1 | 93.8% | 17.5% |
| 2 | 95.0% | 7.5% |
| 3 | 96.3% | 12.5% |
| 4 | 95.0% | 12.5% |
| 5 | 93.8% | 22.5% |

Attack recal was consistent across folds, remaining approximately between 93.8%-96.3%. FPR was less stable, ranging from 7.5%-22.5%. The detector consequently demonstrates strong sensitivity to attacks but requires a trade-off between novelty sensitivity and normal-operation false alarms.

### Leave-one-configuration

The leave-one-configuration-out experiments tested whether a model trained without a particular severity or object configuration could detect attacks when that conifugration appeared at a test time. 

| Held-out configuration | Best feature set and model | Event recall | F1 | Normal-run FPR |
|---|---|---:|---:|---:|
| Medium severity | Fused Random Forest | **74.17%** | **85.16%** | **0.0%** |
| High severity | Fused HistGradientBoosting | **74.38%** | **85.30%** | **0.0%** |
| Low severity | Cyber-only Random Forest | **66.25%** | **77.07%** | **1.5%** |
| Cylinder object | Cyber-only Random Forest | **39.99%** | **52.59%** | **2.0%** |
| Cube object | Physical-only Random Forest | **2.71%** | **5.08%** | **0.0%** |

![alt text](/home/omar/master_project/sentinel_arm_ws/results/final_data/offline_evaluation/configuration_generalisation/best_f1_by_configuration.png)

The models generalised well across unseen attack severities, achieving event recall between 66.25%-74.38%. Generatlisation across unseen objets was weak however. In particular, excluding the cube configuration reduced recall to 2.71% which indicates significant dependence on configuration-specfici behavioural patterns.

### Leave-one-attack-out

Leave one attack out experiments tested whether supervisor models could detect a completely excluded attack. For each scenario, the model was trained using normal behaviour and three attack families, while the fourth attack was witheld entirely until testing. 

| Held-out attack   | Best feature set and model         | Precision | Attack-event recall | Attacked-run recall |     F1 | Normal-run FPR |
| ----------------- | ---------------------------------- | --------: | ------------------: | ------------------: | -----: | -------------: |
| Command injection | Physical-only Random Forest        |    84.72% |          **92.00%** |          **92.00%** | 87.22% |           0.0% |
| Delay DoS         | Fused Random Forest                |     0.00% |           **0.00%** |           **0.00%** |  0.00% |           0.0% |
| MITM manipulation | Physical-only HistGradientBoosting |   100.00% |          **98.00%** |          **98.00%** | 98.97% |           0.0% |
| Replay            | Cyber-only Random Forest           |     0.00% |           **0.00%** |           **0.00%** |  0.00% |           2.5% |

The results demonstrate that supervised generalisation depended strongly on the attack family withheld from training. MITM manipulation generalised particularly well, achieving 98% event and attacked-run recall, while command injection achieved 92%. This suggests that these attacks created behavioural deviations resembling patterns learned from the remaining attacks.

By contrast, the selected operating thresholds detected none of the held-out Delay DoS or replay attacks. Replay achieved a low PR-AUC of approximately 31.03%, indicating weak separation from normal behaviour. Delay DoS achieved a much higher PR-AUC of approximately 97.77% despite zero thresholded recall. This indicates that the model ranked many DoS observations as comparatively suspicious, but their scores did not cross the decision threshold calibrated using the known attack families. Its failure therefore reflects poor threshold transfer rather than necessarily an absolute absence of separability.

These findings show that learning several known attack families does not guarantee detection of every unknown attack. Attack diversity, feature modality and threshold calibration materially affect open-set generalisation.

<!-- ![](/home/omar/master_project/sentinel_arm_ws/results/final_data/offline_evaluation/leave_one_attack_out/held_out_attack_recall.png) -->

### Feature Ablation

Feature ablation is a test in ML to find out how important a specifci input/feature is. Each feature group was first evaluated by itself using run-grouped five-fold validation. A complementary leave-one-feature-group-out ablation then measured the change in performance when each group was removed from the complete fused feature set.

| Feature group         |         F1 | Attack recall |      PR-AUC | Normal-run FPR |
| --------------------- | ---------: | ------------: | ----------: | -------------: |
| All physical features | **99.36%** |    **98.75%** | **100.00%** |           0.0% |
| All fused features    | **99.24%** |    **98.50%** | **100.00%** |           0.0% |
| Joint positions       | **99.13%** |    **99.00%** |  **99.99%** |           1.0% |
| Joint velocities      | **98.64%** |    **99.00%** |  **99.84%** |           2.5% |
| All cyber features    | **97.62%** |    **97.75%** |  **99.65%** |           3.5% |
| Timing and context    | **94.38%** |    **94.50%** |  **97.92%** |           8.5% |
| Joint efforts         | **86.80%** |    **85.50%** |  **95.88%** |          13.0% |
| Tracking residuals    | **81.52%** |    **79.75%** |  **89.31%** |          17.5% |
| Command targets       | **72.79%** |    **57.25%** |  **70.70%** |           0.0% |
| Sampling context      | **28.68%** |    **31.25%** |  **23.11%** |          48.0% |

Joint positions and velocities were the strongest indivial features, showing that the robot's physical motion provided highly informative attack evidence. Timing and context also performed strongly, while command targets alone detected only 57.25% of attacked events. 

![](/home/omar/master_project/sentinel_arm_ws/ml/results/feature_group_ablation/feature_group_standalone_performance.png)

| Removed feature group |            Mean F1 loss | Mean attack-recall loss |
| --------------------- | ----------------------: | ----------------------: |
| Tracking residuals    |  0.26 percentage points |  0.50 percentage points |
| Joint efforts         |  0.25 percentage points |  0.25 percentage points |
| Sampling context      |  0.13 percentage points |  0.25 percentage points |
| Timing and context    |  0.13 percentage points |  0.25 percentage points |
| Joint velocities      |  0.12 percentage points |  0.00 percentage points |
| Command targets       |  0.00 percentage points |  0.00 percentage points |
| Joint positions       | −0.13 percentage points | −0.50 percentage points |

Positive values indicate reduced performance after removal. Negative values indicate that the ablated model performed slightly better. However, the 95% confidence intervals generally crossed zero, meaning that none of the observed removal effects provides clear evidence that one group was individually indispensable.

The standalone and ablation results should be interpreted together. Joint positions and velocities were highly predictive independently, but removing one group from the fused model caused little degradation because other feature groups contained overlapping information. The findings therefore support telemetry redundancy rather than dependence on one isolated predictor.


### Attack Impact Analysis

Attack-impact analysis evaluated how the four attack families changed the robot’s command targets, final joint position, velocity profile, effort profile, proxy timing and final tracking error. Each attack-active command was compared with matched out-of-fold normal behaviour from the same operational context, preventing the attacked observation from being compared with normal data used to construct its own reference.

The effect-size heatmap reports the probability that an attacked command produced a greater deviation than a matched normal command. A value of 0.5 indicates no consistent difference, while a value close to 1.0 indicates that the attack almost always produced a larger deviation.


![](/home/omar/master_project/sentinel_arm_ws/ml/results/attack_impact/attack_impact_effect_size_heatmap.png)

The attacks produced different behavioural signatures:

- Command injection and MITM manipulation consistently changed the commanded target, final position and velocity profile. Their effort, timing and final tracking-error effects were less consistent.

- Delay DoS did not alter the commanded target or consistently change final position. Its strongest effects appeared in velocity, effort and proxy timing, which is consistent with a timing and availability attack.

- Replay produced the broadest behavioural effect, with strong deviations across command, position, velocity, timing, effort and tracking error.
The severity analysis shows that all evaluated attacks generally produced behaviour well above the median normal-operation profile. However, the distributions overlap across low, medium and high settings, so increasing the configured severity did not produce a perfectly monotonic increase for every attack and metric.

These results demonstrate that the four attacks are not merely different labels assigned to similar data. Each attack affects a different combination of command integrity, timing and physical response. This helps explain why multimodal monitoring is useful: a target-based detector may identify injection and MITM but miss Delay DoS, whereas timing and physical-motion features reveal evidence unavailable from the target command alone.

# Live Evaluation

The final live experiment used matched monitor-mode and block-mode configurations.

| Mode | Normal runs | Command injection | Delay DoS | MITM | Replay | Total |
|---|---:|---:|---:|---:|---:|---:|
| IDPS monitor | 25 | 25 | 25 | 25 | 25 | 125 |
| IDPS block | 25 | 25 | 25 | 25 | 25 | 125 |
| **Total** | **50** | **50** | **50** | **50** | **50** | **250** |

### 125 run approach results:

| Approach | Security successes | Security rate | Normal-operation errors | Normal error rate |
|---|---:|---:|---:|---:|
| IDPS monitor | 80/100 attacks detected | **80% recall** | 2/25 normal runs alerted | **8% FPR** |
| Passive IDS | 97/100 attacks detected | **97% recall** | 10/25 normal runs alerted | **40% FPR** |
| IDPS block | 83/100 attacks prevented | **83% prevention recall** | 1/25 normal runs blocked | **4% false-block rate** |

The passive IDS had the greatest attack sensitivity, detecting 97 of 100 attacked runs. However, its 40% normal-run false-positive rate makes it unsuitable as an unqualified blocking mechanism.

The active IDPS prevented 83 of 100 attacks while falsely blocking one of 25 normal executions. It therefore produced the strongest operational balance between attack prevention and preservation of normal commands.


| Attack family | IDPS monitor | Passive IDS | IDPS block |
|---|---:|---:|---:|
| Command injection | 22/25 - **88%** | 25/25 - **100%** | 23/25 - **92%** |
| Delay DoS | 25/25 - **100%** | 25/25 - **100%** | 25/25 - **100%** |
| MITM manipulation | 16/25 - **64%** | 25/25 - **100%** | 17/25 - **68%** |
| Replay | 17/25 - **68%** | 22/25 - **88%** | 18/25 - **72%** |
| **Overall** | **80/100 - 80%** | **97/100 - 97%** | **83/100 - 83%** |

Delay DoS was detected and prevented in every live trial. Command injection was also handled reliably, with 88% pre-execution detection, 100% passive detection and 92% prevention.

MITM manipulation and replay were more difficult for the pre-execution IDPS. These attacks can retain structurally plausible command values and are therefore harder to distinguish before their effect on physical execution becomes available. The passive IDS detected all MITM runs and 88% of replay runs, showing the additional value of post-execution physical evidence.

![](/home/omar/master_project/sentinel_arm_ws/results/final_data/live_validation/live_recall_by_attack.png)

### Wilson 95% confidence intervals

The intervals below reflect the uncertainty associated with 25 trials per attack family and operational path.

| Attack family | IDPS monitor recall, 95% CI | Passive IDS recall, 95% CI | IDPS block recall, 95% CI |
|---|---:|---:|---:|
| Command injection | 88% [70.0%, 95.8%] | 100% [86.7%, 100%] | 92% [75.0%, 97.8%] |
| Delay DoS | 100% [86.7%, 100%] | 100% [86.7%, 100%] | 100% [86.7%, 100%] |
| MITM manipulation | 64% [44.5%, 79.8%] | 100% [86.7%, 100%] | 68% [48.4%, 82.8%] |
| Replay | 68% [48.4%, 82.8%] | 88% [70.0%, 95.8%] | 72% [52.4%, 85.7%] |

The intervals should accompany the point estimates because 25 trials per attack family provide useful comparative evidence but do not justify treating the displayed percentages as exact population performance.

### Operational Latency

| Measurement | Median | 95th percentile | Observations |
|---|---:|---:|---:|
| IDPS monitor inference | **25.910 ms** | **37.214 ms** | 1,679 |
| IDPS block inference | **23.913 ms** | **28.534 ms** | 1,212 |
| Passive IDS run-median decision delay | **122.070 ms** | **159.647 ms** | 125 runs |

The active IDPS generally made pre-execution decisions in approximately 24–26 ms. This demonstrates that the classification step can be inserted into the ROS 2 command path without a large computational delay. The passive IDS responded later because it required post-execution evidence.

### Task Success

| Metric | Result |
|---|---:|
| Monitor-mode task success | 115/125 - **92%** |
| Normal task success in block mode | 23/25 - **92%** |
| IDPS monitor normal-run false-alert rate | 2/25 - **8%** |
| Passive IDS normal-run false-alert rate | 10/25 - **40%** |
| IDPS normal-run false-block rate | 1/25 - **4%** |

Normal operation was largely maintained in block mode, although one normal run was mistakenly blocked. The task sucess results also show a small amount of execution variability that hould not automatically be attributed to the security classifier. 

### Relationship between pre/post-execution detection
The IDPS monitor missed 20 attacked runs, while the passive IDS detected 17 of those missed runs. This demonstrates that pre-execution command evidence and post-execution behavioural evidence are complementary.

The results suggest a possible layered deployment:

- high-confidence pre-execution predictions can block commands immediately
- lower-confidence commands can be permitted while receiving enhanced passive monitoring
- physical evidence can generate a later alert or trigger a safe-stop response.

The current project evaluates these components and their trade-offs, but the layered decision policy itself remains future work.

# Limitations

- The experiments use a simulated UR5e rather than a physical industrial robot.
- The attack model contains four controlled command-layer attack families.
- Generalisation to other robots, controllers and tasks has not been established.
- Object holdout results show substantial configuration dependence.
- MITM and replay produce lower pre-execution recall than command injection and Delay DoS.
- The passive IDS false-positive rate is too high for direct use as an automatic prevention mechanism.
- Twenty-five trials per attack family produce meaningful evidence, but the confidence intervals remain moderately wide.
- Some task failures may arise from simulation or controller variability rather than security decisions.


# Conclusion

| Evaluation setting | Principal result | Main limitation |
|---|---|---|
| Closed-set supervised | Approximately 99.9% under represented conditions | Does not test unseen attacks or configurations |
| Normal-only novelty detection | 95.75% attacked-run recall | 14.5% normal-run FPR |
| Unseen severity | 66.25–74.38% event recall | Performance varies by severity and feature set |
| Unseen object | 2.71–39.99% event recall | Strong configuration dependence |
| Live IDPS monitor | 80% attacked-run recall | MITM and replay misses |
| Live passive IDS | 97% attacked-run recall | 40% normal-run FPR |
| Live IDPS block | 83% prevention recall | 17 attacks missed and one normal run blocked |

The live results are lower than the strongest offline figures. This is expected because live execution includes timing variation, system-state variation and the complete integration path. The difference is an important empirical result: offline classification performance alone would have overstated operational effectiveness.

The project demonstrates the feasibility of low-latency behavioural intrusion detection and command-level prevention in a ROS 2 robotic-arm digital twin. The final active IDPS prevented **83 of 100 live attacks**, falsely blocked **one of 25 normal runs**, and required approximately **24 ms median inference time**. A passive behavioural IDS increased detection to **97 of 100 attacks**, demonstrating the value of physical evidence, but produced false alerts in **10 of 25 normal runs**.

The results do not support a claim of universal or production-ready protection. They instead provide evidence that a digital twin can support an effective IDS/IDPS under the evaluated conditions, while identifying replay, MITM manipulation, false-positive control and cross-configuration generalisation as the principal areas requiring further work.

<!-- # Offline Findings

1. Known attacks are readily separable when their patterns are represented during training.
2. Normal-only novelty detection can identify most attacked runs, but produces more normal-operation false alerts.
3. Generalisation across attack severity is considerably stronger than generalisation across object configuration.
4. No individual modality is universally optimal: the best feature set varies according to the held-out condition. -->