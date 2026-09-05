# Matched live IDS/IDPS validation

Monitor trials: 125. Block trials: 125. The design uses 25 monitor-mode normal trials and 25 block-mode normal trials. Each attack family contains the same frozen task, severity, target-object and repetition configurations in monitor and block mode.

## Overall metrics

| metric | value | numerator | denominator |
| --- | --- | --- | --- |
| idps_monitor_attacked_run_recall | 80.0% | 80 | 100 |
| idps_monitor_normal_run_false_positive_rate | 8.0% | 2 | 25 |
| passive_ids_attacked_run_recall | 97.0% | 97 | 100 |
| passive_ids_normal_run_false_positive_rate | 40.0% | 10 | 25 |
| idps_block_attacked_run_prevention_recall | 83.0% | 83 | 100 |
| idps_block_normal_run_false_block_rate | 4.0% | 1 | 25 |
| idps_monitor_inference_ms_median | 25.910 ms |  | 1679 |
| idps_block_inference_ms_median | 23.913 ms |  | 1212 |
| passive_ids_run_median_decision_delay_ms_median | 122.070 ms |  | 125 |

## Recall by attack family

| dataset_class | monitor_runs | idps_monitor_recall | passive_ids_recall | idps_block_prevention_recall |
| --- | --- | --- | --- | --- |
| Command injection | 25 | 88.0% | 100.0% | 92.0% |
| Delay DoS | 25 | 100.0% | 100.0% | 100.0% |
| MITM manipulation | 25 | 64.0% | 100.0% | 68.0% |
| Replay | 25 | 68.0% | 88.0% | 72.0% |

## Interpretation rule

The live experiment demonstrates operational feasibility and end-to-end behaviour; it does not replace the 600-run grouped offline evaluation. With 25 live trials per attack family, report both the count and rate and retain the Wilson intervals in `live_per_attack_metrics.csv`.
