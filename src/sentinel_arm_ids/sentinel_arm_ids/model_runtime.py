from __future__ import annotations

from collections import defaultdict
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


def validate_runtime_version(model_path: Path) -> None:
    manifest_path = model_path.with_name("model_versions.json")
    if not manifest_path.exists():
        raise RuntimeError(f"Model version manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_version = manifest.get(model_path.name)
    if not expected_version:
        raise RuntimeError(
            f"No scikit-learn version is recorded for {model_path.name}."
        )

    try:
        runtime_version = version("scikit-learn")
    except PackageNotFoundError as exc:
        raise RuntimeError(
            "scikit-learn is not installed for /usr/bin/python3. "
            "Install the package.xml dependencies with rosdep."
        ) from exc
    if runtime_version != expected_version:
        raise RuntimeError(
            f"{model_path.name} was trained with scikit-learn "
            f"{expected_version}, but /usr/bin/python3 has {runtime_version}. "
            "Run ./prepare_system_python.sh from the workspace root."
        )


def anomaly_score(bundle: Mapping[str, Any], frame: pd.DataFrame) -> float:
    transformed = bundle["scaler"].transform(bundle["imputer"].transform(frame))
    estimator = bundle["estimator"]
    components = estimator.components_[: int(bundle["pca_components_retained"])]
    centered = transformed - estimator.mean_
    projected = centered @ components.T
    reconstructed = projected @ components + estimator.mean_
    return float(np.mean(np.square(transformed - reconstructed), axis=1)[0])


class IdsEngine:

    def __init__(
        self,
        supervised_model_path: Path,
        novelty_model_path: Path,
        temporal_model_path: Path,
        supervised_attack_threshold: float = 0.50,
    ) -> None:
        for model_path in (
            supervised_model_path,
            novelty_model_path,
            temporal_model_path,
        ):
            validate_runtime_version(model_path)
        self.supervised = joblib.load(supervised_model_path)
        self.novelty = joblib.load(novelty_model_path)
        self.temporal = joblib.load(temporal_model_path)
        self.supervised_attack_threshold = float(supervised_attack_threshold)
        if not 0.0 < self.supervised_attack_threshold <= 1.0:
            raise ValueError("supervised_attack_threshold must be in (0, 1].")
        self._base_run_max: dict[str, float] = defaultdict(lambda: -np.inf)
        self._temporal_run_max: dict[str, float] = defaultdict(lambda: -np.inf)
        self._known_attack_by_run: dict[str, str] = {}
        self._unknown_attack_runs: set[str] = set()

    def required_columns(self) -> set[str]:
        return set(self.supervised["feature_columns"]) | set(
            self.temporal["feature_columns"]
        )

    def predict(self, features: Mapping[str, float], run_key: str) -> dict[str, Any]:
        missing = sorted(self.required_columns() - set(features))
        if missing:
            raise ValueError(f"Missing required live features: {missing[:10]}")

        supervised_columns = self.supervised["feature_columns"]
        supervised_frame = pd.DataFrame(
            [[features[column] for column in supervised_columns]],
            columns=supervised_columns,
        )
        probabilities = self.supervised["model"].predict_proba(supervised_frame)[0]
        classes = list(self.supervised["model"].classes_)
        best_index = int(np.argmax(probabilities))
        supervised_label = str(classes[best_index])
        supervised_confidence = float(probabilities[best_index])
        normal_probability = (
            float(probabilities[classes.index("normal")]) if "normal" in classes else 0.0
        )
        class_probabilities = {
            f"supervised_probability_{label}": float(probability)
            for label, probability in zip(classes, probabilities, strict=True)
        }
        known_attack_alert = bool(
            supervised_label != "normal"
            and supervised_confidence >= self.supervised_attack_threshold
        )

        base_columns = self.novelty["feature_columns"]
        base_frame = pd.DataFrame(
            [[features[column] for column in base_columns]], columns=base_columns
        )
        temporal_columns = self.temporal["feature_columns"]
        temporal_frame = pd.DataFrame(
            [[features[column] for column in temporal_columns]],
            columns=temporal_columns,
        )
        base_score = anomaly_score(self.novelty, base_frame)
        temporal_score = anomaly_score(self.temporal, temporal_frame)
        self._base_run_max[run_key] = max(self._base_run_max[run_key], base_score)
        self._temporal_run_max[run_key] = max(
            self._temporal_run_max[run_key], temporal_score
        )
        temporal_command_alert = bool(
            temporal_score >= float(self.temporal["command_threshold"])
        )
        base_run_alert = bool(
            self._base_run_max[run_key] >= float(self.novelty["run_threshold"])
        )
        novelty_signal_active = temporal_command_alert or base_run_alert

        if known_attack_alert:
            self._known_attack_by_run[run_key] = supervised_label
            verdict = "known_attack"
            alert_label = supervised_label
            new_unknown_attack_alert = False
        elif (
            novelty_signal_active
            and run_key not in self._known_attack_by_run
            and run_key not in self._unknown_attack_runs
        ):
            self._unknown_attack_runs.add(run_key)
            verdict = "unknown_attack"
            alert_label = "unknown_attack"
            new_unknown_attack_alert = True
        else:
            verdict = "normal"
            alert_label = "normal"
            new_unknown_attack_alert = False

        run_known_attack_label = self._known_attack_by_run.get(run_key, "")
        run_unknown_attack_detected = run_key in self._unknown_attack_runs
        run_compromised = bool(
            run_known_attack_label or run_unknown_attack_detected
        )

        return {
            "supervised_label": supervised_label,
            "supervised_confidence": supervised_confidence,
            "supervised_normal_probability": normal_probability,
            **class_probabilities,
            "known_attack_alert": known_attack_alert,
            "novelty_base_score": base_score,
            "novelty_base_command_threshold": float(
                self.novelty["command_threshold"]
            ),
            "novelty_base_run_max": self._base_run_max[run_key],
            "novelty_base_run_threshold": float(self.novelty["run_threshold"]),
            "novelty_temporal_score": temporal_score,
            "novelty_temporal_command_threshold": float(
                self.temporal["command_threshold"]
            ),
            "novelty_temporal_run_max": self._temporal_run_max[run_key],
            "novelty_temporal_run_threshold": float(
                self.temporal["run_threshold"]
            ),
            "temporal_command_alert": temporal_command_alert,
            "base_run_alert": base_run_alert,
            "novelty_signal_active": novelty_signal_active,
            "new_unknown_attack_alert": new_unknown_attack_alert,
            "novelty_alert": new_unknown_attack_alert,
            "run_known_attack_label": run_known_attack_label,
            "run_unknown_attack_detected": run_unknown_attack_detected,
            "run_compromised": run_compromised,
            "verdict": verdict,
            "alert_label": alert_label,
        }
