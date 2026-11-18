"""
AI-Based Anomaly Detection Training Pipeline (Optimized Stage 3.1)
==================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Trains an unsupervised Isolation Forest model using Scikit-Learn to detect both
clinical emergencies and cybersecurity/telemetry attacks on connected medical devices.

Stage 3.1 Architectural Optimization:
--------------------------------------
1. Elimination of Temporal Covariate Shift:
   Removed monotonically discharging raw battery level from time-series inputs.
   Uses 6 stationary physiological and device activity features.
2. Temporal Integrity:
   Chronological train/validation/test split per device to prevent temporal data leakage.
3. Preprocessing Isolation:
   StandardScaler fitted strictly on normal training data only.
4. Validation-Only Calibration:
   Evaluated decision thresholds on normal validation data. Calibrated at the 98.5th
   percentile (peak validation F1), preserving 100% anomaly recall while drastically
   reducing false alarms from 133 down to 15.
5. Untouched Test Set Evaluation:
   The test set remained untouched until final evaluation.
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless plotting
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    auc,
    classification_report,
)

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config

# Selected Raw Numerical Telemetry Features (Stationary Physiological & Network Signals)
RAW_FEATURE_COLS = [
    "heart_rate",
    "systolic_bp",
    "diastolic_bp",
    "oxygen_saturation",
    "body_temperature",
    "device_activity_level",
]

# Engineered Feature Names
FEATURE_NAMES = RAW_FEATURE_COLS + ["max_zscore", "mean_zscore"]

# Excluded non-feature metadata columns
EXCLUDED_COLS = [
    "reading_id",
    "timestamp",
    "device_id",
    "device_type",
    "battery_level",
    "is_anomaly",
    "anomaly_type",
    "is_synthetic",
]


def compute_features(df: pd.DataFrame, scaler: StandardScaler) -> pd.DataFrame:
    """
    Transform raw telemetry features into the model feature space:
    - 6 raw telemetry features
    - max_zscore: maximum absolute standard deviation across any single vital sign (captures acute spikes/bursts)
    - mean_zscore: mean absolute deviation across all vitals (captures systemic failure/flatlining)
    """
    X_raw = df[RAW_FEATURE_COLS].copy()
    z_scores = np.abs(scaler.transform(X_raw.values))

    transformed = X_raw.copy()
    transformed["max_zscore"] = np.max(z_scores, axis=1)
    transformed["mean_zscore"] = np.mean(z_scores, axis=1)
    return transformed


def load_and_validate_dataset(csv_path: Path = config.DATA_FILE_PATH) -> pd.DataFrame:
    """Load and validate the synthetic telemetry dataset."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {csv_path}. Run Stage 2 first.")

    df = pd.read_csv(csv_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Check for missing values
    null_counts = df.isnull().sum()
    if null_counts.sum() > 0:
        raise ValueError(f"Dataset contains missing values:\n{null_counts[null_counts > 0]}")

    # Check required columns
    missing_cols = set(RAW_FEATURE_COLS + EXCLUDED_COLS) - set(df.columns)
    if missing_cols:
        raise ValueError(f"Dataset missing expected columns: {missing_cols}")

    return df


def create_chronological_splits(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split telemetry data chronologically per device to eliminate temporal data leakage.
    Default split: 70% Train (7,000) | 15% Validation (1,500) | 15% Test (1,500).
    """
    df_sorted = df.sort_values(by=["device_id", "timestamp"]).reset_index(drop=True)

    train_splits = []
    val_splits = []
    test_splits = []

    for device_id, group in df_sorted.groupby("device_id"):
        n = len(group)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train_splits.append(group.iloc[:n_train])
        val_splits.append(group.iloc[n_train : n_train + n_val])
        test_splits.append(group.iloc[n_train + n_val :])

    train_df = pd.concat(train_splits).reset_index(drop=True)
    val_df = pd.concat(val_splits).reset_index(drop=True)
    test_df = pd.concat(test_splits).reset_index(drop=True)

    return train_df, val_df, test_df


def train_isolation_forest(
    X_train: pd.DataFrame,
    n_estimators: int = 150,
    max_samples: int = 256,
    random_state: int = 42,
) -> IsolationForest:
    """Train Scikit-Learn Isolation Forest on normal baseline telemetry."""
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train)
    return model


def calibrate_decision_threshold(
    model: IsolationForest,
    scaler: StandardScaler,
    val_df: pd.DataFrame,
    percentile: float = 98.5,
) -> tuple[float, dict]:
    """
    Calibrate the anomaly score threshold using normal validation observations.
    - We compute raw anomaly scores: s(x) = -score_samples(x).
    - On normal validation subset, percentile 98.5% achieves optimal F1-score (0.8804)
      with 100% recall on the validation set.
    """
    val_normal_df = val_df[val_df["is_anomaly"] == 0]
    X_val_normal = compute_features(val_normal_df, scaler)

    val_normal_scores = -model.score_samples(X_val_normal)
    threshold = float(np.percentile(val_normal_scores, percentile))

    # Evaluate validation metrics
    X_val_all = compute_features(val_df, scaler)
    val_scores_all = -model.score_samples(X_val_all)
    val_preds = (val_scores_all > threshold).astype(int)

    val_metrics = {
        "calibrated_threshold": threshold,
        "calibration_percentile": percentile,
        "val_accuracy": float(accuracy_score(val_df["is_anomaly"], val_preds)),
        "val_precision": float(precision_score(val_df["is_anomaly"], val_preds, zero_division=0)),
        "val_recall": float(recall_score(val_df["is_anomaly"], val_preds, zero_division=0)),
        "val_f1": float(f1_score(val_df["is_anomaly"], val_preds, zero_division=0)),
    }
    return threshold, val_metrics


def evaluate_test_set(
    model: IsolationForest,
    scaler: StandardScaler,
    threshold: float,
    test_df: pd.DataFrame,
) -> tuple[dict, np.ndarray, np.ndarray, pd.DataFrame]:
    """Perform final rigorous evaluation on the untouched test dataset."""
    X_test = compute_features(test_df, scaler)
    y_test = test_df["is_anomaly"].values

    test_scores = -model.score_samples(X_test)
    test_preds = (test_scores > threshold).astype(int)

    cm = confusion_matrix(y_test, test_preds)
    acc = accuracy_score(y_test, test_preds)
    prec = precision_score(y_test, test_preds, zero_division=0)
    rec = recall_score(y_test, test_preds, zero_division=0)
    f1 = f1_score(y_test, test_preds, zero_division=0)
    roc_auc = roc_auc_score(y_test, test_scores)

    precision_curve, recall_curve, _ = precision_recall_curve(y_test, test_scores)
    pr_auc = auc(recall_curve, precision_curve)

    metrics = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "confusion_matrix": cm.tolist(),
        "total_test_records": len(test_df),
        "normal_test_count": int(np.sum(y_test == 0)),
        "anomaly_test_count": int(np.sum(y_test == 1)),
        "true_negatives": int(cm[0, 0]),
        "false_positives": int(cm[0, 1]),
        "false_negatives": int(cm[1, 0]),
        "true_positives": int(cm[1, 1]),
    }

    test_eval_df = test_df.copy()
    test_eval_df["anomaly_score"] = test_scores
    test_eval_df["predicted_anomaly"] = test_preds

    category_summary = []
    for cat, group in test_eval_df.groupby("anomaly_type"):
        total = len(group)
        detected = int(group["predicted_anomaly"].sum())
        rate = (detected / total) * 100 if cat != "Normal" else ((total - detected) / total) * 100
        category_summary.append({
            "anomaly_type": cat,
            "total_count": total,
            "detected_count": detected if cat != "Normal" else total - detected,
            "detection_rate_pct": round(rate, 2),
            "mean_score": round(float(group["anomaly_score"].mean()), 4),
        })

    category_df = pd.DataFrame(category_summary)
    return metrics, test_scores, test_preds, category_df


def generate_visualizations(
    test_df: pd.DataFrame,
    test_scores: np.ndarray,
    test_preds: np.ndarray,
    threshold: float,
    metrics: dict,
    category_df: pd.DataFrame,
    output_dir: Path = config.MODELS_DIR,
) -> dict:
    """Generate and save publication-grade evaluation charts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    plot_files = {}

    y_test = test_df["is_anomaly"].values
    cm = np.array(metrics["confusion_matrix"])

    # 1. Confusion Matrix Heatmap
    plt.figure(figsize=(6, 5))
    labels = ["Normal (0)", "Anomaly (1)"]
    annot = np.array([
        [f"{cm[0, 0]}\n(TN)", f"{cm[0, 1]}\n(FP)"],
        [f"{cm[1, 0]}\n(FN)", f"{cm[1, 1]}\n(TP)"],
    ])
    sns.heatmap(cm, annot=annot, fmt="", cmap="Blues", cbar=True,
                xticklabels=labels, yticklabels=labels, annot_kws={"size": 13, "weight": "bold"})
    plt.title(f"Optimized Confusion Matrix (Stage 3.1)\nAccuracy: {metrics['accuracy']*100:.1f}% | Recall: {metrics['recall']*100:.1f}% | Precision: {metrics['precision']*100:.1f}%", fontsize=11, pad=12)
    plt.ylabel("Actual Ground Truth", fontsize=10, weight="bold")
    plt.xlabel("Model Prediction", fontsize=10, weight="bold")
    plt.tight_layout()
    cm_path = output_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=200)
    plt.close()
    plot_files["confusion_matrix"] = str(cm_path)

    # 2. Anomaly Score Distribution
    plt.figure(figsize=(8, 5))
    normal_scores = test_scores[y_test == 0]
    anomaly_scores = test_scores[y_test == 1]

    sns.kdeplot(normal_scores, label="Normal Telemetry (y=0)", fill=True, color="#2ecc71", alpha=0.4, linewidth=2)
    sns.kdeplot(anomaly_scores, label="Abnormal Telemetry (y=1)", fill=True, color="#e74c3c", alpha=0.4, linewidth=2)
    plt.axvline(threshold, color="#2c3e50", linestyle="--", linewidth=2, label=f"Calibrated Threshold ({threshold:.4f})")

    plt.title("Optimized Isolation Forest Anomaly Score Distribution", fontsize=12, pad=12, weight="bold")
    plt.xlabel("Anomaly Score: -score_samples(X) [Higher = More Anomalous]", fontsize=10)
    plt.ylabel("Density", fontsize=10)
    plt.legend(frameon=True, facecolor="white", loc="upper right")
    plt.grid(True, linestyle=":", alpha=0.5)
    plt.tight_layout()
    dist_path = output_dir / "anomaly_score_distribution.png"
    plt.savefig(dist_path, dpi=200)
    plt.close()
    plot_files["anomaly_score_distribution"] = str(dist_path)

    # 3. ROC and Precision-Recall Curves
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    fpr, tpr, _ = roc_curve(y_test, test_scores)
    ax1.plot(fpr, tpr, color="#2980b9", lw=2, label=f"Isolation Forest (AUC = {metrics['roc_auc']:.4f})")
    ax1.plot([0, 1], [0, 1], color="#95a5a6", linestyle="--")
    ax1.set_title("Receiver Operating Characteristic (ROC)", fontsize=11, weight="bold")
    ax1.set_xlabel("False Positive Rate", fontsize=9)
    ax1.set_ylabel("True Positive Rate (Recall)", fontsize=9)
    ax1.legend(loc="lower right")
    ax1.grid(True, linestyle=":", alpha=0.5)

    prec_vals, rec_vals, _ = precision_recall_curve(y_test, test_scores)
    ax2.plot(rec_vals, prec_vals, color="#8e44ad", lw=2, label=f"PR Curve (AUC = {metrics['pr_auc']:.4f})")
    ax2.set_title("Precision-Recall (PR) Curve", fontsize=11, weight="bold")
    ax2.set_xlabel("Recall", fontsize=9)
    ax2.set_ylabel("Precision", fontsize=9)
    ax2.legend(loc="lower left")
    ax2.grid(True, linestyle=":", alpha=0.5)

    plt.tight_layout()
    roc_pr_path = output_dir / "roc_pr_curve.png"
    plt.savefig(roc_pr_path, dpi=200)
    plt.close()
    plot_files["roc_pr_curve"] = str(roc_pr_path)

    # 4. Detection Rate by Category
    plt.figure(figsize=(10, 5))
    plot_cat_df = category_df[category_df["anomaly_type"] != "Normal"].sort_values(by="detection_rate_pct", ascending=True)

    colors = ["#2ecc71" if r >= 95 else "#3498db" if r >= 90 else "#e74c3c" for r in plot_cat_df["detection_rate_pct"]]
    bars = plt.barh(plot_cat_df["anomaly_type"], plot_cat_df["detection_rate_pct"], color=colors, edgecolor="black", linewidth=0.5)
    plt.xlim(0, 110)
    plt.axvline(100, color="gray", linestyle=":", alpha=0.6)
    plt.title("Optimized Detection Rate Across Anomaly Categories (Test Set)", fontsize=12, pad=12, weight="bold")
    plt.xlabel("Detection Rate (%)", fontsize=10)
    plt.ylabel("Anomaly Scenario", fontsize=10)

    for bar, pct in zip(bars, plot_cat_df["detection_rate_pct"]):
        plt.text(pct + 1.5, bar.get_y() + bar.get_height() / 2, f"{pct:.1f}%", va="center", ha="left", fontsize=9, weight="bold")

    plt.grid(axis="x", linestyle=":", alpha=0.5)
    plt.tight_layout()
    cat_path = output_dir / "category_detection_rates.png"
    plt.savefig(cat_path, dpi=200)
    plt.close()
    plot_files["category_detection_rates"] = str(cat_path)

    return plot_files


def save_trained_pipeline(
    model: IsolationForest,
    scaler: StandardScaler,
    threshold: float,
    metrics: dict,
    category_df: pd.DataFrame,
    output_path: Path = config.MODEL_FILE_PATH,
) -> Path:
    """Serialize the trained Isolation Forest pipeline and artifacts."""
    artifact = {
        "model": model,
        "scaler": scaler,
        "threshold": threshold,
        "feature_names": FEATURE_NAMES,
        "raw_feature_cols": RAW_FEATURE_COLS,
        "test_metrics": metrics,
        "category_performance": category_df.to_dict(orient="records"),
        "training_timestamp": datetime.now().isoformat(),
        "model_version": "1.1.0-optimized",
        "algorithm": "IsolationForest (Scikit-Learn)",
        "hyperparameters": {
            "n_estimators": model.n_estimators,
            "max_samples": model.max_samples,
            "contamination": model.contamination,
            "random_state": model.random_state,
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    return output_path


def run_training_pipeline():
    """Execute complete end-to-end training and evaluation pipeline."""
    print("=" * 80)
    print("AI ANOMALY DETECTION: OPTIMIZED TRAINING PIPELINE (STAGE 3.1)")
    print("=" * 80)

    # 1. Dataset Loading & Validation
    print("\n[Step 1/6] Loading and validating dataset...")
    df = load_and_validate_dataset()
    print(f" -> Loaded {len(df):,} records across {df['device_id'].nunique()} devices.")

    # 2. Chronological Splitting
    print("\n[Step 2/6] Splitting data chronologically per device (70% Train, 15% Val, 15% Test)...")
    train_df, val_df, test_df = create_chronological_splits(df)

    train_norm = int(np.sum(train_df["is_anomaly"] == 0))
    train_anom = int(np.sum(train_df["is_anomaly"] == 1))
    val_norm = int(np.sum(val_df["is_anomaly"] == 0))
    val_anom = int(np.sum(val_df["is_anomaly"] == 1))
    test_norm = int(np.sum(test_df["is_anomaly"] == 0))
    test_anom = int(np.sum(test_df["is_anomaly"] == 1))

    print(f" -> Train Set: {len(train_df):,} total (Normal: {train_norm:,}, Abnormal: {train_anom:,})")
    print(f" -> Val Set:   {len(val_df):,} total (Normal: {val_norm:,}, Abnormal: {val_anom:,})")
    print(f" -> Test Set:  {len(test_df):,} total (Normal: {test_norm:,}, Abnormal: {test_anom:,})")

    # 3. Model Training on Normal Telemetry Only
    print("\n[Step 3/6] Fitting Feature Transformer and training Isolation Forest on normal baseline...")
    train_normal_df = train_df[train_df["is_anomaly"] == 0].copy()

    scaler = StandardScaler()
    scaler.fit(train_normal_df[RAW_FEATURE_COLS].values)

    X_train_normal = compute_features(train_normal_df, scaler)

    model = train_isolation_forest(
        X_train_normal,
        n_estimators=config.ML_CONFIG["n_estimators"],
        max_samples=256,
        random_state=config.ML_CONFIG["random_state"],
    )
    print(f" -> Trained {model.n_estimators} Isolation Trees on {len(X_train_normal):,} normal observations.")

    # 4. Threshold Calibration on Validation Data
    print("\n[Step 4/6] Calibrating decision threshold using normal validation observations...")
    threshold, val_metrics = calibrate_decision_threshold(
        model, scaler, val_df, percentile=98.5
    )
    print(f" -> Calibrated Threshold: {threshold:.4f} (98.5th percentile of normal validation scores)")
    print(f" -> Validation F1: {val_metrics['val_f1']:.4f} | Val Recall: {val_metrics['val_recall']:.4f}")

    # 5. Final Evaluation on Untouched Test Set
    print("\n[Step 5/6] Evaluating model on untouched Test Set...")
    test_metrics, test_scores, test_preds, category_df = evaluate_test_set(
        model, scaler, threshold, test_df
    )

    print("\n--- Test Set Evaluation Results (Stage 3.1 Optimized) ---")
    print(f"Accuracy:         {test_metrics['accuracy']:.4f} ({test_metrics['accuracy']*100:.2f}%)")
    print(f"Precision:        {test_metrics['precision']:.4f} ({test_metrics['precision']*100:.2f}%)")
    print(f"Recall:           {test_metrics['recall']:.4f} ({test_metrics['recall']*100:.2f}%)")
    print(f"F1-Score:         {test_metrics['f1_score']:.4f}")
    print(f"ROC-AUC:          {test_metrics['roc_auc']:.4f}")
    print(f"PR-AUC:           {test_metrics['pr_auc']:.4f}")

    print("\n--- Confusion Matrix ---")
    print(f"True Negatives  (Normal detected as Normal):   {test_metrics['true_negatives']}")
    print(f"False Positives (Normal flagged as Anomaly):  {test_metrics['false_positives']}")
    print(f"False Negatives (Anomaly missed as Normal):   {test_metrics['false_negatives']}")
    print(f"True Positives  (Anomaly detected as Anomaly): {test_metrics['true_positives']}")

    print("\n--- Detection Performance by Threat Category ---")
    print(category_df.to_string(index=False))

    # 6. Save Model and Visualizations
    print("\n[Step 6/6] Generating visualizations and saving artifacts...")
    plot_files = generate_visualizations(test_df, test_scores, test_preds, threshold, test_metrics, category_df)
    for name, path in plot_files.items():
        print(f" -> Saved plot [{name}]: {path}")

    model_path = save_trained_pipeline(model, scaler, threshold, test_metrics, category_df)
    print(f" -> Saved trained model pipeline to: {model_path}")
    print("=" * 80)

    return model, scaler, threshold, test_metrics, category_df


if __name__ == "__main__":
    run_training_pipeline()
