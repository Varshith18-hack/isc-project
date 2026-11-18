"""
Performance, Latency & Reliability Benchmarking Engine (Stage 8)
================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Measures empirical performance metrics across all 7 core subsystem operations:
1. AI Anomaly Inference Latency (Mean, Median, P95, P99, Min, Max).
2. AES-256-GCM AEAD Encryption & Decryption Latency.
3. Telemetry Processing Pipeline Throughput (Records / Second).
4. Dashboard Data & Visualization Loading Latency.
5. Cryptographic Audit-Chain Forensic Verification Scaling (10, 50, 100, 250, 500 blocks).
6. Concurrent Multi-Device Ingestion Throughput (5 simultaneous IoMT devices).
7. System Process Memory Consumption (Baseline, Peak RSS, Delta).
"""

import sys
import os
import json
import time
import tempfile
import shutil
import gc
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import psutil

import config
from models.anomaly_detection import MedicalDeviceAnomalyDetector
from security.encryption import (
    encrypt_telemetry_record,
    decrypt_telemetry_record,
    derive_device_keys,
    get_or_create_master_key,
)
from dashboard.components import (
    load_telemetry_dataset,
    create_vitals_time_series_chart,
    create_network_activity_chart,
    create_anomaly_score_gauge,
)
from audit.audit_logger import append_audit_event
from audit.integrity_checker import verify_audit_chain


def run_comprehensive_benchmark():
    print("=" * 80)
    print("STAGE 8: EMPIRICAL PERFORMANCE & RELIABILITY BENCHMARK")
    print("Course: Information Security and Cryptography (AI 331) — SVNIT")
    print("=" * 80)

    process = psutil.Process(os.getpid())
    gc.collect()
    mem_baseline_mb = process.memory_info().rss / (1024 * 1024)
    print(f"\n[BASELINE SYSTEM STATE] Initial Process Memory RSS: {mem_baseline_mb:.2f} MB")

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "baseline_memory_mb": round(mem_baseline_mb, 2),
    }

    # =========================================================================
    # 1. AI INFERENCE LATENCY
    # =========================================================================
    print("\n[1/7] Benchmarking AI Anomaly Inference Latency (1,000 iterations)...")
    detector = MedicalDeviceAnomalyDetector()
    sample_reading = {
        "device_id": "DEV-VENT-002",
        "heart_rate": 74.0,
        "systolic_bp": 118.0,
        "diastolic_bp": 76.0,
        "oxygen_saturation": 98.4,
        "body_temperature": 36.85,
        "device_activity_level": 22.0,
    }

    # Warmup
    for _ in range(50):
        detector.predict_reading(sample_reading)

    infer_times = []
    for _ in range(1000):
        t0 = time.perf_counter()
        detector.predict_reading(sample_reading)
        infer_times.append((time.perf_counter() - t0) * 1000)  # ms

    infer_times = np.array(infer_times)
    ai_metrics = {
        "iterations": 1000,
        "mean_ms": round(float(np.mean(infer_times)), 4),
        "median_ms": round(float(np.median(infer_times)), 4),
        "p95_ms": round(float(np.percentile(infer_times, 95)), 4),
        "p99_ms": round(float(np.percentile(infer_times, 99)), 4),
        "min_ms": round(float(np.min(infer_times)), 4),
        "max_ms": round(float(np.max(infer_times)), 4),
        "throughput_inferences_per_sec": round(1000.0 / (np.sum(infer_times) / 1000.0), 1),
    }
    results["ai_inference"] = ai_metrics
    print(f" -> AI Inference Latency: Mean={ai_metrics['mean_ms']} ms | Median={ai_metrics['median_ms']} ms | P95={ai_metrics['p95_ms']} ms")
    print(f" -> Throughput: {ai_metrics['throughput_inferences_per_sec']} inferences/sec")

    # =========================================================================
    # 2. AES-256-GCM AEAD ENCRYPTION & DECRYPTION LATENCY
    # =========================================================================
    print("\n[2/7] Benchmarking AES-256-GCM AEAD Cryptography (1,000 iterations)...")
    master_key = get_or_create_master_key()
    device_key = derive_device_keys(master_key, "DEV-VENT-002")
    aad_header = {"ward": "ICU_Ward_2", "device": "DEV-VENT-002"}

    # Encryption benchmark
    enc_times = []
    envelopes = []
    for _ in range(1000):
        t0 = time.perf_counter()
        env = encrypt_telemetry_record(sample_reading, key=device_key, device_id="DEV-VENT-002", associated_data=aad_header)
        enc_times.append((time.perf_counter() - t0) * 1000)
        envelopes.append(env)

    enc_times = np.array(enc_times)

    # Decryption benchmark
    dec_times = []
    for env in envelopes:
        t0 = time.perf_counter()
        decrypt_telemetry_record(env, key=device_key)
        dec_times.append((time.perf_counter() - t0) * 1000)

    dec_times = np.array(dec_times)

    crypto_metrics = {
        "iterations": 1000,
        "encryption": {
            "mean_ms": round(float(np.mean(enc_times)), 4),
            "median_ms": round(float(np.median(enc_times)), 4),
            "p95_ms": round(float(np.percentile(enc_times, 95)), 4),
            "throughput_enc_per_sec": round(1000.0 / (np.sum(enc_times) / 1000.0), 1),
        },
        "decryption": {
            "mean_ms": round(float(np.mean(dec_times)), 4),
            "median_ms": round(float(np.median(dec_times)), 4),
            "p95_ms": round(float(np.percentile(dec_times, 95)), 4),
            "throughput_dec_per_sec": round(1000.0 / (np.sum(dec_times) / 1000.0), 1),
        },
    }
    results["cryptography"] = crypto_metrics
    print(f" -> Encryption Latency: Mean={crypto_metrics['encryption']['mean_ms']} ms | Throughput={crypto_metrics['encryption']['throughput_enc_per_sec']} enc/sec")
    print(f" -> Decryption Latency: Mean={crypto_metrics['decryption']['mean_ms']} ms | Throughput={crypto_metrics['decryption']['throughput_dec_per_sec']} dec/sec")

    # =========================================================================
    # 3. FULL CLOSED-LOOP TELEMETRY PIPELINE THROUGHPUT
    # =========================================================================
    print("\n[3/7] Benchmarking Full Pipeline Throughput (AI + AEAD + Envelope Ingest)...")
    pipe_times = []
    for _ in range(500):
        t0 = time.perf_counter()
        # Step 1: AI Scoring
        pred = detector.predict_reading(sample_reading)
        # Step 2: AEAD Encryption
        env = encrypt_telemetry_record(sample_reading, key=device_key, device_id="DEV-VENT-002", associated_data=aad_header)
        # Step 3: Decrypt at destination
        dec = decrypt_telemetry_record(env, key=device_key)
        pipe_times.append((time.perf_counter() - t0) * 1000)

    pipe_times = np.array(pipe_times)
    pipeline_metrics = {
        "iterations": 500,
        "mean_ms": round(float(np.mean(pipe_times)), 4),
        "median_ms": round(float(np.median(pipe_times)), 4),
        "p95_ms": round(float(np.percentile(pipe_times, 95)), 4),
        "end_to_end_throughput_records_sec": round(500.0 / (np.sum(pipe_times) / 1000.0), 1),
    }
    results["pipeline_throughput"] = pipeline_metrics
    print(f" -> Full Pipeline Cycle: Mean={pipeline_metrics['mean_ms']} ms | Throughput={pipeline_metrics['end_to_end_throughput_records_sec']} rec/sec")

    # =========================================================================
    # 4. DASHBOARD VISUALIZATION & DATA LOADING TIME
    # =========================================================================
    print("\n[4/7] Benchmarking Dashboard Data & Chart Rendering Latency...")
    t0 = time.perf_counter()
    df = load_telemetry_dataset()
    dataset_load_ms = (time.perf_counter() - t0) * 1000

    dev_df = df[df["device_id"] == "DEV-VENT-002"]

    t0 = time.perf_counter()
    create_vitals_time_series_chart(dev_df, window=100)
    vitals_chart_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    create_network_activity_chart(dev_df, window=100)
    network_chart_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    create_anomaly_score_gauge(0.6888, 0.5809)
    gauge_chart_ms = (time.perf_counter() - t0) * 1000

    dashboard_metrics = {
        "dataset_rows": len(df),
        "dataset_load_ms": round(dataset_load_ms, 2),
        "vitals_time_series_chart_ms": round(vitals_chart_ms, 2),
        "network_activity_chart_ms": round(network_chart_ms, 2),
        "anomaly_gauge_chart_ms": round(gauge_chart_ms, 2),
        "total_page_load_ms": round(dataset_load_ms + vitals_chart_ms + network_chart_ms + gauge_chart_ms, 2),
    }
    results["dashboard"] = dashboard_metrics
    print(f" -> Dataset (10,000 rows) Ingestion: {dashboard_metrics['dataset_load_ms']} ms")
    print(f" -> Vitals Multi-Axis Chart:         {dashboard_metrics['vitals_time_series_chart_ms']} ms")
    print(f" -> Network Traffic Chart:          {dashboard_metrics['network_activity_chart_ms']} ms")
    print(f" -> Total Page 1 Initialization:    {dashboard_metrics['total_page_load_ms']} ms")

    # =========================================================================
    # 5. AUDIT-CHAIN VERIFICATION SCALING
    # =========================================================================
    print("\n[5/7] Benchmarking Audit Chain Forensic Verification Scaling...")
    temp_dir = tempfile.mkdtemp()
    scaling_metrics = {}
    try:
        block_counts = [10, 50, 100, 250, 500]
        for count in block_counts:
            chain_path = Path(temp_dir) / f"scale_{count}_chain.json"
            for i in range(1, count + 1):
                append_audit_event(
                    user_id=f"DEV-VENT-{(i%5)+1:03d}",
                    event_type="TELEMETRY_LOG",
                    event_details={"seq": i, "val": i * 1.5},
                    file_path=chain_path,
                    sync_to_sqlite=False,
                )

            # Benchmark verification
            t0 = time.perf_counter()
            rep = verify_audit_chain(chain_path)
            verif_time_ms = (time.perf_counter() - t0) * 1000

            assert rep["is_valid"], f"Verification failed for {count} blocks"
            scaling_metrics[f"{count}_blocks"] = {
                "blocks": count,
                "verification_time_ms": round(verif_time_ms, 2),
                "time_per_block_us": round((verif_time_ms / count) * 1000, 2),
            }
            print(f" -> {count:3d} Blocks: {verif_time_ms:6.2f} ms total ({scaling_metrics[f'{count}_blocks']['time_per_block_us']:5.1f} us/block)")

        results["audit_verification_scaling"] = scaling_metrics
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # =========================================================================
    # 6. CONCURRENT MULTI-DEVICE INGESTION
    # =========================================================================
    print("\n[6/7] Benchmarking Concurrent Multi-Device Ingestion (5 IoMT Devices)...")
    temp_dir_concurrent = tempfile.mkdtemp()
    concurrent_chain_path = Path(temp_dir_concurrent) / "concurrent_benchmark_chain.json"

    def device_worker(device_id: str, count: int):
        dev_k = derive_device_keys(master_key, device_id)
        for idx in range(count):
            reading = {
                "device_id": device_id,
                "heart_rate": 70.0 + idx,
                "oxygen_saturation": 98.0,
                "systolic_bp": 120.0,
                "diastolic_bp": 80.0,
                "body_temperature": 36.8,
                "device_activity_level": 20.0,
            }
            p = detector.predict_reading(reading)
            env = encrypt_telemetry_record(reading, key=dev_k, device_id=device_id)
            append_audit_event(
                user_id=device_id,
                event_type="CONCURRENT_TELEMETRY",
                event_details={"idx": idx, "score": p["anomaly_score"], "tag": env["auth_tag"][:8]},
                file_path=concurrent_chain_path,
                sync_to_sqlite=False,
            )

    try:
        devices = ["DEV-MON-001", "DEV-VENT-002", "DEV-PUMP-001", "DEV-ECG-001", "DEV-DIAL-001"]
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(device_worker, dev, 20) for dev in devices]
            for f in futures:
                f.result()
        total_concurrent_time_s = time.perf_counter() - t0
        total_records = len(devices) * 20

        concurrent_metrics = {
            "device_count": len(devices),
            "records_per_device": 20,
            "total_records": total_records,
            "total_elapsed_s": round(total_concurrent_time_s, 3),
            "effective_throughput_records_sec": round(total_records / total_concurrent_time_s, 1),
        }
        results["concurrent_ingestion"] = concurrent_metrics
        print(f" -> 5 Devices Ingested {total_records} Encrypted Records in {concurrent_metrics['total_elapsed_s']} s")
        print(f" -> Multi-Device Throughput: {concurrent_metrics['effective_throughput_records_sec']} records/sec")
    finally:
        shutil.rmtree(temp_dir_concurrent, ignore_errors=True)

    # =========================================================================
    # 7. PROCESS MEMORY FOOTPRINT
    # =========================================================================
    print("\n[7/7] Measuring Memory Consumption & Peak RSS...")
    mem_final_mb = process.memory_info().rss / (1024 * 1024)
    mem_delta_mb = mem_final_mb - mem_baseline_mb
    gc.collect()
    mem_after_gc_mb = process.memory_info().rss / (1024 * 1024)

    memory_metrics = {
        "baseline_rss_mb": round(mem_baseline_mb, 2),
        "peak_rss_mb": round(mem_final_mb, 2),
        "memory_delta_mb": round(mem_delta_mb, 2),
        "post_gc_rss_mb": round(mem_after_gc_mb, 2),
    }
    results["memory"] = memory_metrics
    print(f" -> Baseline RSS:   {memory_metrics['baseline_rss_mb']} MB")
    print(f" -> Peak RSS:       {memory_metrics['peak_rss_mb']} MB (Delta: +{memory_metrics['memory_delta_mb']} MB)")
    print(f" -> Post-GC RSS:    {memory_metrics['post_gc_rss_mb']} MB")

    # Save benchmark results
    out_path = PROJECT_ROOT / "benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[BENCHMARK COMPLETE] Empirical results saved to: {out_path.name}")
    print("=" * 80)
    return results


if __name__ == "__main__":
    run_comprehensive_benchmark()

