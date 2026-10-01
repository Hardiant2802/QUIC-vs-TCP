#!/usr/bin/env python3
"""Analyze week8-run output without re-running network experiments."""
import csv
import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def save_csv(path, rows):
    if rows:
        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def metrics(values):
    return dict(min_ms=min(values) if values else None,
                p50_ms=float(np.percentile(values, 50)) if values else None,
                p95_ms=float(np.percentile(values, 95)) if values else None)


def analyze(out):
    objects, runs, packet_checks = [], [], []
    for file in sorted(out.glob("*/loss-*/h*/run-*/run.json")):
        info = json.loads(file.read_text())
        directory = file.parent
        rows, errors = [], []
        for line in (directory / "curl.jsonl").read_text().splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    errors.append("malformed_json")
        expected = info["expected_objects"]
        urls = [row.get("url_effective", "") for row in rows]
        expected_urls = {f"https://localhost:4433/objects/object-{i:02d}.bin" for i in range(1, expected + 1)}
        if len(set(urls)) != len(urls) or not set(urls).issubset(expected_urls) or len(rows) > expected:
            errors.append("unexpected_or_duplicate_objects")
        connects = sum(int(row.get("num_connects", 0)) for row in rows)
        if connects > 1:
            errors.append("multiple_connections")
        version = "2" if info["protocol"] == "h2" else "3"
        if any(row.get("http_code") == 200 and str(row.get("http_version")) != version for row in rows):
            errors.append("wrong_protocol")
        if len(rows) == expected and all(row.get("exitcode") == 0 for row in rows) and connects != 1:
            errors.append("missing_connection")
        by_url = {row.get("url_effective"): row for row in rows}
        successes = []
        for url in sorted(expected_urls):
            row = by_url.get(url, {})
            success = (not errors and row.get("exitcode", -1) == 0 and row.get("http_code", 0) == 200
                       and int(row.get("size_download", 0)) == info["expected_bytes"]
                       and str(row.get("http_version")) == version)
            elapsed = float(row.get("time_total", 0)) * 1000 if row else None
            objects.append(dict(mode=info["mode"], loss_pct=info["loss_pct"], protocol=info["protocol"],
                                run=directory.name, url=url, success=bool(success), completion_ms=elapsed,
                                curl_exitcode=row.get("exitcode"), invalid_reason=";".join(errors)))
            if success:
                successes.append(elapsed)
        passed = len(successes) == expected and info["exit_code"] == 0 and not errors
        runs.append(dict(mode=info["mode"], loss_pct=info["loss_pct"], protocol=info["protocol"], run=directory.name,
                         valid_completed=passed, expected_objects=expected, successful_objects=len(successes),
                         failed_objects=expected - len(successes), exit_code=info["exit_code"], connections=connects,
                         elapsed_ms=info["elapsed_ms"],
                         goodput_mbit_s=(expected * info["expected_bytes"] * 8 / (info["elapsed_ms"] * 1000)) if passed else None,
                         invalid_reason=";".join(errors)))
        pcap = directory / "capture.pcap"
        if pcap.exists():
            with (directory / "packets.tsv").open() as f:
                packets = list(csv.DictReader(f, delimiter="\t"))
            field = "http2.streamid" if version == "2" else "quic.stream.stream_id"
            streamids = sorted({v for row in packets for v in row[field].split(",") if v})
            # QUIC unidirectional control streams are not request streams.
            request_streams = [v for v in streamids if int(v, 0) > 0] if version == "2" else [v for v in streamids if int(v, 0) % 4 == 0]
            keys = directory / "tls.keys"
            packet_checks.append(dict(path=str(directory.relative_to(out)), protocol=info["protocol"],
                                      packet_count=len(packets), has_tls_keys=keys.exists() and keys.stat().st_size > 0,
                                      decoded_request_streams=len(request_streams), request_stream_ids=",".join(request_streams),
                                      completed_run=passed, decode_ok=not passed or len(request_streams) == expected))

    save_csv(out / "objects.csv", objects)
    save_csv(out / "runs.csv", runs)
    save_csv(out / "packet-checks.csv", packet_checks)
    summary = []
    groups = sorted({(r["mode"], r["loss_pct"], r["protocol"]) for r in runs})
    for mode, loss, proto in groups:
        selected = [r for r in runs if (r["mode"], r["loss_pct"], r["protocol"]) == (mode, loss, proto)]
        values = [r["completion_ms"] for r in objects if (r["mode"], r["loss_pct"], r["protocol"]) == (mode, loss, proto) and r["success"]]
        expected = sum(r["expected_objects"] for r in selected)
        complete = [r["elapsed_ms"] for r in selected if r["valid_completed"]]
        summary.append(dict(mode=mode, loss_pct=loss, protocol=proto, runs=len(selected),
                            completed_runs=len(complete), expected_objects=expected, successful_objects=len(values),
                            failed_objects=expected - len(values), failure_pct=100 * (expected - len(values)) / expected,
                            **{f"object_{k}": v for k, v in metrics(values).items()},
                            **{f"run_{k}": v for k, v in metrics(complete).items()}))
    save_csv(out / "summary.csv", summary)
    validation = dict(total_runs=len(runs), completed_runs=sum(r["valid_completed"] for r in runs),
                      failed_runs=sum(not r["valid_completed"] for r in runs),
                      invalid_runs=sum(bool(r["invalid_reason"]) for r in runs),
                      pcap_decode_failures=sum(not r["decode_ok"] for r in packet_checks),
                      note="Percentiles/ECDF chỉ gồm đối tượng thành công; thời gian toàn lượt chỉ gồm lượt hoàn tất. Xem cả tỉ lệ thất bại.")
    (out / "validation.json").write_text(json.dumps(validation, indent=2, ensure_ascii=False) + "\n")
    styles = [("h2", "HTTP/2 (TLS 1.2)", "#c94138", "o"), ("h3", "HTTP/3 (QUIC)", "#286fb4", "s")]
    for mode in sorted({r["mode"] for r in summary}):
        selected = [r for r in summary if r["mode"] == mode]
        fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
        for proto, label, color, marker in styles:
            rows = [r for r in selected if r["protocol"] == proto]
            for ax, key, title in zip(axes, ("object_p50_ms", "object_p95_ms", "failure_pct"),
                                     ("Median object completion (successful only)", "p95 object completion (successful only)", "Failed objects")):
                ax.plot([r["loss_pct"] for r in rows], [r[key] if r[key] is not None else np.nan for r in rows],
                        color=color, marker=marker, label=label, linestyle="-" if proto == "h2" else "--",
                        markersize=9 if proto == "h2" else 4, markerfacecolor="none" if proto == "h2" else color)
                ax.set_title(title, fontsize=10)
                ax.set_xlabel("Configured loss per direction (%)")
                ax.set_ylabel("%" if key == "failure_pct" else "ms")
                ax.grid(alpha=.25)
        for ax in axes:
            ax.legend(fontsize=8)
        max_failure = max(r["failure_pct"] for r in selected)
        if max_failure == 0:
            axes[2].set_ylim(-.01, .1)
            axes[2].set_yticks([0, .05, .1])
        else:
            axes[2].set_ylim(0, min(105, max_failure * 1.1))
        fig.suptitle(mode)
        fig.tight_layout()
        fig.savefig(out / mode / "latency-and-failures.png", dpi=160)
        plt.close(fig)
        for loss in sorted({r["loss_pct"] for r in selected}):
            fig, ax = plt.subplots(figsize=(7, 4.5))
            for proto, label, color, _ in styles:
                vals = sorted(r["completion_ms"] for r in objects if r["mode"] == mode and r["loss_pct"] == loss and r["protocol"] == proto and r["success"])
                if vals:
                    ax.step(vals, np.arange(1, len(vals) + 1) / len(vals), where="post", color=color, label=label)
            ax.set(xlabel="Object completion time (ms)", ylabel="ECDF (successful objects only)",
                   title=f"{mode}; loss={loss:g}% per direction")
            ax.grid(alpha=.25)
            if ax.lines:
                ax.legend()
            else:
                ax.text(.5, .5, "No successful transfers", transform=ax.transAxes, ha="center")
            fig.tight_layout()
            fig.savefig(out / mode / f"ecdf-loss-{loss:g}.png", dpi=160)
            plt.close(fig)
    print(f'Tổng hợp: {validation["completed_runs"]}/{len(runs)} lượt hoàn tất; '
          f'{validation["invalid_runs"]} lượt sai điều kiện; '
          f'{validation["pcap_decode_failures"]} pcap chưa giải mã đủ.')
    return validation


if __name__ == "__main__":
    analyze(Path(sys.argv[1]).resolve())
