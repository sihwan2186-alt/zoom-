# pyright: reportMissingTypeStubs=false
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
FIGURES = REPORTS / "figures"
SUMMARY = REPORTS / "comparison" / "stride_zap_summary.json"


def load_summary() -> dict[str, Any]:
    return json.loads(SUMMARY.read_text(encoding="utf-8"))


def save_bar_chart(path: Path, labels: list[str], values: list[int], title: str, ylabel: str) -> None:
    colors = ["#2f6f9f", "#d97706", "#4b8f5a", "#7c3aed", "#64748b"]
    fig, ax = plt.subplots(figsize=(7.0, 4.0), dpi=180)
    bars = ax.bar(labels, values, color=colors[: len(labels)], width=0.56)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, max(values) + 2)
    ax.grid(axis="y", color="#dbe3eb", linewidth=0.8)
    ax.set_axisbelow(True)
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.15,
            str(value),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def save_horizontal_chart(path: Path, labels: list[str], values: list[int], title: str) -> None:
    colors = ["#4b8f5a", "#2f6f9f", "#d97706", "#7c3aed", "#64748b"]
    fig, ax = plt.subplots(figsize=(7.0, 4.2), dpi=180)
    bars = ax.barh(labels, values, color=colors[: len(labels)], height=0.55)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("OWASP category count")
    ax.set_xlim(0, max(values) + 1)
    ax.grid(axis="x", color="#dbe3eb", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.invert_yaxis()
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_width() + 0.08,
            bar.get_y() + bar.get_height() / 2,
            str(value),
            ha="left",
            va="center",
            fontsize=10,
            fontweight="bold",
        )
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def build() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    summary = load_summary()

    save_bar_chart(
        FIGURES / "owasp_top10_coverage.png",
        ["STRIDE", "ZAP", "Combined"],
        [
            int(summary["stride_owasp_coverage"]),
            int(summary["zap_owasp_coverage"]),
            int(summary["combined_owasp_coverage"]),
        ],
        "OWASP Top 10 Detection Coverage",
        "Detected categories out of 10",
    )

    save_horizontal_chart(
        FIGURES / "detection_scope_distribution.png",
        ["Both", "STRIDE only", "ZAP only", "Unmapped info", "None"],
        [
            len(summary["overlap_categories"]),
            len(summary["stride_only_categories"]),
            len(summary["zap_only_categories"]),
            int(summary["unmapped_zap_alerts"]),
            2,
        ],
        "Detection Scope Distribution",
    )

    save_bar_chart(
        FIGURES / "zap_alert_reduction.png",
        ["Alerts before", "Alerts after", "Instances before", "Instances after"],
        [13, int(summary["zap_total"]), 19, int(summary["zap_instance_total"])],
        "ZAP Findings Before and After Security Headers",
        "Count",
    )


if __name__ == "__main__":
    build()
