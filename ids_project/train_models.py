"""
train_models.py
Trains Isolation Forest + Random Forest using:
  1. Your honeypot logs (ids_ml_features.csv)
  2. CIC-IDS2017 datasets (placed in ~/ids_project/datasets/)

Run: python train_models.py
"""

import os
import json
import glob
import joblib
import warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")                        # headless backend (no display needed)
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
import seaborn as sns

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, label_binarize
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    f1_score, precision_score, recall_score,
)

# ─── PATHS ────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.expanduser("~/ids_project")
CSV_PATH     = os.path.join(BASE_DIR, "ids_ml_features.csv")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
MODELS_DIR   = os.path.join(BASE_DIR, "models")
FIGURES_DIR  = os.path.join(BASE_DIR, "figures")        # ← all plots saved here
os.makedirs(MODELS_DIR,  exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR,  exist_ok=True)

IF_PATH      = os.path.join(MODELS_DIR, "isolation_forest.pkl")
RF_PATH      = os.path.join(MODELS_DIR, "random_forest.pkl")
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.pkl")
META_PATH    = os.path.join(MODELS_DIR, "meta.json")

# ─── IEEE PLOT STYLE ──────────────────────────────────────────────────────────

# Times New Roman + tight layout matches IEEE double-column format
IEEE_STYLE = {
    "font.family":        "serif",
    "font.serif":         ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":     10,
    "axes.labelsize":     9,
    "xtick.labelsize":    8,
    "ytick.labelsize":    8,
    "legend.fontsize":    8,
    "figure.dpi":         300,
    "savefig.dpi":        300,
    "savefig.bbox":       "tight",
    "axes.linewidth":     0.8,
    "grid.linewidth":     0.5,
    "lines.linewidth":    1.2,
    "axes.grid":          True,
    "grid.alpha":         0.3,
    "axes.spines.top":    False,
    "axes.spines.right":  False,
}

# Colour palette: IEEE-friendly, prints well in B&W
C_RF  = "#1f77b4"   # blue  – Random Forest
C_IF  = "#d62728"   # red   – Isolation Forest
C_ACC = "#2ca02c"   # green – accuracy highlight
C_NEG = "#aec7e8"   # light blue – benign bars

# ─── FEATURES ─────────────────────────────────────────────────────────────────

FEATURES = [
    "session_count",
    "login_success_rate",
    "login_failure_count",
    "total_login_attempts",
    "command_count",
    "unique_command_count",
    "avg_session_duration",
    "max_session_duration",
    "default_cred_attempts",
    "cowrie_download_attempts",
    "dionaea_connections",
    "dionaea_download_attempts",
    "dionaea_protocol_count",
    "dionaea_error_count",
    "suricata_alert_count",
    "suricata_priority1_count",
    "suricata_proto_count",
    "suricata_unique_sigs",
    "total_threat_score",
]

# ─── CIC-IDS2017 ATTACK LABELS ────────────────────────────────────────────────

ATTACK_LABELS = {
    "DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris",
    "DoS Slowhttptest", "PortScan", "FTP-Patator", "SSH-Patator",
    "Bot", "Web Attack – Brute Force", "Web Attack – XSS",
    "Web Attack – Sql Injection", "Infiltration", "Heartbleed",
}

# ─── STEP 1: LOAD HONEYPOT DATA ───────────────────────────────────────────────

def load_honeypot():
    if not os.path.exists(CSV_PATH):
        print(f"[!] Honeypot CSV not found: {CSV_PATH}")
        print("[!] Run unified_parser.py first.")
        return None

    df = pd.read_csv(CSV_PATH)
    df[FEATURES] = df[FEATURES].fillna(0)
    df["label"] = "malicious"
    df["label_enc"] = 1
    df["source_dataset"] = "honeypot"
    print(f"[+] Honeypot samples     : {len(df)}")
    return df[FEATURES + ["label", "label_enc", "source_dataset"]]


# ─── STEP 2: LOAD CIC-IDS2017 DATASETS ───────────────────────────────────────

def map_cic_to_features(df_cic, filename):
    df_cic.columns = df_cic.columns.str.strip()
    df_cic["Label"] = df_cic["Label"].str.strip()
    df_cic["label_enc"] = df_cic["Label"].apply(
        lambda x: 0 if x.upper() == "BENIGN" else 1
    )
    df_cic["label"] = df_cic["label_enc"].apply(
        lambda x: "benign" if x == 0 else "malicious"
    )

    mapped = pd.DataFrame()
    mapped["session_count"] = 1.0

    total_pkts = df_cic.get("Total Fwd Packets", pd.Series(1)).clip(lower=1)
    rst_flags  = df_cic.get("RST Flag Count", pd.Series(0)).fillna(0)
    mapped["login_success_rate"] = (1 - (rst_flags / total_pkts)).clip(0, 1)
    mapped["login_failure_count"] = rst_flags.fillna(0)

    syn_flags = df_cic.get("SYN Flag Count", pd.Series(0)).fillna(0)
    mapped["total_login_attempts"] = syn_flags

    mapped["command_count"] = df_cic.get("Total Fwd Packets", pd.Series(0)).fillna(0)
    mapped["unique_command_count"] = df_cic.get(
        "Fwd Packet Length Max", pd.Series(0)
    ).fillna(0).clip(0, 100)
    mapped["avg_session_duration"] = (
        df_cic.get("Flow Duration", pd.Series(0)).fillna(0) / 1e6
    ).clip(0, 3600)
    mapped["max_session_duration"] = mapped["avg_session_duration"]

    is_brute = df_cic["Label"].str.contains(
        "Patator|Brute", case=False, na=False
    ).astype(int)
    mapped["default_cred_attempts"] = is_brute * syn_flags

    is_download = df_cic["Label"].str.contains(
        "Bot|Infiltration", case=False, na=False
    ).astype(int)
    mapped["cowrie_download_attempts"] = is_download.astype(float)

    mapped["dionaea_connections"] = df_cic.get(
        "Total Backward Packets", pd.Series(0)
    ).fillna(0)
    mapped["dionaea_download_attempts"] = mapped["cowrie_download_attempts"]
    mapped["dionaea_protocol_count"] = df_cic.get(
        "Protocol", pd.Series(0)
    ).fillna(0).clip(0, 5)
    mapped["dionaea_error_count"] = df_cic.get(
        "URG Flag Count", pd.Series(0)
    ).fillna(0)

    psh_flags = df_cic.get("PSH Flag Count", pd.Series(0)).fillna(0)
    mapped["suricata_alert_count"] = psh_flags

    is_ddos = df_cic["Label"].str.contains(
        "DDoS|DoS|Heartbleed", case=False, na=False
    ).astype(int)
    mapped["suricata_priority1_count"] = is_ddos.astype(float)
    mapped["suricata_proto_count"] = df_cic.get(
        "Protocol", pd.Series(1)
    ).fillna(1).clip(1, 3)
    mapped["suricata_unique_sigs"] = df_cic.get(
        "Fwd Packet Length Std", pd.Series(0)
    ).fillna(0).clip(0, 50)

    mapped["total_threat_score"] = (
        mapped["login_failure_count"]      * 0.3 +
        mapped["default_cred_attempts"]    * 2.0 +
        mapped["cowrie_download_attempts"] * 3.0 +
        mapped["command_count"].clip(0,100)* 0.1 +
        mapped["dionaea_connections"].clip(0,50) * 0.2 +
        mapped["suricata_alert_count"].clip(0,50)* 0.5 +
        mapped["suricata_priority1_count"] * 3.0
    ).round(2)

    mapped["label"]          = df_cic["label"]
    mapped["label_enc"]      = df_cic["label_enc"]
    mapped["source_dataset"] = os.path.basename(filename)

    return mapped[FEATURES + ["label", "label_enc", "source_dataset"]]


def load_cic_datasets():
    patterns = [
        os.path.join(DATASETS_DIR, "*.csv"),
        os.path.join(BASE_DIR, "*ISCX*.csv"),
        os.path.join(BASE_DIR, "*pcap*.csv"),
    ]
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    files = list(set(files))

    if not files:
        print(f"[!] No CIC datasets found in {DATASETS_DIR}")
        print(f"[!] Place CSV files in: {DATASETS_DIR}")
        return None

    dfs = []
    for f in files:
        print(f"[*] Loading: {os.path.basename(f)}")
        try:
            df_raw = pd.read_csv(f, encoding="latin1", low_memory=False)
            df_raw.columns = df_raw.columns.str.strip()

            if "Label" not in df_raw.columns:
                print(f"    [!] No Label column, skipping")
                continue

            df_raw = df_raw.replace([np.inf, -np.inf], np.nan)
            df_raw = df_raw.dropna(subset=["Label"])

            benign  = df_raw[df_raw["Label"].str.upper() == "BENIGN"]
            attack  = df_raw[df_raw["Label"].str.upper() != "BENIGN"]

            n_sample = min(2500, len(benign), len(attack)) if len(attack) > 0 else min(2500, len(benign))
            sampled  = pd.concat([
                benign.sample(n=n_sample, random_state=42) if len(benign) >= n_sample else benign,
                attack.sample(n=n_sample, random_state=42) if len(attack) >= n_sample else attack,
            ])

            labels = sampled["Label"].value_counts()
            print(f"    Rows sampled : {len(sampled)}")
            print(f"    Labels       : {dict(labels)}")

            mapped = map_cic_to_features(sampled, f)
            mapped = mapped.replace([np.inf, -np.inf], np.nan).fillna(0)
            dfs.append(mapped)
            print(f"    [+] Mapped successfully")

        except Exception as e:
            print(f"    [!] Error loading {f}: {e}")
            continue

    if not dfs:
        return None

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[+] Total CIC samples    : {len(combined)}")
    print(f"[+] Benign               : {(combined['label_enc']==0).sum()}")
    print(f"[+] Malicious            : {(combined['label_enc']==1).sum()}")
    return combined


# ─── STEP 3: GENERATE SYNTHETIC BENIGN ───────────────────────────────────────

def generate_benign(n):
    np.random.seed(42)
    return pd.DataFrame({
        "session_count":             np.random.randint(1, 4, n).astype(float),
        "login_success_rate":        np.random.uniform(0.8, 1.0, n),
        "login_failure_count":       np.random.randint(0, 2, n).astype(float),
        "total_login_attempts":      np.random.randint(1, 3, n).astype(float),
        "command_count":             np.random.randint(0, 5, n).astype(float),
        "unique_command_count":      np.random.randint(0, 5, n).astype(float),
        "avg_session_duration":      np.random.uniform(30, 300, n),
        "max_session_duration":      np.random.uniform(60, 600, n),
        "default_cred_attempts":     np.zeros(n),
        "cowrie_download_attempts":  np.zeros(n),
        "dionaea_connections":       np.random.randint(0, 2, n).astype(float),
        "dionaea_download_attempts": np.zeros(n),
        "dionaea_protocol_count":    np.random.randint(0, 2, n).astype(float),
        "dionaea_error_count":       np.zeros(n),
        "suricata_alert_count":      np.random.randint(0, 2, n).astype(float),
        "suricata_priority1_count":  np.zeros(n),
        "suricata_proto_count":      np.random.randint(1, 3, n).astype(float),
        "suricata_unique_sigs":      np.random.randint(0, 2, n).astype(float),
        "total_threat_score":        np.random.uniform(0, 1.0, n),
        "label":                     "benign",
        "label_enc":                 0,
        "source_dataset":            "synthetic",
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  VISUALISATION MODULE  (IEEE-quality, 300 DPI)
# ═══════════════════════════════════════════════════════════════════════════════

def _save(fig, name):
    path = os.path.join(FIGURES_DIR, name)
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"[✓] Figure saved → {path}")


# ── Fig 1: Confusion Matrices (both models, side-by-side) ────────────────────
def plot_confusion_matrices(y_test, if_preds, rf_preds):
    with plt.rc_context(IEEE_STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.8))
        labels = ["Benign", "Malicious"]

        configs = [
            (if_preds, "Isolation Forest", C_IF),
            (rf_preds, "Random Forest",    C_RF),
        ]
        for ax, (preds, title, color) in zip(axes, configs):
            cm = confusion_matrix(y_test, preds)
            # Normalised (%) for annotation
            cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100

            cmap = sns.light_palette(color, as_cmap=True)
            sns.heatmap(
                cm_norm, annot=False, fmt=".1f", cmap=cmap,
                linewidths=0.5, linecolor="white",
                xticklabels=labels, yticklabels=labels,
                ax=ax, cbar=True, vmin=0, vmax=100,
            )
            # Annotate with count + percentage
            for i in range(2):
                for j in range(2):
                    ax.text(j + 0.5, i + 0.5,
                            f"{cm[i,j]}\n({cm_norm[i,j]:.1f}%)",
                            ha="center", va="center",
                            fontsize=7.5,
                            color="white" if cm_norm[i,j] > 55 else "black",
                            fontweight="bold")
            ax.set_title(title, fontweight="bold", pad=6)
            ax.set_ylabel("True Label")
            ax.set_xlabel("Predicted Label")
            ax.tick_params(length=0)

        fig.suptitle("Fig. 1. Confusion Matrices — IDS/IPS Classification",
                     fontsize=9, fontweight="bold", y=1.02)
        plt.tight_layout()
        _save(fig, "fig1_confusion_matrices.png")


# ── Fig 2: Per-Class Metric Bar Chart (Precision / Recall / F1) ──────────────
def plot_metric_comparison(y_test, if_preds, rf_preds):
    with plt.rc_context(IEEE_STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.8), sharey=True)

        classes = ["Benign", "Malicious"]
        metrics = ["Precision", "Recall", "F1-Score"]
        x = np.arange(len(metrics))
        width = 0.35

        configs = [
            (if_preds, "Isolation Forest", C_IF),
            (rf_preds, "Random Forest",    C_RF),
        ]
        for ax, (preds, title, color) in zip(axes, configs):
            report = classification_report(
                y_test, preds,
                target_names=classes,
                output_dict=True,
                zero_division=0,
            )
            for idx, cls in enumerate(classes):
                vals = [
                    report[cls]["precision"],
                    report[cls]["recall"],
                    report[cls]["f1-score"],
                ]
                offset = width * (idx - 0.5)
                bars = ax.bar(x + offset, vals, width,
                              label=cls,
                              color=color if idx == 1 else C_NEG,
                              edgecolor="white", linewidth=0.6,
                              zorder=3)
                for bar, v in zip(bars, vals):
                    ax.text(bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + 0.01,
                            f"{v:.2f}", ha="center", va="bottom",
                            fontsize=6.5, fontweight="bold")

            ax.set_title(title, fontweight="bold")
            ax.set_xticks(x)
            ax.set_xticklabels(metrics)
            ax.set_ylim(0, 1.12)
            ax.set_ylabel("Score")
            ax.legend(loc="lower right", framealpha=0.8)
            ax.yaxis.grid(True, zorder=0)
            ax.set_axisbelow(True)

        fig.suptitle("Fig. 2. Per-Class Precision, Recall, and F1-Score",
                     fontsize=9, fontweight="bold", y=1.02)
        plt.tight_layout()
        _save(fig, "fig2_precision_recall_f1.png")


# ── Fig 3: ROC Curves (both models on same axes) ──────────────────────────────
def plot_roc_curves(y_test, if_scores, rf_scores):
    with plt.rc_context(IEEE_STYLE):
        fig, ax = plt.subplots(figsize=(3.5, 3.2))

        configs = [
            (if_scores, "Isolation Forest", C_IF,  "--"),
            (rf_scores, "Random Forest",    C_RF,  "-"),
        ]
        for scores, label, color, ls in configs:
            fpr, tpr, _ = roc_curve(y_test, scores)
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, ls, color=color, lw=1.5,
                    label=f"{label} (AUC = {roc_auc:.3f})")

        ax.plot([0, 1], [0, 1], "k:", lw=0.8, label="Random (AUC = 0.500)")
        ax.fill_between([0, 1], [0, 1], alpha=0.04, color="gray")
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title("Fig. 3. ROC Curves", fontweight="bold")
        ax.legend(loc="lower right", framealpha=0.9)
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        plt.tight_layout()
        _save(fig, "fig3_roc_curves.png")


# ── Fig 4: Precision-Recall Curves ───────────────────────────────────────────
def plot_pr_curves(y_test, if_scores, rf_scores):
    with plt.rc_context(IEEE_STYLE):
        fig, ax = plt.subplots(figsize=(3.5, 3.2))

        configs = [
            (if_scores, "Isolation Forest", C_IF, "--"),
            (rf_scores, "Random Forest",    C_RF, "-"),
        ]
        for scores, label, color, ls in configs:
            prec, rec, _ = precision_recall_curve(y_test, scores)
            ap = average_precision_score(y_test, scores)
            ax.plot(rec, prec, ls, color=color, lw=1.5,
                    label=f"{label} (AP = {ap:.3f})")

        baseline = y_test.mean()
        ax.axhline(y=baseline, color="k", linestyle=":", lw=0.8,
                   label=f"Baseline (AP = {baseline:.3f})")
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.set_title("Fig. 4. Precision-Recall Curves", fontweight="bold")
        ax.legend(loc="upper right", framealpha=0.9)
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        plt.tight_layout()
        _save(fig, "fig4_pr_curves.png")


# ── Fig 5: Cross-Validation Scores (RF) ──────────────────────────────────────
def plot_cv_scores(cv_scores):
    with plt.rc_context(IEEE_STYLE):
        fig, ax = plt.subplots(figsize=(3.5, 2.8))
        folds = np.arange(1, len(cv_scores) + 1)
        bars = ax.bar(folds, cv_scores, color=C_RF, edgecolor="white",
                      linewidth=0.6, zorder=3, width=0.55)

        mean_val = cv_scores.mean()
        ax.axhline(y=mean_val, color=C_IF, linestyle="--", lw=1.2,
                   label=f"Mean = {mean_val:.4f}")
        ax.fill_between(
            [0.5, len(cv_scores) + 0.5],
            mean_val - cv_scores.std(),
            mean_val + cv_scores.std(),
            alpha=0.15, color=C_IF, label=f"±1 SD = {cv_scores.std():.4f}",
        )

        for bar, v in zip(bars, cv_scores):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.003,
                    f"{v:.4f}", ha="center", va="bottom",
                    fontsize=7, fontweight="bold")

        ax.set_xlabel("Fold")
        ax.set_ylabel("Accuracy")
        ax.set_title("Fig. 5. 5-Fold Cross-Validation — Random Forest",
                     fontweight="bold")
        ax.set_xticks(folds)
        ax.set_xticklabels([f"Fold {i}" for i in folds])
        lower = max(0, mean_val - 0.1)
        ax.set_ylim([lower, 1.02])
        ax.legend(framealpha=0.9)
        ax.yaxis.grid(True, zorder=0)
        ax.set_axisbelow(True)
        plt.tight_layout()
        _save(fig, "fig5_cross_validation.png")


# ── Fig 6: Top-15 Feature Importances (RF) ───────────────────────────────────
def plot_feature_importance(rf_model):
    with plt.rc_context(IEEE_STYLE):
        imp = pd.Series(rf_model.feature_importances_, index=FEATURES)
        imp = imp.sort_values(ascending=True).tail(15)

        fig, ax = plt.subplots(figsize=(6.5, 3.6))
        colors = [C_RF if v >= imp.median() else C_NEG for v in imp.values]
        bars = ax.barh(imp.index, imp.values, color=colors,
                       edgecolor="white", linewidth=0.5, height=0.7)

        for bar, v in zip(bars, imp.values):
            ax.text(v + 0.001, bar.get_y() + bar.get_height() / 2,
                    f"{v:.4f}", va="center", fontsize=7)

        ax.set_xlabel("Gini Importance")
        ax.set_title("Fig. 6. Top-15 Feature Importances — Random Forest",
                     fontweight="bold")
        ax.xaxis.grid(True, zorder=0)
        ax.set_axisbelow(True)
        # Format y-tick labels
        ax.set_yticklabels(
            [lbl.replace("_", " ").title() for lbl in imp.index],
            fontsize=7.5
        )
        plt.tight_layout()
        _save(fig, "fig6_feature_importance.png")


# ── Fig 7: Accuracy Comparison Summary ───────────────────────────────────────
def plot_accuracy_summary(if_acc, rf_acc, cv_mean, cv_std):
    with plt.rc_context(IEEE_STYLE):
        fig, ax = plt.subplots(figsize=(4.5, 3.0))

        models = ["Isolation\nForest", "Random\nForest\n(Test)", "Random\nForest\n(CV Mean)"]
        accs   = [if_acc, rf_acc, cv_mean]
        errs   = [0,       0,      cv_std]
        colors = [C_IF,   C_RF,   C_RF]
        hatches = ["//",  "",     ".."]

        bars = ax.bar(models, accs, color=colors, hatch=hatches,
                      edgecolor="white", linewidth=0.7,
                      yerr=errs, capsize=4, error_kw={"linewidth": 1},
                      zorder=3, width=0.5)

        for bar, v, e in zip(bars, accs, errs):
            label = f"{v*100:.2f}%"
            if e > 0:
                label += f"\n±{e*100:.2f}%"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + (e or 0) + 0.005,
                    label,
                    ha="center", va="bottom",
                    fontsize=8, fontweight="bold")

        ax.set_ylim([max(0, min(accs) - 0.15), 1.06])
        ax.set_ylabel("Accuracy")
        ax.set_title("Fig. 7. Model Accuracy Summary", fontweight="bold")
        ax.yaxis.grid(True, zorder=0)
        ax.set_axisbelow(True)
        ax.yaxis.set_major_formatter(
            matplotlib.ticker.FuncFormatter(lambda x, _: f"{x:.0%}")
        )
        plt.tight_layout()
        _save(fig, "fig7_accuracy_summary.png")


# ── Fig 8: Dataset Composition Pie ────────────────────────────────────────────
def plot_dataset_composition(df):
    with plt.rc_context(IEEE_STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(6.5, 3.0))

        # Left: benign vs malicious
        counts_class = [
            (df["label_enc"] == 0).sum(),
            (df["label_enc"] == 1).sum(),
        ]
        wedge_props = {"linewidth": 0.8, "edgecolor": "white"}
        axes[0].pie(
            counts_class,
            labels=["Benign", "Malicious"],
            autopct="%1.1f%%",
            colors=[C_NEG, C_IF],
            wedgeprops=wedge_props,
            startangle=90,
            textprops={"fontsize": 8},
        )
        axes[0].set_title("(a) Class Distribution", fontweight="bold")

        # Right: data sources
        src_counts = df["source_dataset"].value_counts()
        palette = plt.cm.tab10(np.linspace(0, 0.8, len(src_counts)))
        axes[1].pie(
            src_counts.values,
            labels=src_counts.index,
            autopct="%1.1f%%",
            colors=palette,
            wedgeprops=wedge_props,
            startangle=90,
            textprops={"fontsize": 7},
        )
        axes[1].set_title("(b) Dataset Sources", fontweight="bold")

        fig.suptitle("Fig. 8. Training Dataset Composition",
                     fontsize=9, fontweight="bold", y=1.02)
        plt.tight_layout()
        _save(fig, "fig8_dataset_composition.png")


# ── Generate all figures ──────────────────────────────────────────────────────
def generate_all_figures(
    df, y_test, if_preds, rf_preds,
    if_scores, rf_scores,
    cv_scores, rf_model,
    if_acc, rf_acc,
):
    print("\n" + "="*60)
    print("  Generating IEEE-quality figures → " + FIGURES_DIR)
    print("="*60)

    plot_confusion_matrices(y_test, if_preds, rf_preds)
    plot_metric_comparison(y_test, if_preds, rf_preds)
    plot_roc_curves(y_test, if_scores, rf_scores)
    plot_pr_curves(y_test, if_scores, rf_scores)
    plot_cv_scores(cv_scores)
    plot_feature_importance(rf_model)
    plot_accuracy_summary(if_acc, rf_acc, cv_scores.mean(), cv_scores.std())
    plot_dataset_composition(df)

    print(f"\n[✓] All 8 figures saved to: {FIGURES_DIR}")
    print("[✓] Ready for inclusion in IEEE paper (300 DPI, Times New Roman)")


# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 4: TRAIN
# ═══════════════════════════════════════════════════════════════════════════════

def train():
    print("=" * 60)
    print("  IDS/IPS ML Training Pipeline")
    print("  Honeypot Logs + CIC-IDS2017 Datasets")
    print("=" * 60)

    all_dfs = []

    print("\n[*] Loading honeypot data...")
    df_honeypot = load_honeypot()
    if df_honeypot is not None:
        all_dfs.append(df_honeypot)

    print("\n[*] Loading CIC-IDS2017 datasets...")
    df_cic = load_cic_datasets()
    if df_cic is not None:
        all_dfs.append(df_cic)

    if not all_dfs:
        print("[!] No data found. Cannot train.")
        exit(1)

    df = pd.concat(all_dfs, ignore_index=True)
    df[FEATURES] = df[FEATURES].fillna(0).replace([np.inf, -np.inf], 0)

    n_benign = (df["label_enc"] == 0).sum()
    if n_benign < 100:
        print(f"\n[!] Only {n_benign} benign samples — adding synthetic benign data")
        df_syn = generate_benign(max(500, (df["label_enc"]==1).sum()))
        df = pd.concat([df, df_syn], ignore_index=True)

    print(f"\n{'='*60}")
    print(f"  DATASET SUMMARY")
    print(f"{'='*60}")
    print(f"  Total samples    : {len(df)}")
    print(f"  Malicious        : {(df['label_enc']==1).sum()}")
    print(f"  Benign           : {(df['label_enc']==0).sum()}")
    print(f"  Sources          : {df['source_dataset'].nunique()}")
    for src, count in df['source_dataset'].value_counts().items():
        print(f"    {src:<45}: {count}")

    X = df[FEATURES].values
    y = df["label_enc"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[+] Train : {len(X_train)}  Test : {len(X_test)}")

    scaler    = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    n_mal         = (y == 1).sum()
    contamination = round(min(max(n_mal / len(y), 0.05), 0.5), 2)

    # ── Isolation Forest ──────────────────────────────────────────
    print(f"\n[*] Training Isolation Forest (contamination={contamination})...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train_s)
    if_preds  = np.where(iso.predict(X_test_s) == -1, 1, 0)
    # Anomaly scores: negate so higher = more anomalous (= malicious)
    if_scores = -iso.score_samples(X_test_s)
    if_acc    = accuracy_score(y_test, if_preds)
    print(f"[+] Isolation Forest Accuracy : {if_acc:.4f} ({if_acc*100:.2f}%)")
    print(classification_report(y_test, if_preds,
          target_names=["Benign","Malicious"], zero_division=0))

    # ── Random Forest ─────────────────────────────────────────────
    print("[*] Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train_s, y_train)
    rf_preds  = rf.predict(X_test_s)
    rf_scores = rf.predict_proba(X_test_s)[:, 1]   # P(malicious)
    rf_acc    = accuracy_score(y_test, rf_preds)
    cv        = cross_val_score(rf, X_train_s, y_train, cv=5, n_jobs=-1)
    print(f"[+] Random Forest Accuracy    : {rf_acc:.4f} ({rf_acc*100:.2f}%)")
    print(f"[+] Cross-val Mean            : {cv.mean():.4f} (+/- {cv.std():.4f})")
    print(classification_report(y_test, rf_preds,
          target_names=["Benign","Malicious"], zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_preds))

    imp = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
    print("\n[+] Top 10 Feature Importances:")
    for feat, val in imp.head(10).items():
        bar = "█" * int(val * 40)
        print(f"    {feat:<35} {val:.4f} {bar}")

    # ── Save models ───────────────────────────────────────────────
    print("\n[*] Saving models...")
    joblib.dump(iso,    IF_PATH)
    joblib.dump(rf,     RF_PATH)
    joblib.dump(scaler, SCALER_PATH)

    meta = {
        "features":        FEATURES,
        "contamination":   contamination,
        "if_accuracy":     round(float(if_acc), 4),
        "rf_accuracy":     round(float(rf_acc), 4),
        "cv_mean":         round(float(cv.mean()), 4),
        "total_samples":   int(len(df)),
        "malicious":       int((y==1).sum()),
        "benign":          int((y==0).sum()),
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[✓] isolation_forest.pkl → {IF_PATH}")
    print(f"[✓] random_forest.pkl    → {RF_PATH}")
    print(f"[✓] scaler.pkl           → {SCALER_PATH}")
    print(f"[✓] meta.json            → {META_PATH}")

    # ── Generate all IEEE figures ─────────────────────────────────
    generate_all_figures(
        df        = df,
        y_test    = y_test,
        if_preds  = if_preds,
        rf_preds  = rf_preds,
        if_scores = if_scores,
        rf_scores = rf_scores,
        cv_scores = cv,
        rf_model  = rf,
        if_acc    = if_acc,
        rf_acc    = rf_acc,
    )

    print(f"\n[✓] Training complete!")
    print(f"[✓] Run: sudo python main.py")


if __name__ == "__main__":
    train()
