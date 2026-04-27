#!/usr/bin/env /opt/homebrew/bin/python3.12
"""
Lab 1: Prompt Injection Detection Engine
Phase 2 — Blue Team Operations
==================================

Architecture
------------
  Feature extraction : TF-IDF vectoriser (unigrams + bigrams, max 500 features)
  Classifier         : Logistic Regression (L2 regularisation, balanced class weights)
  Evaluation         : 5-fold stratified cross-validation + 25% held-out test set
  Persistence        : joblib serialisation → models/detector.pkl

Dataset
-------
  60 hand-labelled prompts (30 benign / 30 malicious) drawn from:
    • Benign  — legitimate compiler/security coursework questions
    • Malicious — direct exploit requests, jailbreak attempts, persona bypass,
                  social-engineering framings, and obfuscated attack prompts

  The benign set deliberately includes security-adjacent questions (CWE lookups,
  vulnerability analysis, code audit) to stress-test precision — the classifier
  must discriminate intent, not just topic.

Usage
-----
  Train and evaluate:
      python detector.py

  Classify a single prompt:
      python detector.py --prompt "your prompt here"

  Custom dataset:
      python detector.py --dataset /path/to/dataset.csv

Report documentation
--------------------
  Results are written to results/metrics_report.txt and results/metrics.json.
  The trained model is saved to models/detector.pkl for use in Lab 3.
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install with:  pip install scikit-learn joblib")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE        = Path(__file__).parent
DATASET_CSV = HERE / "dataset.csv"
MODELS_DIR  = HERE / "models"
RESULTS_DIR = HERE / "results"
MODEL_PATH  = MODELS_DIR / "detector.pkl"


# ---------------------------------------------------------------------------
# Detector class — also imported by Lab 3
# ---------------------------------------------------------------------------

class PromptInjectionDetector:
    """
    TF-IDF + Logistic Regression binary classifier.

    Labels each prompt as 'malicious' (injection / jailbreak / exploit request)
    or 'benign' (legitimate programming / security coursework question).

    Design rationale
    ----------------
    TF-IDF captures lexical signals (e.g. "shellcode", "jailbreak", "bypass")
    as well as bigram patterns ("no restrictions", "working exploit") that are
    strong indicators of adversarial intent.  Logistic Regression is chosen for
    its interpretability — feature weights can be inspected to explain decisions
    in the Phase 2 report.  Balanced class weights ensure the model does not
    trivially predict the majority class on a perfectly-balanced dataset.
    """

    LABEL_MALICIOUS = "malicious"
    LABEL_BENIGN    = "benign"

    # Lexical signals used as human-readable explanation hints (not used in
    # classification — the TF-IDF pipeline handles that independently).
    MALICIOUS_SIGNALS = [
        "shellcode", "exploit", "backdoor", "rootkit", "malware", "payload",
        "reverse shell", "privilege escalation", "no restrictions", "jailbreak",
        "ignore your", "forget your training", "bypass your", "unrestricted",
        "working exploit", "you have been jailbroken", "as dan", "as hackergpt",
        "disable your safety", "no content policy", "no ethical constraints",
        "write me code to", "without safeguards", "exfiltrate", "phone home",
    ]

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = Path(model_path)
        self._pipeline  = None

    # ------------------------------------------------------------------
    # Pipeline construction
    # ------------------------------------------------------------------

    def _build_pipeline(self) -> Pipeline:
        """
        TF-IDF vectoriser → Logistic Regression.

        Hyperparameter choices:
          ngram_range=(1,2)     Bigrams capture "no restrictions", "working exploit"
          max_features=500      Limits overfitting on 60-sample dataset
          sublinear_tf=True     Log-normalised TF reduces dominance of repeated terms
          C=1.0                 Default L2 strength; adequate for small dataset
          class_weight=balanced Equalises benign/malicious influence during training
        """
        return Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=500,
                sublinear_tf=True,
                lowercase=True,
                strip_accents="unicode",
            )),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=1000,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42,
            )),
        ])

    # ------------------------------------------------------------------
    # Training and evaluation
    # ------------------------------------------------------------------

    def train(self, dataset_path: Path = DATASET_CSV) -> dict:
        """
        Load labelled CSV, run 5-fold cross-validation, fit final model.

        Returns a metrics dict suitable for report generation.

        Evaluation strategy
        -------------------
        With only 60 samples a single train/test split is high-variance.
        5-fold stratified cross-validation gives a more reliable estimate of
        generalisation performance.  A separate 25% held-out split is used
        solely for the confusion matrix and per-class breakdown.
        """
        prompts, labels = self._load_dataset(dataset_path)
        print(f"[*] Dataset loaded: {len(prompts)} samples "
              f"({labels.count(self.LABEL_BENIGN)} benign / "
              f"{labels.count(self.LABEL_MALICIOUS)} malicious)")

        # --- 5-fold stratified cross-validation ---
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_results = cross_validate(
            self._build_pipeline(), prompts, labels, cv=cv,
            scoring=["accuracy", "precision_macro", "recall_macro", "f1_macro"],
        )

        # --- Held-out test set (25%) for confusion matrix ---
        X_train, X_test, y_train, y_test = train_test_split(
            prompts, labels, test_size=0.25, stratify=labels, random_state=42
        )
        held_out_pipeline = self._build_pipeline()
        held_out_pipeline.fit(X_train, y_train)
        y_pred = held_out_pipeline.predict(X_test)

        metrics = {
            "cv_accuracy_mean":  float(cv_results["test_accuracy"].mean()),
            "cv_accuracy_std":   float(cv_results["test_accuracy"].std()),
            "cv_precision_mean": float(cv_results["test_precision_macro"].mean()),
            "cv_recall_mean":    float(cv_results["test_recall_macro"].mean()),
            "cv_f1_mean":        float(cv_results["test_f1_macro"].mean()),
            "cv_f1_std":         float(cv_results["test_f1_macro"].std()),
            "holdout_report":    classification_report(
                y_test, y_pred,
                labels=[self.LABEL_BENIGN, self.LABEL_MALICIOUS],
            ),
            "confusion_matrix":  confusion_matrix(
                y_test, y_pred,
                labels=[self.LABEL_BENIGN, self.LABEL_MALICIOUS],
            ).tolist(),
            "train_size":    len(X_train),
            "test_size":     len(X_test),
            "dataset_size":  len(prompts),
        }

        # Refit on ALL data so the saved model uses every sample
        self._pipeline = self._build_pipeline()
        self._pipeline.fit(prompts, labels)

        return metrics

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def analyze_prompt(self, prompt: str) -> dict:
        """
        Classify a single prompt.

        Returns
        -------
        {
            "label":      "malicious" | "benign",
            "confidence": float (probability of predicted class),
            "signals":    list of matched high-signal lexical features
        }
        """
        if self._pipeline is None:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        label      = self._pipeline.predict([prompt])[0]
        proba      = self._pipeline.predict_proba([prompt])[0]
        classes    = list(self._pipeline.classes_)
        confidence = float(proba[classes.index(label)])

        lower   = prompt.lower()
        signals = [s for s in self.MALICIOUS_SIGNALS if s in lower]

        return {
            "label":      label,
            "confidence": round(confidence, 4),
            "signals":    signals,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Path = MODEL_PATH):
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, path)
        print(f"[+] Model saved → {path}")

    def load(self, path: Path = MODEL_PATH):
        self._pipeline = joblib.load(path)
        print(f"[+] Model loaded ← {path}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_dataset(path: Path) -> tuple:
        prompts, labels = [], []
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                prompts.append(row["prompt"].strip())
                labels.append(row["label"].strip())
        return prompts, labels


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def save_report(metrics: dict) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cm_labels   = [PromptInjectionDetector.LABEL_BENIGN,
                   PromptInjectionDetector.LABEL_MALICIOUS]
    report_path = RESULTS_DIR / "metrics_report.txt"
    json_path   = RESULTS_DIR / "metrics.json"

    with open(report_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("Lab 1: Prompt Injection Detection Engine — Results\n")
        f.write(f"Generated : {ts}\n")
        f.write("=" * 60 + "\n\n")

        f.write("DATASET\n")
        f.write(f"  Total samples : {metrics['dataset_size']}\n")
        f.write(f"  Train split   : {metrics['train_size']}\n")
        f.write(f"  Test split    : {metrics['test_size']}\n\n")

        f.write("MODEL ARCHITECTURE\n")
        f.write("  Feature extraction : TF-IDF (unigrams + bigrams, max_features=500,\n")
        f.write("                       sublinear_tf=True, lowercase=True)\n")
        f.write("  Classifier         : Logistic Regression (L2, C=1.0,\n")
        f.write("                       class_weight=balanced, solver=lbfgs)\n\n")

        f.write("CROSS-VALIDATION RESULTS (5-fold stratified)\n")
        f.write(f"  Accuracy  : {metrics['cv_accuracy_mean']:.4f} ± {metrics['cv_accuracy_std']:.4f}\n")
        f.write(f"  Precision : {metrics['cv_precision_mean']:.4f} (macro avg)\n")
        f.write(f"  Recall    : {metrics['cv_recall_mean']:.4f} (macro avg)\n")
        f.write(f"  F1-score  : {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f} (macro avg)\n\n")

        f.write("HELD-OUT TEST SET (25% split, stratified)\n")
        f.write(metrics["holdout_report"] + "\n")

        f.write("CONFUSION MATRIX\n")
        f.write(f"  Rows = actual class | Cols = predicted class\n")
        f.write(f"  Labels: {cm_labels}\n")
        cm = metrics["confusion_matrix"]
        for i, row in enumerate(cm):
            f.write(f"  {cm_labels[i]:10s} | {row}\n")

    # JSON copy for Lab 3 programmatic use
    with open(json_path, "w") as f:
        serialisable = {k: v for k, v in metrics.items() if k != "holdout_report"}
        json.dump(serialisable, f, indent=2)

    print(f"\n[+] Report saved → {report_path}")
    print(f"[+] Metrics JSON → {json_path}")
    return report_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Lab 1: Prompt Injection Detection Engine"
    )
    parser.add_argument("--prompt",  type=str,  help="Classify a single prompt and exit")
    parser.add_argument("--dataset", type=Path, default=DATASET_CSV,
                        help="Path to labelled dataset CSV (default: dataset.csv)")
    args = parser.parse_args()

    detector = PromptInjectionDetector()

    # ---- Single-prompt inference mode ----
    if args.prompt:
        if not MODEL_PATH.exists():
            print("[!] No trained model found. Run without --prompt first to train.")
            sys.exit(1)
        detector.load()
        result = detector.analyze_prompt(args.prompt)
        print(f"\nPrompt    : {args.prompt[:100]}")
        print(f"Label     : {result['label'].upper()}")
        print(f"Confidence: {result['confidence']:.2%}")
        if result["signals"]:
            print(f"Signals   : {', '.join(result['signals'])}")
        return

    # ---- Train + evaluate mode ----
    print("\n" + "=" * 60)
    print("  Lab 1: Prompt Injection Detection Engine")
    print("  Phase 2 — Blue Team Operations")
    print("=" * 60)

    print(f"\n[*] Dataset: {args.dataset}")
    metrics = detector.train(args.dataset)
    detector.save()

    print(f"\n{'─' * 40}")
    print("CROSS-VALIDATION (5-fold stratified):")
    print(f"  Accuracy  : {metrics['cv_accuracy_mean']:.4f} ± {metrics['cv_accuracy_std']:.4f}")
    print(f"  Precision : {metrics['cv_precision_mean']:.4f} (macro)")
    print(f"  Recall    : {metrics['cv_recall_mean']:.4f} (macro)")
    print(f"  F1-score  : {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f} (macro)")
    print(f"\nHELD-OUT TEST SET (25%):")
    print(metrics["holdout_report"])
    print("CONFUSION MATRIX  [benign | malicious]:")
    for row in metrics["confusion_matrix"]:
        print(f"  {row}")

    save_report(metrics)


if __name__ == "__main__":
    main()
