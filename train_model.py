"""
train_model.py — Ransomware Family Classifier

Trains two models (Random Forest and XGBoost) on static PE features extracted
from ransomware samples and saves them for use by the Flask app (app.py).

Pipeline:
  1. Load the five per-family feature CSVs (produced by extract_features.py)
  2. Combine them into combined_dataset.csv
  3. Encode the family labels
  4. Train Random Forest and XGBoost on an 80/20 stratified split
  5. Report test accuracy, weighted F1, per-class metrics, and 5-fold CV
  6. Save rf_model.pkl, xgb_model.pkl, and label_encoder.pkl

Usage:
    python train_model.py
"""

import glob
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from xgboost import XGBClassifier

RANDOM_STATE = 42

# The 22 static PE features used for classification.
# This list MUST match FEATURE_COLUMNS in app.py.
FEATURE_COLUMNS = [
    'machine_type', 'num_sections', 'timestamp', 'characteristics',
    'imagebase', 'entrypoint', 'dll_characteristics', 'file_size',
    'mean_section_entropy', 'max_section_entropy', 'min_section_entropy',
    'mean_section_size', 'num_imported_dlls', 'num_imports',
    'imports_cryptsp', 'imports_advapi32', 'imports_kernel32',
    'imports_wininet', 'imports_ws2_32', 'imports_vssapi',
    'num_exports', 'file_entropy'
]

# Per-family CSV files (output of extract_features.py). Adjust names if needed.
FAMILY_FILES = {
    'akira':       'akira.csv',
    'blackcat':    'blackcat.csv',
    'dragonforce': 'dragonforce.csv',
    'lockbit':     'lockbit.csv',
    'maze':        'maze.csv',
}


def load_and_combine():
    """Load the five per-family CSVs, drop unparseable rows, save combined file."""
    frames = []
    for family, path in FAMILY_FILES.items():
        matches = glob.glob(path) or glob.glob(f'*{family}.csv')
        if not matches:
            raise FileNotFoundError(f"Could not find a CSV for family '{family}'")
        frames.append(pd.read_csv(matches[0]))

    df = pd.concat(frames, ignore_index=True)

    # Drop any samples that failed to parse during feature extraction
    if 'parse_error' in df.columns:
        df = df[df['parse_error'] == 0].reset_index(drop=True)

    df.to_csv('combined_dataset.csv', index=False)
    print(f"[+] Combined dataset saved: combined_dataset.csv ({len(df)} samples)")
    print(df['family'].value_counts().to_string())
    print()
    return df


def main():
    df = load_and_combine()

    X = df[FEATURE_COLUMNS]
    le = LabelEncoder()
    y = le.fit_transform(df['family'])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )

    # ── Random Forest ─────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)

    # ── XGBoost ───────────────────────────────────────────────
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric='mlogloss',
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)

    # ── Evaluation ────────────────────────────────────────────
    for name, pred in [('Random Forest', rf_pred), ('XGBoost', xgb_pred)]:
        acc = accuracy_score(y_test, pred)
        f1 = f1_score(y_test, pred, average='weighted')
        print(f"── {name} ──")
        print(f"Test accuracy:  {acc:.4f}")
        print(f"Weighted F1:    {f1:.4f}")
        print(classification_report(y_test, pred, target_names=le.classes_, zero_division=0))

    # ── 5-fold cross-validation (full dataset) ────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    for name, model in [('Random Forest', rf), ('XGBoost', xgb)]:
        scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        print(f"[CV] {name}: {scores.mean():.4f} (+/- {scores.std():.4f})")
    print()

    # ── Save artifacts ────────────────────────────────────────
    joblib.dump(rf, 'rf_model.pkl')
    joblib.dump(xgb, 'xgb_model.pkl')
    joblib.dump(le, 'label_encoder.pkl')
    print("[+] Saved: rf_model.pkl, xgb_model.pkl, label_encoder.pkl")


if __name__ == '__main__':
    main()
