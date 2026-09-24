# Ransomware Family Classifier

A machine learning system that classifies Windows ransomware executables into their respective families using static analysis of Portable Executable (PE) features. Developed as a graduate capstone project under the Master of Applied Cybersecurity (MACSEC) program at the University of New Brunswick.

**Author:** Moyosoreoluwa Toluhi
**Course:** CS6497 Capstone Project, University of New Brunswick
**Supervisor:** Dr. Saqib Hakak
**Project title:** *Comparative Analysis of Modern Ransomware Families*

---

## Overview

Ransomware remains one of the most damaging categories of malware, and correctly attributing a sample to its family is an important early step in incident response and threat intelligence. This project investigates whether five modern ransomware families can be distinguished from one another using only **static** features — that is, without ever executing the sample.

A dataset of 189 real ransomware samples was collected, 22 static PE features were extracted from each, and two classifiers (Random Forest and XGBoost) were trained and combined into a soft-voting ensemble. The trained models are served through a Flask web application that accepts either an uploaded executable or manually entered feature values and returns a predicted family with per-family confidence scores.

## Ransomware families studied

| Family | Samples |
|---|---|
| BlackCat (ALPHV) | 52 |
| Akira | 49 |
| LockBit 3.0 | 43 |
| DragonForce | 27 |
| Maze | 18 |
| **Total** | **189** |

All samples were sourced from [MalwareBazaar](https://bazaar.abuse.ch/) and handled exclusively within an isolated Kali Linux virtual machine.

## Methodology

**Data collection.** Samples were downloaded from MalwareBazaar and stored inside an isolated Kali Linux guest running in Oracle VirtualBox. No sample was ever executed; all analysis is static.

**Feature extraction.** `extract_features.py` uses the `pefile` library to extract 22 static features from each executable, including PE header fields, section entropy statistics, import/export counts, and binary flags for security- and ransomware-relevant DLLs (e.g. `advapi32.dll`, `cryptsp.dll`, `vssapi.dll`). Section and whole-file Shannon entropy are computed to capture packing and encryption characteristics.

**Modelling.** Two classifiers — a Random Forest and an XGBoost model — are trained on an 80/20 stratified split of the dataset. At prediction time their probability outputs are averaged (soft voting) and the family with the highest mean probability is returned.

## Results

| Metric | Score |
|---|---|
| Test accuracy | 89.47% |
| Weighted F1 | 0.8913 |

Five-fold stratified cross-validation confirmed stable performance in the low-to-mid 90% range for both models, with no indication of overfitting. A split-sensitivity analysis across 80/20, 70/30, 60/40, and 50/50 partitions produced consistent results, supporting the robustness of the approach. The primary limitation is the smaller number of DragonForce and Maze samples available, which reduces per-class recall for those two families.

## Web application

The Flask application (`app.py`) provides two modes of operation:

- **File upload** — a `.exe` or `.dll` is uploaded, its static features are extracted, and a prediction is returned. The uploaded file is never executed and is deleted immediately after analysis.
- **Manual entry** — the 22 feature values are entered directly, which is useful for testing and demonstration.

Predictions are displayed as a top family plus a confidence breakdown across all five families.

## Demo

<!-- Add the demo video here on GitHub (see README notes) -->
*A short demo of the web application is available in the repository.*

## Repository structure

```
.
├── app.py                  # Flask web application
├── extract_features.py     # Static PE feature extraction
├── train_model.py          # Dataset assembly, training, evaluation
├── combined_dataset.csv    # Full 189-sample feature dataset
├── akira.csv               # Per-family feature CSVs
├── blackcat.csv
├── dragonforce.csv
├── lockbit.csv
├── maze.csv
├── rf_model.pkl            # Trained Random Forest model
├── xgb_model.pkl           # Trained XGBoost model
├── label_encoder.pkl       # Family label encoder
├── templates/
│   └── index.html          # Web interface
└── uploads/                # Runtime temp folder (files deleted after analysis)
```

## Installation and usage

Requires Python 3.9+.

```bash
# Install dependencies
pip install flask joblib pefile pandas scikit-learn xgboost

# (Optional) retrain the models from the dataset
python train_model.py

# Run the web application
python app.py
```

Then open `http://127.0.0.1:5000` in a browser.

## Security note

This project is for research and educational purposes. The classifier performs **static analysis only** — uploaded files are parsed for their PE structure and are never executed. Raw ransomware samples are deliberately **not** included in this repository; only the numeric feature values extracted from them are provided. Anyone reproducing this work should collect and handle live samples solely within an isolated, non-networked virtual machine.

## Limitations and future work

- Class imbalance for DragonForce and Maze limits per-class recall.
- Static features alone cannot capture runtime behaviour; combining static and dynamic analysis is a natural extension.
- The manual-entry confidence breakdown could, in principle, expose the model to membership-inference probing, noted here as a direction for future hardening.

## Acknowledgements

Developed under the supervision of Dr. Saqib Hakak as part of the MACSEC capstone requirement at the University of New Brunswick. AI assistance (Claude, Anthropic) was used for language refinement and code structuring; all research decisions, sample handling, and analysis were carried out by the author.