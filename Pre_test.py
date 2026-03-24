  Source Code
# pre_test.py
# Pre-Test: Rule-Based Baseline Evaluation (Existing System Simulation)
# Simulates Snort-style threshold IDS on CIC-Bell-DNS-EXF-2021 dataset.
# Run: python pre_test.py
 
import pandas as pd
import numpy as np
from sklearn.metrics import (confusion_matrix, accuracy_score,
                              precision_score, recall_score, f1_score)
import matplotlib.pyplot as plt
import seaborn as sns
import glob, warnings
warnings.filterwarnings('ignore')
 
# ── 1. LOAD DATA ────────────────────────────────────────────────────────
print("Loading stateless benign data...")
b_files = glob.glob('./datasets/Benign/stateless_*.csv')
benign  = pd.concat([pd.read_csv(f) for f in b_files], ignore_index=True)
benign['label'] = 0
 
print("Loading stateless malicious data (light + heavy)...")
m_files = (glob.glob('./datasets/Attack_Light_Benign/Attacks/stateless_*.csv') +
           glob.glob('./datasets/Attack_heavy_Benign/Attacks/stateless_*.csv'))
malicious = pd.concat([pd.read_csv(f) for f in m_files], ignore_index=True)
malicious['label'] = 1
 
print(f"  Benign:    {len(benign):,} records")
print(f"  Malicious: {len(malicious):,} records")
 
# ── 2. FEATURES & BALANCE ───────────────────────────────────────────────
FEATURES = ['FQDN_count', 'subdomain_length', 'upper', 'lower',
            'numeric', 'entropy', 'special', 'labels',
            'labels_max', 'labels_average', 'longest_word', 'len']
FEATURES = [c for c in FEATURES
            if c in benign.columns and c in malicious.columns]
 
def clean(df):
    d = df[FEATURES + ['label']].copy()
    d[FEATURES] = d[FEATURES].apply(pd.to_numeric, errors='coerce')
    d[FEATURES] = d[FEATURES].replace([np.inf, -np.inf], np.nan)
    d.dropna(subset=['entropy', 'subdomain_length'], inplace=True)
    for col in FEATURES:
        d[col] = d[col].fillna(d[col].median())
    return d
 
benign_c   = clean(benign)
malicious_c = clean(malicious)
 
# Balanced sample for fair evaluation
n_pre = min(len(benign_c), len(malicious_c))
pre_df = pd.concat([
    benign_c.sample(n=n_pre, random_state=42),
    malicious_c.sample(n=n_pre, random_state=42)
], ignore_index=True)
y_true = pre_df['label'].values
 
# ── 3. RULE-BASED PREDICTION (Snort-style thresholds) ───────────────────
def rule_predict(row):
    if row['entropy']          > 4.0: return 1
    if row['subdomain_length'] > 100: return 1
    if row['numeric']          > 50:  return 1
    return 0
 
y_pred = pre_df[FEATURES].apply(rule_predict, axis=1).values
 
# ── 4. METRICS ──────────────────────────────────────────────────────────
cm = confusion_matrix(y_true, y_pred)
TN, FP, FN, TP = cm.ravel()
 
acc  = accuracy_score(y_true,  y_pred)
prec = precision_score(y_true, y_pred, zero_division=0)
rec  = recall_score(y_true,   y_pred, zero_division=0)
f1   = f1_score(y_true,       y_pred, zero_division=0)
 
print("\n===== PRE-TEST RESULTS (Rule-Based Existing System) =====")
print(f"  Total  : {len(pre_df):,}")
print(f"  TP={TP:,}  FP={FP:,}  TN={TN:,}  FN={FN:,}")
print(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
print(f"  Precision : {prec:.4f}  ({prec*100:.2f}%)")
print(f"  Recall    : {rec:.4f}  ({rec*100:.2f}%)")
print(f"  F1-Score  : {f1:.4f}  ({f1*100:.2f}%)")
print("=========================================================")
 
# ── 5. VISUALISATION ────────────────────────────────────────────────────
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 12})
fig, axes = plt.subplots(1, 2, figsize=(13, 5))
fig.patch.set_facecolor('#FAFAFA')
 
# Confusion matrix
sns.heatmap(np.array([[TN, FP], [FN, TP]]),
            annot=True, fmt=',', cmap='YlOrRd',
            xticklabels=['Pred: Benign', 'Pred: Malicious'],
            yticklabels=['Actual: Benign', 'Actual: Malicious'],
            ax=axes[0], linewidths=0.5,
            annot_kws={'size': 13, 'weight': 'bold'})
axes[0].set_title('Pre-Test Confusion Matrix\n(Rule-Based System)', fontweight='bold')
 
# Metrics bar
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
vals    = [acc, prec, rec, f1]
colors  = ['#2196F3', '#4CAF50', '#FF9800', '#9C27B0']
bars = axes[1].bar(metrics, vals, color=colors, width=0.45, edgecolor='white')
axes[1].set_ylim(0, 1.15)
axes[1].axhline(1.0, color='gray', ls='--', lw=0.8, alpha=0.5)
axes[1].set_title('Performance Metrics — Rule-Based', fontweight='bold')
for b, v in zip(bars, vals):
    axes[1].text(b.get_x() + b.get_width()/2, v + 0.03,
                 f'{v:.4f}', ha='center', fontsize=11, fontweight='bold')
 
plt.tight_layout()
plt.savefig('./outputs/fig_pretest.png', dpi=180, bbox_inches='tight')
plt.close()
print("Figure saved: ./outputs/fig_pretest.png")
