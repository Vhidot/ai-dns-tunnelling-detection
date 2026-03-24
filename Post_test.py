# post_test.py
# Post-Test: Random Forest Classifier Evaluation (New System)
# Trains Random Forest on CIC-Bell-DNS-EXF-2021 stateless features,
# evaluates on held-out 20% test set, and saves figures.
# Run: python post_test.py
 
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (confusion_matrix, accuracy_score,
                              precision_score, recall_score, f1_score)
import matplotlib.pyplot as plt
import seaborn as sns
import glob, pickle, warnings
warnings.filterwarnings('ignore')
 
# ── 1. LOAD & CLEAN DATA 
print("Loading dataset...")
b_files = glob.glob('./datasets/Benign/stateless_*.csv')
m_files = (glob.glob('./datasets/Attack_Light_Benign/Attacks/stateless_*.csv') +
           glob.glob('./datasets/Attack_heavy_Benign/Attacks/stateless_*.csv'))
 
benign   = pd.concat([pd.read_csv(f) for f in b_files],  ignore_index=True)
benign['label'] = 0
malicious = pd.concat([pd.read_csv(f) for f in m_files], ignore_index=True)
malicious['label'] = 1
 
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
 
df = pd.concat([clean(benign), clean(malicious)], ignore_index=True)
print(f"Dataset: {len(df):,}  "
      f"(Benign: {(df.label==0).sum():,} | Malicious: {(df.label==1).sum():,})")
 
# ── 2. TRAIN / TEST SPLIT (80/20 stratified) 
X, y = df[FEATURES], df['label']
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)
 
print(f"Training: {len(X_train):,}  |  Test: {len(X_test):,}")
 
# ── 3. NORMALISE 
scaler = MinMaxScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)
 
# Persist scaler for the Node.js inference module
import json
scaler_params = {
    f: {'min': float(scaler.data_min_[i]),
        'max': float(scaler.data_max_[i])}
    for i, f in enumerate(FEATURES)
}
with open('./backend/scaler.json', 'w') as fh:
    json.dump(scaler_params, fh, indent=2)
print("scaler.json saved to ./backend/")
 
# ── 4. TRAIN RANDOM FOREST 
print("Training Random Forest (n_estimators=100, random_state=42)...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train_s, y_train)
print("Training complete.")
 
# Save model
with open('./backend/rf_model.pkl', 'wb') as fh:
    pickle.dump(rf, fh)
print("rf_model.pkl saved to ./backend/")
 
# ── 5. EVALUATE 
y_pred = rf.predict(X_test_s)
cm     = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()
 
acc  = accuracy_score(y_test,  y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test,   y_pred)
f1   = f1_score(y_test,       y_pred)
 
print("\n===== POST-TEST RESULTS (Random Forest) =====")
print(f"  TP={TP:,}  FP={FP:,}  TN={TN:,}  FN={FN:,}")
print(f"  Accuracy  : {acc:.4f} ({acc*100:.2f}%)")
print(f"  Precision : {prec:.4f} ({prec*100:.2f}%)")
print(f"  Recall    : {rec:.4f} ({rec*100:.2f}%)")
print(f"  F1-Score  : {f1:.4f} ({f1*100:.2f}%)")
print("==============================================")
 
# Feature importance
feat_imp = pd.Series(rf.feature_importances_,
                     index=FEATURES).sort_values(ascending=False)
print("\nTop feature importances:")
print(feat_imp.round(4).to_string())
 
# ── 6. FIGURES 
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 12})
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.patch.set_facecolor('#FAFAFA')
 
sns.heatmap(np.array([[TN, FP], [FN, TP]]),
            annot=True, fmt=',', cmap='Blues',
            xticklabels=['Pred: Benign', 'Pred: Malicious'],
            yticklabels=['Actual: Benign', 'Actual: Malicious'],
            ax=axes[0], annot_kws={'size': 13, 'weight': 'bold'})
axes[0].set_title('Post-Test Confusion Matrix\n(Random Forest)', fontweight='bold')
 
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
vals    = [acc, prec, rec, f1]
colors  = ['#2196F3', '#4CAF50', '#FF9800', '#9C27B0']
bars = axes[1].bar(metrics, vals, color=colors, width=0.45, edgecolor='white')
axes[1].set_ylim(0, 1.15)
axes[1].axhline(1.0, color='gray', ls='--', lw=0.8, alpha=0.5)
axes[1].set_title('Performance Metrics — Random Forest', fontweight='bold')
for b, v in zip(bars, vals):
    axes[1].text(b.get_x() + b.get_width()/2, v + 0.03,
                 f'{v:.4f}', ha='center', fontsize=11, fontweight='bold')
 
top8 = feat_imp.head(8)
axes[2].barh(top8.index[::-1], top8.values[::-1], color='#5C6BC0')
axes[2].set_title('Top Feature Importances\n(Mean Gini Decrease)', fontweight='bold')
for i, (v, n) in enumerate(zip(top8.values[::-1], top8.index[::-1])):
    axes[2].text(v + 0.002, i, f'{v:.4f}', va='center', fontsize=9)
 
plt.tight_layout()
plt.savefig('./outputs/fig_posttest.png', dpi=180, bbox_inches='tight')
plt.close()
print("Figure saved: ./outputs/fig_posttest.png")
