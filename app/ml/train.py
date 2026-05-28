import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, MultiLabelBinarizer
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path

# Setup paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "app" / "ml" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH        = MODEL_DIR / "classifier.pkl"
ENCODER_PATH      = MODEL_DIR / "label_encoder.pkl"
FEATURE_LIST_PATH = MODEL_DIR / "feature_list.pkl"


def train_and_save_model():
    print("Loading mapped attack dataset (8 categories aligned with CF rules)...")

    # Dataset khusus yang di-mapping ke 8 jenis serangan sesuai CF rules
    df = pd.read_csv(BASE_DIR / "dataset" / "5_mapped_attacks.csv")

    print(f"Total data: {len(df)} rows")
    print(f"Label distribution:")
    for label, count in df['label'].value_counts().items():
        print(f"  {label}: {count}")

    # One-hot encoding fitur (gejala serangan)
    print("\nExtracting and encoding features (symptoms)...")
    tags_list = [[t.strip() for t in str(s).split(",")] for s in df["features"]]

    mlb = MultiLabelBinarizer()
    X = mlb.fit_transform(tags_list)
    all_symptoms = list(mlb.classes_)
    print(f"Total unique symptoms: {len(all_symptoms)}")

    # Encode label ke angka
    print("Encoding labels...")
    le = LabelEncoder()
    y = le.fit_transform(df["label"].str.strip())

    print(f"Total unique labels: {len(le.classes_)}")
    print(f"Labels: {list(le.classes_)}")

    # Split 80/20 dengan stratify (aman karena 8 kelas seimbang)
    print("\nSplitting dataset (80/20 stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {X_train.shape[0]} | Test: {X_test.shape[0]}")

    # Random Forest dioptimalkan
    print("\nTraining RandomForestClassifier (optimized)...")
    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Test Accuracy
    y_pred = model.predict(X_test)
    test_accuracy = accuracy_score(y_test, y_pred)
    print(f"\nTest Accuracy       : {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")

    # 5-Fold Stratified Cross-Validation
    print("Running 5-Fold Stratified Cross-Validation...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=skf, scoring="accuracy", n_jobs=-1)
    print(f"CV Fold Scores      : {[round(s, 4) for s in cv_scores]}")
    print(f"CV Mean (Validation): {cv_scores.mean():.4f} ({cv_scores.mean()*100:.2f}%)")
    print(f"CV Std              : +/- {cv_scores.std():.4f}")

    print("\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        zero_division=0
    ))

    # Simpan model
    print(f"Saving models to {MODEL_DIR}...")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    joblib.dump(all_symptoms, FEATURE_LIST_PATH)
    print("[OK] All models saved successfully.")
    print(f"  - {MODEL_PATH}")
    print(f"  - {ENCODER_PATH}")
    print(f"  - {FEATURE_LIST_PATH}")


if __name__ == "__main__":
    train_and_save_model()
