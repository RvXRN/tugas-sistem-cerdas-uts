import joblib
import pandas as pd
from typing import List
from pathlib import Path
import os
import logging

logger = logging.getLogger(__name__)

# Model paths
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "classifier.pkl"
ENCODER_PATH = BASE_DIR / "models" / "label_encoder.pkl"
FEATURE_LIST_PATH = BASE_DIR / "models" / "feature_list.pkl"


class MLCybersecurityEngine:
    """
    Drop-in replacement untuk CybersecurityExpertEngine.
    Menggunakan Machine Learning (Random Forest) untuk deteksi serangan.
    """

    def __init__(self):
        self.is_loaded = False
        try:
            if MODEL_PATH.exists() and ENCODER_PATH.exists() and FEATURE_LIST_PATH.exists():
                self.model = joblib.load(MODEL_PATH)
                self.encoder = joblib.load(ENCODER_PATH)
                self.all_symptoms = joblib.load(FEATURE_LIST_PATH)
                self.is_loaded = True
                logger.info("ML Engine successfully loaded.")
            else:
                logger.warning("ML models not found. Please run train_model.py first.")
        except Exception as e:
            logger.error(f"Error loading ML models: {e}")

    def predict(self, symptoms: List[str], target_system: str = None) -> List[dict]:
        """
        Terima list gejala → kembalikan prediksi serangan + confidence.
        """
        if not self.is_loaded:
            return [{
                "attack_type": "Unknown / Insufficient Data",
                "confidence": 0.0,
                "description": "ML Engine tidak memiliki model terlatih. Silakan hubungi Administrator.",
                "mitre_id": None,
                "recommendations": []
            }]

        # One-hot encode symptoms
        feature_vector = {s: 0 for s in self.all_symptoms}
        matched_symptoms = []
        for symptom in symptoms:
            if symptom in feature_vector:
                feature_vector[symptom] = 1
                matched_symptoms.append(symptom)

        X = pd.DataFrame([feature_vector])
        probabilities = self.model.predict_proba(X)[0]
        predicted_class = self.model.predict(X)[0]
        confidence = float(max(probabilities))

        attack_type = self.encoder.inverse_transform([predicted_class])[0]
        
        return [{
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "description": f"Serangan {attack_type} terdeteksi oleh Machine Learning Engine (Random Forest) berdasarkan kemiripan pola data historis.",
            "mitre_id": None,
            "matched_symptoms": matched_symptoms,
            "recommendations": [
                {"priority": 1, "action": f"Periksa logs terkait indikasi {attack_type}", "tool": "SIEM"},
                {"priority": 2, "action": "Segera blokir IP yang mencurigakan di firewall", "tool": "Firewall"}
            ]
        }]
