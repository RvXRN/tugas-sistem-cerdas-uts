import pytest
from app.ml.engine import MLCybersecurityEngine

def test_ml_engine_fallback_when_no_model():
    """
    Jika file classifier.pkl tidak ada, engine harus fail gracefully
    dan mereturn hasil Unknown / Insufficient Data.
    """
    # Create engine (jika file model belum ditraining di environment test, is_loaded akan False)
    engine = MLCybersecurityEngine()
    
    # Lakukan prediksi
    results = engine.predict(symptoms=["port_scanning"])
    
    assert len(results) == 1
    assert "Unknown" in results[0]["attack_type"]
    assert results[0]["confidence"] == 0.0
