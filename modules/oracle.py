import requests

def ask_brain(url_length: int, cluster_density: int, entropy_score: float) -> dict:
    """Queries the remote Hugging Face ML Brain to filter false positives."""
    try:
        API_URL = "https://bytesyed-kestrel-brain.hf.space/predict"
        payload = {
            "url_length": url_length,
            "cluster_density": cluster_density,
            "entropy_score": float(entropy_score)
        }
        
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            # If API rejects payload, fail open (keep the alert)
            return {"is_false_positive": 0, "confidence": 0.0}
            
    except requests.exceptions.RequestException:
        # If Hugging Face is asleep/offline, fail open
        return {"is_false_positive": 0, "confidence": 0.0}
