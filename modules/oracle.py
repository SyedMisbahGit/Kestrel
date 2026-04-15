import requests

def ask_brain(url_length: int, cluster_density: int) -> dict:
    """Queries the Hugging Face ML Brain to filter false positives."""
    try:
        # Replace with your actual Hugging Face Space URL
        API_URL = "https://bytesyed-kestrel-brain.hf.space/predict"
        payload = {"url_length": url_length, "cluster_density": cluster_density}
        
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()
            
    except requests.exceptions.RequestException:
        pass # If the Brain is offline, we fail open (don't drop alerts)
        
    return {"is_false_positive": 0, "confidence_percentage": 0.0, "recommendation": "ALERT"}
