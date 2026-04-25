import requests

def ask_brain(url_length: int, cluster_density: int, entropy_score: float, context_key: str = "unknown") -> dict:
    """Queries the remote Hugging Face ML Brain with AST Context for ultra-precision filtering."""
    try:
        API_URL = "https://bytesyed-kestrel-brain.hf.space/predict"
        payload = {
            "url_length": url_length,
            "cluster_density": cluster_density,
            "entropy_score": float(entropy_score),
            "context_key": str(context_key).lower()[:50] # Send the variable name (e.g., 'aws_secret', 'chunk_hash')
        }
        
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return {"is_false_positive": 0, "confidence": 0.0, "reason": "api_rejection"}
            
    except requests.exceptions.RequestException:
        return {"is_false_positive": 0, "confidence": 0.0, "reason": "api_timeout"}
