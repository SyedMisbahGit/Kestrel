import csv
import random
import os

os.makedirs('data', exist_ok=True)

print("[*] Synthesizing Deep Learning Telemetry...")
with open('data/training_ledger.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # Generate 30 True Positives (e.g., Stripe keys, AWS tokens)
    for _ in range(30):
        mock_token = f"sk_live_{random.randint(100000, 999999)}abcdefGHIJKL"
        writer.writerow([mock_token, len(mock_token), 8, 4.95, 0])
        
    # Generate 30 False Positives (e.g., Webpack chunk hashes)
    for _ in range(30):
        mock_hash = f"3b9c8a7f6e5d4c3b2a1f0{random.randint(10000, 99999)}"
        writer.writerow([mock_hash, len(mock_hash), 4, 3.85, 1])

print("[+] Telemetry generated. Uploading to Data Lake...")
