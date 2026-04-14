import sqlite3
import pandas as pd
import os

def synthesize_training_data(db_path, output_csv="data/training_ledger.csv"):
    if not os.path.exists(db_path): return
    
    conn = sqlite3.connect(db_path)
    # Extract features: Entropy, Length, Port Count, Protocol
    query = """
    SELECT 
        length(node) as url_length,
        vulnerability,
        severity,
        (SELECT count(*) FROM vulnerabilities v2 WHERE v2.node = v1.node) as cluster_density
    FROM vulnerabilities v1
    """
    df = pd.read_sql_query(query, conn)
    
    # Simple Labeling Logic (to be refined by your manual /confirm or /ignore)
    df['is_false_positive'] = df['vulnerability'].apply(lambda x: 1 if "Entropy" in x and "H=4.5" in x else 0)
    
    # Append to master ledger
    header = not os.path.exists(output_csv)
    df.to_csv(output_csv, mode='a', index=False, header=header)
    conn.close()
    print(f"[*] Brain: Digested {len(df)} data points into {output_csv}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1: synthesize_training_data(sys.argv[1])
