import sqlite3
import pandas as pd
import os

def synthesize_training_data(db_path, output_csv="data/training_ledger.csv"):
    if not os.path.exists(db_path): return
    
    conn = sqlite3.connect(db_path)
    
    try:
        # 1. Verify table exists
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
        if not cursor.fetchone():
            print(f"[*] Brain: Table 'vulnerabilities' missing in {db_path} (Empty Scan)")
            return
            
        # 2. Pull raw data without referencing column names
        df_raw = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
        
        if df_raw.empty:
            print(f"[*] Brain: No vulnerabilities found in {db_path}")
            return
            
        # 3. Extract features positionally (Col 0: Node, Col 1: Vuln, Col 2: Severity)
        node_series = df_raw.iloc[:, 0].astype(str)
        vuln_series = df_raw.iloc[:, 1].astype(str)
        sev_series = df_raw.iloc[:, 2].astype(str)
        
        # 4. Build the Mathematical Feature Matrix
        df = pd.DataFrame({
            'url_length': node_series.apply(len),
            'vulnerability': vuln_series,
            'severity': sev_series,
            'cluster_density': node_series.map(node_series.value_counts())
        })
        
        # 5. Labeling Logic for the Random Forest
        df['is_false_positive'] = df['vulnerability'].apply(lambda x: 1 if "Entropy" in x and "H=4.5" in x else 0)
        
        # 6. Append to Cloud Ledger
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        header = not os.path.exists(output_csv)
        df.to_csv(output_csv, mode='a', index=False, header=header)
        print(f"[*] Brain: Digested {len(df)} data points into {output_csv}")
        
    except Exception as e:
        print(f"[!] Brain Error digesting {db_path}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1: synthesize_training_data(sys.argv[1])
