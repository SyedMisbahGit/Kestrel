import sqlite3
import pandas as pd
import os

def synthesize_training_data(db_path, output_csv="data/training_ledger.csv"):
    if not os.path.exists(db_path): return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Dynamically map the SQLite schema
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if not columns:
            print(f"[!] Brain: Table 'vulnerabilities' is empty or missing in {db_path}")
            return
            
        node_col = 'node' if 'node' in columns else 'url'
        vuln_col = 'vulnerability' if 'vulnerability' in columns else 'type'
        sev_col = 'severity' if 'severity' in columns else 'severity'

        # Feature Extraction SQL using dynamic columns
        query = f"""
        SELECT 
            length({node_col}) as url_length,
            {vuln_col} as vulnerability,
            {sev_col} as severity,
            (SELECT count(*) FROM vulnerabilities v2 WHERE v2.{node_col} = v1.{node_col}) as cluster_density
        FROM vulnerabilities v1
        """
        
        df = pd.read_sql_query(query, conn)
        
        # Simple Labeling Logic
        df['is_false_positive'] = df['vulnerability'].apply(lambda x: 1 if "Entropy" in str(x) and "H=4.5" in str(x) else 0)
        
        # Append to master ledger
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
