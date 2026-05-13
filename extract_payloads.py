import sqlite3
import json
import os
import glob

# Find the most recently modified session database
db_files = glob.glob('*.db') + glob.glob('data/sessions/*.db') + glob.glob('sessions/*.db')
if not db_files:
    print("[-] No state databases found.")
    exit()

latest_db = max(db_files, key=os.path.getctime)
print(f"[*] Accessing State Database: {latest_db}")

conn = sqlite3.connect(latest_db)
cursor = conn.cursor()

try:
    cursor.execute("SELECT id, data FROM vulnerabilities")
    rows = cursor.fetchall()
    
    print("\n[+] --- EXTRACTED WEAPONIZED PAYLOADS ---")
    deleted_count = 0
    
    for row_id, data_str in rows:
        vuln = json.loads(data_str)
        name = vuln.get("name", "")
        
        # 1. Extract the SSRF / OAST Callbacks
        if "OAST" in name or "SSRF" in name:
            print(f"\n[CRITICAL SSRF / OAST PINGBACK]")
            print(f"Target URL : {vuln.get('matched-at')}")
            print(f"Raw Payload: {json.dumps(vuln, indent=2)}")
            
        # 2. Purge the Old Ghost Data
        elif "Chronos" in name or ("Entropy" in name and "H=4.5" in name):
            cursor.execute("DELETE FROM vulnerabilities WHERE id = ?", (row_id,))
            deleted_count += 1

    conn.commit()
    print(f"\n[*] Purged {deleted_count} obsolete ghost records from the database.")

except Exception as e:
    print(f"[-] Database Error: {e}")

finally:
    conn.close()
