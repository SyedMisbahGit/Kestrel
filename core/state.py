import sqlite3
import json
import os
import logging
import uuid

log = logging.getLogger("rich")

class DBList:
    def __init__(self, conn, table, run_id):
        self.conn = conn
        self.table = table
        self.run_id = run_id

    def append(self, item):
        val = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
        c = self.conn.cursor()
        try:
            # THE DELTA ENGINE: UPSERT Logic
            query = f"""
                INSERT INTO {self.table} (data, first_run_id, last_run_id) 
                VALUES (?, ?, ?)
                ON CONFLICT(data) DO UPDATE SET 
                last_run_id = ?,
                updated_at = CURRENT_TIMESTAMP
            """
            c.execute(query, (val, self.run_id, self.run_id, self.run_id))
            self.conn.commit()
        except Exception as e:
            log.error(f"DB Append Error in {self.table}: {e}")

    def extend(self, items):
        if not items: return
        try:
            vals = [(json.dumps(i) if isinstance(i, (dict, list)) else str(i), 
                     self.run_id, self.run_id, self.run_id) for i in items]
            c = self.conn.cursor()
            query = f"""
                INSERT INTO {self.table} (data, first_run_id, last_run_id) 
                VALUES (?, ?, ?)
                ON CONFLICT(data) DO UPDATE SET 
                last_run_id = ?,
                updated_at = CURRENT_TIMESTAMP
            """
            c.executemany(query, vals)
            self.conn.commit()
        except Exception as e:
            log.error(f"DB Extend Error in {self.table}: {e}")

    def __iter__(self):
        c = self.conn.cursor()
        # Fetch the data and the temporal metadata
        c.execute(f"SELECT data, first_run_id FROM {self.table}")
        for row in c.fetchall():
            try:
                obj = json.loads(row[0])
                # Inject the diffing state directly into the dictionary
                if isinstance(obj, dict):
                    obj['_is_new'] = (row[1] == self.run_id)
                yield obj
            except json.JSONDecodeError:
                # For basic strings (like subdomains)
                yield row[0]

    def __len__(self):
        c = self.conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM {self.table}")
        return c.fetchone()[0]

    def clear(self):
        c = self.conn.cursor()
        c.execute(f"DELETE FROM {self.table}")
        self.conn.commit()

class TargetSession:
    def __init__(self, domain, mode="standard"):
        self.domain = domain
        self.mode = mode
        self.run_id = str(uuid.uuid4()) # Unique ID for this specific scan execution
        
        os.makedirs("data/sessions", exist_ok=True)
        self.db_path = f"data/sessions/{domain.replace('.', '_')}.db"
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        
        self._init_db()

        self.subdomains = DBList(self.conn, "subdomains", self.run_id)
        self.live_hosts = DBList(self.conn, "live_hosts", self.run_id)
        self.vulnerabilities = DBList(self.conn, "vulnerabilities", self.run_id)
        self.cidrs = DBList(self.conn, "cidrs", self.run_id)
        self.crawled_urls = DBList(self.conn, "crawled_urls", self.run_id)

    def _init_db(self):
        c = self.conn.cursor()
        tables = ["subdomains", "live_hosts", "vulnerabilities", "cidrs", "crawled_urls"]
        for t in tables:
            # New Schema with Temporal Tracking
            c.execute(f"""
                CREATE TABLE IF NOT EXISTS {t} (
                    data TEXT UNIQUE, 
                    first_run_id TEXT, 
                    last_run_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
        self.conn.commit()

    def save(self): pass

    def purge(self):
        self.conn.close()
        if os.path.exists(self.db_path): os.remove(self.db_path)
