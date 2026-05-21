import sqlite3
import json
import os
import logging
import uuid
import hashlib

log = logging.getLogger("rich")

class DBList:
    def __init__(self, conn, table, run_id):
        self.conn = conn
        self.table = table
        self.run_id = run_id

    def _generate_id(self, item):
        """Generates a deterministic hash based on the URL or raw string to prevent JSON ordering collisions."""
        if isinstance(item, dict):
            core_id = item.get('url', item.get('matched-at', str(item)))
        else:
            core_id = str(item)
        return hashlib.md5(core_id.encode()).hexdigest()

    def append(self, item):
        item_id = self._generate_id(item)
        val = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
        c = self.conn.cursor()
        try:
            # Upsert now relies on the deterministic MD5 hash, not the raw JSON string
            query = f"""
                INSERT INTO {self.table} (id, data, first_run_id, last_run_id) 
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET 
                data = excluded.data,
                last_run_id = ?,
                updated_at = CURRENT_TIMESTAMP
            """
            c.execute(query, (item_id, val, self.run_id, self.run_id, self.run_id))
            self.conn.commit()
        except Exception as e:
            log.error(f"DB Append Error in {self.table}: {e}")

    def extend(self, items):
        if not items: return
        try:
            vals = [(self._generate_id(i), json.dumps(i, sort_keys=True) if isinstance(i, (dict, list)) else str(i), 
                     self.run_id, self.run_id, self.run_id) for i in items]
            c = self.conn.cursor()
            query = f"""
                INSERT INTO {self.table} (id, data, first_run_id, last_run_id) 
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET 
                data = excluded.data,
                last_run_id = ?,
                updated_at = CURRENT_TIMESTAMP
            """
            c.executemany(query, vals)
            self.conn.commit()
        except Exception as e:
            log.error(f"DB Extend Error in {self.table}: {e}")

    def __iter__(self):
        """Iterate over stored items, yielding parsed Python objects."""
        c = self.conn.cursor()
        try:
            for row in c.execute(f"SELECT data FROM {self.table}"):
                try:
                    yield json.loads(row[0])
                except (json.JSONDecodeError, TypeError):
                    yield row[0]
        except Exception:
            return

    def __len__(self):
        c = self.conn.cursor()
        try:
            return c.execute(f"SELECT COUNT(*) FROM {self.table}").fetchone()[0]
        except Exception:
            return 0

    def __bool__(self):
        return self.__len__() > 0

    def __iter__(self):
        c = self.conn.cursor()
        c.execute(f"SELECT data, first_run_id FROM {self.table}")
        for row in c.fetchall():
            try:
                obj = json.loads(row[0])
                if isinstance(obj, dict):
                    obj['_is_new'] = (row[1] == self.run_id)
                yield obj
            except json.JSONDecodeError:
                yield row[0]

    def __len__(self):
        c = self.conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM {self.table}")
        return c.fetchone()[0]

class TargetSession:
    def __init__(self, domain, mode="standard"):
        self.domain = domain
        self.mode = mode
        self.run_id = str(uuid.uuid4())
        
        os.makedirs("data/sessions", exist_ok=True)
        self.db_path = f"data/sessions/{domain.replace('.', '_')}.db"
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        
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
            c.execute(f"""
                CREATE TABLE IF NOT EXISTS {t} (
                    id TEXT PRIMARY KEY, 
                    data TEXT, 
                    first_run_id TEXT, 
                    last_run_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
        self.conn.commit()

    # --- OMNI-ADAPTER LAYER ---
    def add_subdomain(self, sub=None, **kwargs):
        if sub:
            if isinstance(sub, (list, set)): self.subdomains.extend(list(sub))
            else: self.subdomains.append(sub)

    def get_subdomains(self): return list(self.subdomains)

    def add_live_host(self, host=None, **kwargs):
        if host is None and kwargs: host = kwargs
        if host:
            if isinstance(host, (list, set)): self.live_hosts.extend(list(host))
            else: self.live_hosts.append(host)
            
    def get_live_hosts(self): return list(self.live_hosts)

    def get_tech_stacks(self):
        """Extract unique tech stacks from profiled live hosts."""
        import json
        techs = set()
        for host_data in self.live_hosts:
            try:
                if isinstance(host_data, str):
                    host_data = json.loads(host_data)
                if isinstance(host_data, dict):
                    tech_str = host_data.get('tech', '')
                    for t in tech_str.split(','):
                        t = t.strip().lower()
                        if t and t != 'undetected':
                            techs.add(t)
            except (json.JSONDecodeError, AttributeError):
                continue
        return sorted(list(techs))

    def add_crawled_url(self, url=None, **kwargs):
        if url:
            if isinstance(url, (list, set)): self.crawled_urls.extend(list(url))
            else: self.crawled_urls.append(url)

    def get_crawled_urls(self): return list(self.crawled_urls)

    def commit(self): pass
    def save(self): pass 
    def close(self): self.conn.close()
    def purge(self):
        self.conn.close()
        if os.path.exists(self.db_path): os.remove(self.db_path)
