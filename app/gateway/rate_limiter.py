import time
import threading
import json
import hashlib
import math
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, capacity=10000, db=None):
        self.clients = OrderedDict()
        self.capacity = capacity
        self.lock = threading.RLock()
        self.db = db

    def check(self, route, client, limit, window):
        with self.lock:
            if self.db is not None:
                return self._persistent_check(route,client,limit,window)
            return self._check(route, client, limit, window)

    def _persistent_check(self, route, client, limit, window):
        current=time.time()
        identity=hashlib.sha256(client.encode('utf-8')).hexdigest()
        with self.db.lock,self.db.conn:
            self.db.conn.execute('DELETE FROM rate_limits WHERE expires_at<=?',(current,))
            row=self.db.conn.execute('SELECT timestamps FROM rate_limits WHERE route=? AND client_hash=?',(route,identity)).fetchone()
            values=[t for t in json.loads(row['timestamps']) if t>current-window] if row else []
            if not row and self.db.conn.execute('SELECT COUNT(*) FROM rate_limits').fetchone()[0]>=self.capacity:
                return False,window
            if len(values)>=limit:
                return False,max(1,math.ceil(window-(current-values[0])))
            values.append(current)
            self.db.conn.execute('INSERT OR REPLACE INTO rate_limits VALUES (?,?,?,?)',(route,identity,json.dumps(values),current+window))
            return True,0

    def _check(self, route, client, limit, window):
        current = time.monotonic()
        key = (route, client)
        # Expire old identities; fail closed if the bound is exhausted.
        for old_key in list(self.clients)[:100]:
            if self.clients[old_key][1] <= current:
                del self.clients[old_key]
        if key not in self.clients:
            if len(self.clients) >= self.capacity:
                return False, window
            self.clients[key] = (deque(), current + window)
        values, _ = self.clients[key]
        while values and values[0] <= current - window:
            values.popleft()
        self.clients[key] = (values, current + window)
        self.clients.move_to_end(key)
        if len(values) >= limit:
            return False, max(1, int(window - (current - values[0])) + 1)
        values.append(current)
        return True, 0

    def clear_route(self, route):
        with self.lock:
            if self.db is not None:
                self.db.execute('DELETE FROM rate_limits WHERE route=?',(route,))
            for key in list(self.clients):
                if key[0] == route:
                    del self.clients[key]
