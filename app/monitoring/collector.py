import asyncio
import json
import math
from datetime import datetime, timedelta, timezone
import psutil
from app.discovery.classification import classify


def percentile(values, p):
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered)*p)-1)], 2) if ordered else 0


class Collector:
    def __init__(self, db):
        self.db = db
        self.subscribers = set()
        psutil.cpu_percent()

    def publish(self, item):
        for queue in tuple(self.subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(item)

    def record(self, item):
        self.db.record(item)
        self.publish({'type':'request', 'data':item})

    async def stream(self, disconnected):
        queue = asyncio.Queue(maxsize=64)
        if len(self.subscribers) >= 20:
            yield 'event: error\ndata: {"message":"Live connection limit reached"}\n\n'
            return
        self.subscribers.add(queue)
        try:
            yield 'event: ready\ndata: {"status":"connected"}\n\n'
            while not await disconnected():
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=2)
                    if await disconnected():
                        break
                    yield f'data: {json.dumps(item)}\n\n'
                except asyncio.TimeoutError:
                    yield 'event: tick\ndata: {}\n\n'
        finally:
            self.subscribers.discard(queue)

    def overview(self):
        rows = self.db.query('SELECT * FROM requests ORDER BY id DESC LIMIT 20000')
        cutoff = (datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat()
        totals = self.db.query('SELECT COALESCE(SUM(total),0) total, COALESCE(SUM(blocked),0) blocked, COALESCE(SUM(errors),0) errors, COALESCE(SUM(latency),0) latency FROM aggregates')[0]
        listeners = [json.loads(r['data']) for r in self.db.query('SELECT data FROM listeners')]
        services = self.db.services_with_evidence()
        listeners = [classify(r,services) for r in listeners]
        durations = [r['duration'] for r in rows]
        count = totals['total']
        return dict(listening_ports=len(listeners), potential_apis=sum(r['classification']!='Unknown' for r in listeners),
            confirmed_exposed=sum(r['security_status']=='Exposed' for r in listeners),
            gateway_managed=sum(s['enabled'] and (s['forwarded_observed'] or bool(s.get('verification') and s['verification'].get('forwarded'))) for s in services),
            needs_review=sum(r['security_status'] in ('Needs Review','Potentially Exposed','Protection Failed') for r in listeners),
            rps=round(sum(r['timestamp']>=cutoff for r in rows)/10, 1), total_requests=count, blocked=totals['blocked'],
            average_latency=round(totals['latency']/count, 2) if count else 0,
            error_rate=round(totals['errors']*100/count,2) if count else 0,
            successful=sum(200<=r['status']<400 for r in rows), client_errors=sum(400<=r['status']<500 for r in rows), upstream_errors=sum(r['status']>=500 for r in rows),
            p50=percentile(durations,.5), p95=percentile(durations,.95), p99=percentile(durations,.99),
            cpu=psutil.cpu_percent(), memory=psutil.virtual_memory().percent, last_scan=self.db.meta('last_scan'),
            scope='Gateway requests only. Totals cover retained 30-day aggregates; percentiles cover the last 20,000 requests. External reachability has not been tested.')

    def traffic(self):
        return dict(series=self.db.query('SELECT bucket, SUM(total) total, SUM(blocked) blocked, SUM(latency)/SUM(total) latency FROM aggregates GROUP BY bucket ORDER BY bucket DESC LIMIT 60')[::-1],
            statuses=self.db.query('SELECT status, COUNT(*) total FROM requests GROUP BY status ORDER BY status'),
            apis=self.db.query('SELECT api_name, COUNT(*) total FROM requests GROUP BY api_name ORDER BY total DESC'))
