import requests
import urllib.parse
from datetime import datetime

class WebScan:
    def __init__(self, ports=None):
        self.ports = ports or [80,8080,443]
        self.payloads = ["' OR '1'='1","<script>alert(1)</script>","../../../etc/passwd"]
        self.paths = ['/','/admin','/login','/api','/.env']

    def run(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            results = []
            for port in self.ports:
                for path in self.paths:
                    try:
                        resp = requests.get(
                            f"http://{ip}:{port}{path}",
                            timeout=3, allow_redirects=False
                        )
                        results.append({'url':f"http://{ip}:{port}{path}",'status':resp.status_code})
                    except: pass
                for payload in self.payloads:
                    try:
                        url = f"http://{ip}:{port}/search?q={urllib.parse.quote(payload)}"
                        resp = requests.get(url, timeout=3)
                        results.append({'url':url[:60],'payload':True,'status':resp.status_code})
                    except: pass
            r['targets'][ip] = {'requests':len(results),'sample':results[:5]}
        r['end_time'] = datetime.now().isoformat()
        return r
