import paramiko
import time
import random
from datetime import datetime

class BruteForce:
    def __init__(self, users=None, passwords=None):
        self.users = users or ['admin','root','test','user']
        self.passwords = passwords or ['123456','password','admin123','qwerty']

    def ssh(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            attempts = []
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            for u in self.users:
                for p in self.passwords:
                    try:
                        c.connect(ip, username=u, password=p, timeout=3, banner_timeout=3)
                        c.close()
                        attempts.append({'user':u,'res':'UNEXPECTED_SUCCESS'})
                    except paramiko.AuthenticationException:
                        attempts.append({'user':u,'res':'FAILED'})
                    except Exception as e:
                        attempts.append({'user':u,'res':f'ERR:{str(e)[:30]}'})
                    time.sleep(random.uniform(0.5,1.5))
            c.close()
            r['targets'][ip] = {
                'total':len(attempts),
                'failed_rate':sum(1 for a in attempts if 'FAILED' in a['res'])/len(attempts)*100,
                'sample':attempts[:3]
            }
        r['end_time'] = datetime.now().isoformat()
        return r
