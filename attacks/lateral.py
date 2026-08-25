import paramiko
from datetime import datetime

class LateralMovement:
    def __init__(self, creds=None):
        self.creds = creds or [
            ('admin','P@ssw0rd123'),
            ('DOMAIN\\svc_account','ServicePass2024!')
        ]

    def run(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for src in targets:
            attempts = []
            for dst in targets:
                if src == dst: continue
                for u,p in self.creds:
                    try:
                        c = paramiko.SSHClient()
                        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        c.connect(dst, username=u, password=p, timeout=3)
                        c.close()
                        attempts.append({'dst':dst,'res':'UNEXPECTED_SUCCESS'})
                    except paramiko.AuthenticationException:
                        attempts.append({'dst':dst,'res':'FAILED'})
                    except Exception as e:
                        attempts.append({'dst':dst,'res':f'ERR:{str(e)[:30]}'})
            r['targets'][src] = {
                'targets':len(targets)-1,
                'total':len(attempts),
                'sample':attempts[:3]
            }
        r['end_time'] = datetime.now().isoformat()
        return r
