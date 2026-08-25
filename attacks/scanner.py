import nmap
import socket
from datetime import datetime

class Scanner:
    def nmap_syn(self, targets: list, ports: str = "1-65535") -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        nm = nmap.PortScanner()
        for ip in targets:
            try:
                nm.scan(ip, arguments='-sS -sV --top-ports 1000 -T2 --open')
                h = nm[ip] if ip in nm.all_hosts() else {}
                r['targets'][ip] = {
                    'status': h.get('status',{}).get('state','unknown'),
                    'tcp': {str(p): h['tcp'][p] for p in h.get('tcp',{})} if 'tcp' in h else {},
                    'os': h.get('osmatch',[])[:2]
                }
            except Exception as e:
                r['targets'][ip] = {'error': str(e)}
        r['end_time'] = datetime.now().isoformat()
        return r

    def smb_enum(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                open_445 = s.connect_ex((ip, 445)) == 0
                s.close()
                r['targets'][ip] = {'smb_open': open_445, 'null_session': 'attempted' if open_445 else 'skipped'}
            except Exception as e:
                r['targets'][ip] = {'error': str(e)}
        r['end_time'] = datetime.now().isoformat()
        return r
