import scapy.all as scapy
import subprocess
import time
from datetime import datetime

class NetworkAttacks:
    def arp_discovery(self, targets: list) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            try:
                ans = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip),
                    timeout=2, verbose=False
                )[0]
                r['targets'][ip] = {
                    'entries':[{'ip':rcv.psrc,'mac':rcv.hwsrc} for snd,rcv in ans],
                    'note':'PASSIVE ONLY'
                }
            except Exception as e:
                r['targets'][ip] = {'error':str(e)}
        r['end_time'] = datetime.now().isoformat()
        return r

    def icmp_flood(self, targets: list, count=50, interval=0.1) -> dict:
        r = {'start_time': datetime.now().isoformat(), 'targets': {}}
        for ip in targets:
            start = time.time()
            try:
                subprocess.run(
                    ['ping','-c',str(count),'-i',str(interval),ip],
                    capture_output=True, text=True, timeout=60
                )
                dur = time.time() - start
                r['targets'][ip] = {
                    'packets':count,
                    'duration':round(dur,2),
                    'pps':round(count/dur,2),
                    'note':'LIGHT - safe'
                }
            except Exception as e:
                r['targets'][ip] = {'error':str(e)}
        r['end_time'] = datetime.now().isoformat()
        return r
