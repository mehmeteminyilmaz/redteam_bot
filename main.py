#!/usr/bin/env python3
import nmap
import random
import time
import logging
from config import BotConfig
from reporter import AttackReporter
from attacks import Scanner, BruteForce, C2Beacon, Exfiltration
from attacks import LateralMovement, DNSTunnel, NetworkAttacks, WebScan

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RedTeamBot:
    VECTORS = [
        ('nmap_syn', 'Nmap SYN Tarama', lambda s, t: s.nmap_syn(t)),
        ('smb_enum', 'SMB Enumerasyon', lambda s, t: s.smb_enum(t)),
        ('ssh_brute', 'SSH Brute Force', lambda bf, t: bf.ssh(t)),
        ('c2_beacon', 'C2 Beacon', lambda c2, t: c2.run(t)),
        ('exfil', 'Veri Sizintisi', lambda ex, t: ex.run(t)),
        ('lateral', 'Lateral Movement', lambda lat, t: lat.run(t)),
        ('dns_tunnel', 'DNS Tunelleme', lambda dns, t: dns.run(t)),
        ('arp_disc', 'ARP Kesif', lambda net, t: net.arp_discovery(t)),
        ('icmp_flood', 'ICMP Flood', lambda net, t: net.icmp_flood(t)),
        ('web_scan', 'Web App Tarama', lambda ws, t: ws.run(t)),
    ]

    def __init__(self, cfg: BotConfig):
        self.cfg = cfg
        self.reporter = AttackReporter(cfg)
        self.scanner = Scanner()
        self.brute = BruteForce(cfg.ssh_fake_users, cfg.ssh_fake_passwords)
        self.c2 = C2Beacon(cfg.c2_beacon_count, cfg.c2_interval_range)
        self.exfil = Exfiltration(cfg.exfil_size_mb)
        self.lateral = LateralMovement()
        self.dns = DNSTunnel(cfg.dns_query_count)
        self.net = NetworkAttacks()
        self.web = WebScan(cfg.web_common_ports)
        self.ips = []

    def discover(self):
        logger.info(f"[*] Ag kesfi baslatiliyor: {self.cfg.network_range}")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.cfg.network_range, arguments='-sn -T4')
        self.ips = sorted(nm.all_hosts())
        logger.info(f"[+] {len(self.ips)} aktif host bulundu: {self.ips}")
        return self.ips

    def distribute(self):
        n = len(self.VECTORS)
        g = max(1, len(self.ips) // n)
        dist = {}
        for i, (mid, name, fn) in enumerate(self.VECTORS):
            s, e = i * g, (i + 1) * g if i < n - 1 else len(self.ips)
            dist[mid] = (name, fn, self.ips[s:e])
        return {k: v for k, v in dist.items() if v[2]}

    def run(self):
        logger.info("=" * 60)
        logger.info("[*] RED TEAM BOT BASLATILIYOR")
        logger.info("=" * 60)

        self.discover()
        if not self.ips:
            logger.warning("[-] Aktif host bulunamadi!")
            return

        dist = self.distribute()

        for mid, (name, fn, targets) in dist.items():
            if not targets:
                continue

            logger.info(f"\n[>] {name} | {len(targets)} hedef")
            logger.info(f"   Hedefler: {', '.join(targets)}")

            if 'nmap' in mid or 'smb' in mid:
                res = fn(self.scanner, targets)
            elif 'ssh' in mid:
                res = fn(self.brute, targets)
            elif 'c2' in mid:
                res = fn(self.c2, targets)
            elif 'exfil' in mid:
                res = fn(self.exfil, targets)
            elif 'lateral' in mid:
                res = fn(self.lateral, targets)
            elif 'dns' in mid:
                res = fn(self.dns, targets)
            elif 'arp' in mid or 'icmp' in mid:
                res = fn(self.net, targets)
            elif 'web' in mid:
                res = fn(self.web, targets)
            else:
                continue

            attack_id = self.reporter.log_attack(name, targets, res)
            logger.info(f"[+] Log kaydedildi: {attack_id}")

            if self.cfg.stagger_enabled:
                d = random.uniform(*self.cfg.delay_between_attacks)
                logger.info(f"[*] Sonraki saldiriya kadar bekleme: {d:.0f} saniye")
                time.sleep(d)

        logger.info("\n" + "=" * 60)
        logger.info("[+] RED TEAM BOT TAMAMLANDI")
        logger.info("[*] Log dosyasi: redteam_attacks.json")
        logger.info("=" * 60)

if __name__ == "__main__":
    cfg = BotConfig(network_range="192.168.1.0/24")
    RedTeamBot(cfg).run()
