#!/usr/bin/env python3
import nmap
import random
import time
import logging
from config import BotConfig
from reporter import AttackReporter
from attacks import Scanner, BruteForce, C2Beacon, Exfiltration
from attacks import LateralMovement, DNSTunnel, NetworkAttacks, WebScan
from attacks import MITRETactics

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RedTeamBot:
    """
    MITRE ATT&CK Framework tabanlı Red Team Bot
    T1071.001, T1071.004, T1046, T1095, T1021.001, T1021.002, T1041, T1562
    """
    
    # MITRE ATT&CK Vektörleri
    VECTORS = [
        # T1046 - Keşif
        ('t1046_scan', 'T1046 - Network Service Discovery (Slow Scan)', 
         lambda m, t: m.t1046_slow_scan(t)),
        
        # T1071.001 - C2
        ('t1071_001_beacon', 'T1071.001 - Application Layer Protocol: Web (Beacon)',
         lambda m, t: m.t1071_001_beacon(t, beacon_count=30, jitter=True)),
        
        # T1071.004 - DNS Tunnel
        ('t1071_004_dns', 'T1071.004 - Application Layer Protocol: DNS (Tunnel)',
         lambda m, t: m.t1071_004_dns_tunnel(t, query_count=50)),
        
        # T1095 - Non-Standard Tunnel
        ('t1095_icmp', 'T1095 - Non-Application Layer Protocol (ICMP Tunnel)',
         lambda m, t: m.t1095_icmp_tunnel(t, packet_count=20)),
        
        ('t1095_tcp', 'T1095 - Non-Application Layer Protocol (Raw TCP)',
         lambda m, t: m.t1095_raw_tcp(t, duration=180)),
        
        # T1021.001 - RDP Lateral
        ('t1021_001_rdp', 'T1021.001 - Remote Services: RDP (Lateral)',
         lambda m, t: m.t1021_001_rdp_lateral(t)),
        
        # T1021.002 - SMB Lateral
        ('t1021_002_smb', 'T1021.002 - Remote Services: SMB (Lateral)',
         lambda m, t: m.t1021_002_smb_lateral(t)),
        
        # T1041 - Exfiltration
        ('t1041_burst', 'T1041 - Exfiltration Over C2 Channel (Burst)',
         lambda m, t: m.t1041_burst_exfil(t, total_mb=20)),
        
        ('t1041_slow', 'T1041 - Exfiltration Over C2 Channel (Low & Slow)',
         lambda m, t: m.t1041_low_and_slow(t, total_mb=5, duration_minutes=10)),
        
        # T1562 - Baseline Poison
        ('t1562_poison', 'T1562 - Impair Defenses: Baseline Poisoning',
         lambda m, t: m.t1562_baseline_poison(t, duration_hours=1)),
        
        # Eski vektörler (yedek)
        ('nmap_syn', 'Nmap SYN Tarama (Legacy)', lambda s, t: s.nmap_syn(t)),
        ('ssh_brute', 'SSH Brute Force (Legacy)', lambda bf, t: bf.ssh(t)),
        ('web_scan', 'Web App Tarama (Legacy)', lambda ws, t: ws.run(t)),
    ]
    
    def __init__(self, cfg: BotConfig):
        self.cfg = cfg
        self.reporter = AttackReporter(cfg)
        
        # Eski modüller
        self.scanner = Scanner()
        self.brute = BruteForce(cfg.ssh_fake_users, cfg.ssh_fake_passwords)
        self.c2 = C2Beacon(cfg.c2_beacon_count, cfg.c2_interval_range)
        self.exfil = Exfiltration(cfg.exfil_size_mb)
        self.lateral = LateralMovement()
        self.dns = DNSTunnel(cfg.dns_query_count)
        self.net = NetworkAttacks()
        self.web = WebScan(cfg.web_common_ports)
        
        # Yeni MITRE modülü
        self.mitre = MITRETactics()
        
        self.ips = []
    
    def discover(self):
        logger.info(f"🔍 Ağ keşfi: {self.cfg.network_range}")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.cfg.network_range, arguments='-sn -T4')
        self.ips = sorted(nm.all_hosts())
        logger.info(f"✅ {len(self.ips)} aktif host bulundu: {self.ips}")
        return self.ips
    
    def distribute(self):
        """IP'leri vektörlere dağıt"""
        n = len(self.VECTORS)
        g = max(1, len(self.ips) // n)
        dist = {}
        
        for i, (mid, name, fn) in enumerate(self.VECTORS):
            s = i * g
            e = (i + 1) * g if i < n - 1 else len(self.ips)
            assigned_ips = self.ips[s:e]
            
            if assigned_ips:
                dist[mid] = {
                    'name': name,
                    'fn': fn,
                    'targets': assigned_ips,
                    'mitre_id': mid.split('_')[0].upper()
                }
        
        return dist
    
    def run(self):
        logger.info("=" * 70)
        logger.info("🤖 RED TEAM BOT - MITRE ATT&CK EDITION")
        logger.info("=" * 70)
        logger.info("Teknikler: T1071.001, T1071.004, T1046, T1095,")
        logger.info("           T1021.001, T1021.002, T1041, T1562")
        logger.info("=" * 70)
        
        self.discover()
        if not self.ips:
            logger.warning("❌ Aktif host bulunamadı!")
            return
        
        dist = self.distribute()
        
        for mid, data in dist.items():
            name = data['name']
            fn = data['fn']
            targets = data['targets']
            mitre_id = data.get('mitre_id', 'UNKNOWN')
            
            logger.info(f"\n{'='*70}")
            logger.info(f"🎯 {mitre_id} | {name}")
            logger.info(f"   Hedefler ({len(targets)}): {', '.join(targets)}")
            logger.info(f"{'='*70}")
            
            # Doğru modülü seç
            try:
                if mid.startswith('t10') or mid.startswith('t1562'):
                    # MITRE teknikleri
                    res = fn(self.mitre, targets)
                elif 'nmap' in mid or 'smb' in mid:
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
                
                # Log kaydet
                attack_id = self.reporter.log_attack(name, targets, res)
                logger.info(f"✅ Log kaydedildi: {attack_id}")
                
                # MITRE beklentisi kontrolü
                self._check_mitre_expectations(res)
                
            except Exception as e:
                logger.error(f"❌ Saldırı hatası ({name}): {e}")
            
            # Bekleme
            if self.cfg.stagger_enabled:
                d = random.uniform(*self.cfg.delay_between_attacks)
                logger.info(f"⏳ Sonraki saldırıya kadar: {d:.0f}s")
                time.sleep(d)
        
        logger.info("\n" + "=" * 70)
        logger.info("✅ RED TEAM BOT TAMAMLANDI")
        logger.info("📄 Log dosyası: redteam_attacks.json")
        logger.info("=" * 70)
    
    def _check_mitre_expectations(self, result: dict):
        """MITRE beklentilerini konsola yazdır"""
        technique = result.get('technique', 'UNKNOWN')
        
        expectations = {
            'T1071.001': 'Beklenen: Beacon, InteractiveC2 alarmı',
            'T1071.004': 'Beklenen: DnsTunnel, C2 alarmı',
            'T1046': 'Beklenen: Scan, ServiceDiscovery alarmı',
            'T1095': 'Beklenen: TcpTunnel, IcmpTunnel alarmı',
            'T1021.001': 'Beklenen: Lateral, RdpLateral alarmı',
            'T1021.002': 'Beklenen: Lateral, SmbLateral alarmı',
            'T1041': 'Beklenen: Exfil, StealthExfil alarmı',
            'T1562': 'Beklenen: BASELINE_POISON, DefenseEvasion alarmı',
        }
        
        if technique in expectations:
            logger.info(f"📊 {expectations[technique]}")


if __name__ == "__main__":
    cfg = BotConfig(
        network_range="192.168.1.0/24",
        # Diğer ayarlar default
    )
    RedTeamBot(cfg).run()