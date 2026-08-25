# Red Team Bot - MITRE ATT&CK Security Testing Platform

## Proje Aciklamasi

Bu bot, ag guvenlik sistemlerinin (SIEM, IDS/IPS, NDR vb.) anomali algilama ve kural tetikleme yeteneklerini test etmek icin tasarlanmis zararsiz bir Red Team simulasyon aracidir.

Proje, **MITRE ATT&CK Matrix for Enterprise** cercevesiyle tam uyumlu teknikler ve simulasyonlar icerir.

---

## Desteklenen MITRE ATT&CK Teknikleri ve Vektorler

| MITRE ID | Taktik (Tactic) | Teknik / Simulasyon Adi | Aciklama |
|---|---|---|---|
| **T1071.001** | Command and Control | Web Protocols: HTTPS Beaconing & Jitter | Duzensiz aralikli (jitter) C2 trafigi |
| **T1071.004** | Command and Control | DNS Tunneling Simulation | Base64 kodlanmis DNS alt alan sorgulari |
| **T1046** | Discovery | Network Service Discovery | SYN ve Port Taramasi |
| **T1095** | Command and Control | Non-Application Layer Protocol | TCP/ICMP tunel simulasyonu |
| **T1021.001** | Lateral Movement | Remote Desktop Protocol (RDP) | RDP portu uzerinden lateral movement |
| **T1021.002** | Lateral Movement | SMB/Windows Admin Shares | SMB portu uzerinden lateral movement |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel (Burst & Slow) | Hizli veya Low-and-Slow gizli veri aktarimi |
| **T1562** | Defense Evasion | Impair Defenses: Baseline Poisoning | Dusuk hacimli trafikle ogrenmeyi manipule etme |
| *Legacy* | Discovery | Nmap SYN Tarama | Ag kesfi ve port taramasi |
| *Legacy* | Credential Access | SSH Brute Force | Basarisiz oturum acma denemeleri |
| *Legacy* | Initial Access / Discovery | Web App Tarama | Guvenlik payload ve path testleri |

---

## Kurulum

Gerekli Python bagimlilikalarini yukleyin:

```bash
pip install -r requirements.txt
python main.py
```

> **Not:** SYN taramalari, ham soket (raw socket) veya ARP/ICMP operasyonlari icin yonetici (root/administrator) izinleri gerekebilir.

---

## Yapilandirma

`config.py` veya `main.py` icerisinden ag araligini ve davranis parametrelerini ozellestirilebilirsiniz:

```python
from config import BotConfig

cfg = BotConfig(
    network_range="192.168.1.0/24",
    stagger_enabled=True,
    delay_between_attacks=(120, 600)
)
```

---

## Raporlama ve Loglar

Her saldiri tamamlandiginda MITRE ID ve taktik etiketleriyle detayli sekilde loglanir:

- `redteam_attacks.json` - Her saldirinin teknik bilgileri, hedef IP adresleri, baslangic/bitis sureleri ve ham sonuclarini iceren JSON kaydi
- `redteam_attacks.log` - Konsol ciktisi ve calisma gecmisi loglari

---

## Yasal Uyari

Bu arac **yalnizca yetkili guvenlik testleri, egitim ve savunma mekanizmalarini dogrulamak amaciyla** kullanilmalidir. Izin alinmamis sistemlerde veya aglarda kullanilmasi yasal sorumluluk dogurabilir.
