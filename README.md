# Red Team Bot - MITRE ATT&CK Security Testing Platform

## 🎯 Proje Açıklaması

Bu bot, ağ güvenlik sistemlerinin (SIEM, IDS/IPS, NDR vb.) anomali algılama ve kural tetikleme yeteneklerini test etmek için tasarlanmış zararsız bir Red Team simülasyon aracıdır.

Proje, **MITRE ATT&CK Matrix for Enterprise** çerçevesiyle tam uyumlu teknikler ve simülasyonlar içerir.

---

## 🚀 Desteklenen MITRE ATT&CK Teknikleri & Vektörler

| MITRE ID | Taktik (Tactic) | Teknik / Simülasyon Adı | Açıklama |
|---|---|---|---|
| **T1071.001** | Command and Control | Web Protocols: HTTPS Beaconing & Jitter | Düzensiz aralıklı (jitter) C2 trafiği |
| **T1071.004** | Command and Control | DNS Tunneling Simulation | Base64 kodlanmış DNS alt alan sorguları |
| **T1046** | Discovery | Network Service Discovery | SYN ve Port Taraması |
| **T1095** | Command and Control | Non-Application Layer Protocol | TCP/ICMP tünel simülasyonu |
| **T1021.001** | Lateral Movement | Remote Desktop Protocol (RDP) | RDP portu üzerinden lateral movement |
| **T1021.002** | Lateral Movement | SMB/Windows Admin Shares | SMB portu üzerinden lateral movement |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel (Burst & Slow) | Hızlı veya 'Low & Slow' gizli veri aktarımı |
| **T1562** | Defense Evasion | Impair Defenses: Baseline Poisoning | Düşük hacimli trafikle öğrenmeyi manipüle etme |
| *Legacy* | Discovery | Nmap SYN Tarama | Ağ keşfi ve port taraması |
| *Legacy* | Credential Access | SSH Brute Force | Başarısız oturum açma denemeleri |
| *Legacy* | Initial Access / Discovery | Web App Tarama | Güvenlik payload ve path testleri |

---

## 📦 Kurulum

Gerekli Python bağımlılıklarını yükleyin:

```bash
pip install -r requirements.txt
python main.py
```

> **Not:** SYN taramaları, ham soket (raw socket) veya ARP/ICMP operasyonları için yönetici (root/administrator) izinleri gerekebilir.

---

## ⚙️ Yapılandırma

`config.py` veya `main.py` içerisinden ağ aralığını ve davranış parametrelerini özelleştirebilirsiniz:

```python
from config import BotConfig

cfg = BotConfig(
    network_range="192.168.1.0/24",
    stagger_enabled=True,
    delay_between_attacks=(120, 600)
)
```

---

## 📊 Raporlama ve Loglar

Her saldırı tamamlandığında MITRE ID ve taktik etiketleriyle detaylı şekilde loglanır:

- `redteam_attacks.json` - Her saldırının teknik bilgileri, hedef IP'leri, başlangıç/bitiş süreleri ve ham sonuçlarını içeren JSON kaydı
- `redteam_attacks.log` - Konsol çıktısı ve çalışma geçmişi logları

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca yetkili güvenlik testleri, eğitim ve savunma mekanizmalarını doğrulamak amacıyla** kullanılmalıdır. İzin alınmamış sistemlerde veya ağlarda kullanılması yasal sorumluluk doğurabilir.
