# Red Team Bot - Zararsız Ağ Güvenlik Test Platformu

## 🎯 Proje Açıklaması

Bu bot, ağ güvenlik sistemlerinin (SIEM, IDS/IPS, NDR vb.) anomali algılama yeteneğini test etmek için tasarlanmış zararsız bir Red Team simülasyon aracıdır.

## 🚀 Saldırı Vektörleri

| # | Saldırı Türü | Açıklama |
|---|-------------|----------|
| 1 | Nmap SYN Tarama | Ağ keşfi ve port taraması |
| 2 | SMB Enumerasyon | SMB servis bilgisi toplama |
| 3 | SSH Brute Force | Başarısız oturum açma denemeleri |
| 4 | C2 Beacon Simülasyonu | Düzenli dış bağlantı istekleri |
| 5 | Veri Sızıntısı Simülasyonu | Dummy veri transferi |
| 6 | Lateral Movement | Aynı kimlikle farklı host denemeleri |
| 7 | DNS Tünelleme | Uzun subdomain sorguları |
| 8 | ARP Keşif | Pasif ARP tarama |
| 9 | ICMP Flood (Hafif) | Düşük hacimli ping flood |
| 10 | Web App Tarama | Güvenlik payload testleri |

## 📦 Kurulum

```bash
pip install -r requirements.txt
python main.py
```

> **Not:** SYN taraması ve ARP/ICMP operasyonları için yönetici (root/admin) izinleri gerekebilir.

## ⚙️ Yapılandırma

`config.py` veya `main.py` içerisindeki `network_range` ve diğer parametreleri kendi test ağınıza göre özelleştirebilirsiniz:

```python
from config import BotConfig

cfg = BotConfig(
    network_range="192.168.1.0/24",
    stagger_enabled=True,
    delay_between_attacks=(120, 600)
)
```

## 📊 Log Dosyaları

- `redteam_attacks.json` - Detaylı JSON formatında saldırı raporları
- `redteam_attacks.log` - Konsol ve çalışma geçmişi logları

## ⚠️ Yasal Uyarı

Bu araç yalnızca yetkili güvenlik testleri, eğitim ve laboratuvar ortamlarında ağ savunma mekanizmalarını doğrulamak amacıyla kullanılmalıdır. İzin alınmamış sistemlerde kullanılması yasal sorumluluk doğurabilir.
