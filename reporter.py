import json
import logging
import os
from datetime import datetime
from config import BotConfig

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('redteam_attacks.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AttackReporter:
    def __init__(self, config: BotConfig):
        self.config = config
        self.counter = 0
        self.log_file = "redteam_attacks.json"
        self.mitre_summary = {}
    
    def log_attack(self, attack_type: str, target_ips: list, details: dict) -> str:
        self.counter += 1
        attack_id = f"RT-{datetime.now():%Y%m%d}-{self.counter:04d}"
        
        # MITRE teknik bilgisi
        mitre_id = details.get('technique', 'UNKNOWN')
        mitre_tactic = details.get('tactic', 'UNKNOWN')
        
        log_entry = {
            "attack_id": attack_id,
            "mitre_technique": mitre_id,
            "mitre_tactic": mitre_tactic,
            "attack_type": attack_type,
            "target_ips": target_ips,
            "start_time": details.get("start_time", ""),
            "end_time": details.get("end_time", ""),
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        
        self._append_json(log_entry)
        self._update_mitre_summary(mitre_id, attack_id)
        
        # Konsola özet
        logger.info("=" * 70)
        logger.info(f"🔴 SALDIRI TAMAMLANDI")
        logger.info(f"   ID: {attack_id}")
        logger.info(f"   MITRE: {mitre_id} | {mitre_tactic}")
        logger.info(f"   Tip: {attack_type}")
        logger.info(f"   Hedefler: {', '.join(target_ips)}")
        logger.info(f"   Zaman: {details.get('start_time', 'N/A')} → {details.get('end_time', 'N/A')}")
        logger.info(f"   Log: {self.log_file}")
        logger.info("=" * 70)
        
        return attack_id
    
    def _append_json(self, entry: dict):
        data = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except:
                data = []
        
        data.append(entry)
        
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    def _update_mitre_summary(self, mitre_id: str, attack_id: str):
        if mitre_id not in self.mitre_summary:
            self.mitre_summary[mitre_id] = []
        self.mitre_summary[mitre_id].append(attack_id)
    
    def print_mitre_summary(self):
        """Tüm MITRE teknik özetini yazdır"""
        logger.info("\n" + "=" * 70)
        logger.info("📊 MITRE ATT&CK TEKNİK ÖZETİ")
        logger.info("=" * 70)
        for mitre_id, attacks in self.mitre_summary.items():
            logger.info(f"   {mitre_id}: {len(attacks)} saldırı")
        logger.info("=" * 70)