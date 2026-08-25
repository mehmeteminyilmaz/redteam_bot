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

    def log_attack(self, attack_type: str, target_ips: list, details: dict) -> str:
        self.counter += 1
        attack_id = f"RT-{datetime.now():%Y%m%d}-{self.counter:04d}"

        log_entry = {
            "attack_id": attack_id,
            "attack_type": attack_type,
            "target_ips": target_ips,
            "start_time": details.get("start_time", ""),
            "end_time": details.get("end_time", ""),
            "details": details,
            "timestamp": datetime.now().isoformat()
        }

        self._append_json(log_entry)

        logger.info("=" * 60)
        logger.info(f"[*] SALDIRI TAMAMLANDI: {attack_type}")
        logger.info(f"   ID: {attack_id}")
        logger.info(f"   Hedefler: {', '.join(target_ips)}")
        logger.info(f"   Baslangic: {details.get('start_time', 'N/A')}")
        logger.info(f"   Bitis: {details.get('end_time', 'N/A')}")
        logger.info(f"   Log dosyasi: {self.log_file}")
        logger.info("=" * 60)

        return attack_id

    def _append_json(self, entry: dict):
        data = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

        data.append(entry)

        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
