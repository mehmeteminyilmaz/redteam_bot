from dataclasses import dataclass, field
from typing import List

@dataclass
class BotConfig:
    network_range: str = "192.168.1.0/24"
    ssh_fake_users: List[str] = field(default_factory=lambda: ['admin','root','test'])
    ssh_fake_passwords: List[str] = field(default_factory=lambda: ['123456','password'])
    c2_beacon_count: int = 15
    c2_interval_range: tuple = (45, 180)
    exfil_size_mb: int = 5
    dns_query_count: int = 30
    icmp_packet_count: int = 50
    web_common_ports: List[int] = field(default_factory=lambda: [80,8080,443])
    delay_between_attacks: tuple = (120, 600)
    stagger_enabled: bool = True
