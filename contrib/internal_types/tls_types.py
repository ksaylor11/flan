from collections import defaultdict
from typing import List, Dict

__all__ = ['Cipher', 'ScanResult', 'TLS']


class TLS:
    tls10 = 'TLSv1.0'
    tls11 = 'TLSv1.1'
    tls12 = 'TLSv1.2'


class Cipher:
    """
    Descriptor for ciphers
    """
    def __init__(self, name: str, kex_info: str, strength: str):
        self.name = name
        self.kex_info = kex_info
        self.strength = strength

    def to_dict(self):
        return {
            'name': self.name,
            'key_exchange': self.kex_info,
            'strength': self.strength,
        }


class ScanResult:
    """
    Scan result representation
    """
    def __init__(self):
        self.locations = defaultdict(list)  # type: Dict[str, List[str]]
        self.vulns = []  # type: List[Vuln]
        self.ciphers = [] # type: List[Cipher]
