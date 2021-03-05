from collections import defaultdict
from typing import List, Dict

__all__ = ['Cipher', 'TlsScanResult', 'TLS', 'TlS_Grade']


class TLS:
    TLS10 = 'TLSv1.0'
    TLS11 = 'TLSv1.1'
    TLS12 = 'TLSv1.2'

class TlS_Grade:
    GOOD = 'Good'
    FAIR = 'Fair'
    POOR = 'Poor'
    FAIL = 'Fail'

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

    @staticmethod
    def convert_strength(strength: str) -> str:
        """
        :return: Float severity value to text
        """
        if strength == 'A':
            return 'Good'
        elif strength == 'B':
            return 'Fair'
        elif strength == 'C':
            return 'Poor'
        else:
            return 'Fail'

    @property
    def strength_str(self) -> str:
        """
        :return: Text severity representation
        """
        return self.convert_strength(self.strength)

class TlsScanResult:
    """
    Scan result representation
    """
    def __init__(self):
        self.ciphers = [] # type: List[Cipher]
