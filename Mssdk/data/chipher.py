from dataclasses import dataclass
from typing import List


@dataclass
class AESConfig(object):
    key: str
    iv: str


@dataclass
class XteaConfig(object):
    key: str
    iv: str
