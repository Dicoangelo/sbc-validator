"""
Parser contract. Each vendor parser turns raw exported config text into a
NormalizedConfig. Parsing is 100% local; no network, no file egress.
"""
from __future__ import annotations

import abc

from ..models import NormalizedConfig


class AbstractParser(abc.ABC):
    vendor: str = "unknown"

    @classmethod
    @abc.abstractmethod
    def sniff(cls, text: str) -> bool:
        """Cheap heuristic: does this text look like our vendor's export?"""
        ...

    @abc.abstractmethod
    def parse(self, text: str) -> NormalizedConfig:
        ...
