"""Whitelist and policy helpers for SDN access control."""

from __future__ import annotations

import json
import os
from typing import Iterable, Set


class WhitelistManager:
    """Loads and manages the authorized host whitelist."""

    def __init__(self, whitelist_path: str) -> None:
        self.whitelist_path = whitelist_path
        self._authorized_hosts: Set[str] = set()
        self.load()

    @staticmethod
    def normalize_mac(mac_address: str) -> str:
        return mac_address.strip().lower()

    def load(self) -> Set[str]:
        if not os.path.exists(self.whitelist_path):
            raise FileNotFoundError(
                f"Whitelist file not found: {self.whitelist_path}"
            )

        with open(self.whitelist_path, "r", encoding="utf-8") as whitelist_file:
            payload = json.load(whitelist_file)

        hosts = payload.get("authorized_hosts", [])
        self._authorized_hosts = {
            self.normalize_mac(mac_address) for mac_address in hosts
        }
        return set(self._authorized_hosts)

    def reload(self) -> Set[str]:
        return self.load()

    def save(self) -> None:
        ordered_hosts = sorted(self._authorized_hosts)
        payload = {"authorized_hosts": ordered_hosts}
        with open(self.whitelist_path, "w", encoding="utf-8") as whitelist_file:
            json.dump(payload, whitelist_file, indent=2)
            whitelist_file.write("\n")

    def is_authorized(self, mac_address: str) -> bool:
        normalized = self.normalize_mac(mac_address)
        return normalized in self._authorized_hosts

    def add_host(self, mac_address: str) -> None:
        self._authorized_hosts.add(self.normalize_mac(mac_address))
        self.save()

    def remove_host(self, mac_address: str) -> None:
        self._authorized_hosts.discard(self.normalize_mac(mac_address))
        self.save()

    def get_all(self) -> Set[str]:
        return set(self._authorized_hosts)


class PolicyEngine:
    """Pure policy logic kept separate from controller I/O for testability."""

    ACTION_ALLOW = "ALLOW"
    ACTION_DENY = "DENY"

    def __init__(self, whitelist_manager: WhitelistManager) -> None:
        self.whitelist_manager = whitelist_manager

    def decide(self, source_mac: str) -> str:
        self.whitelist_manager.reload()
        if self.whitelist_manager.is_authorized(source_mac):
            return self.ACTION_ALLOW
        return self.ACTION_DENY

    def validate_no_conflicts(self, sources: Iterable[str]) -> bool:
        decisions = {}
        for source_mac in sources:
            normalized = self.whitelist_manager.normalize_mac(source_mac)
            decision = self.decide(normalized)
            existing = decisions.get(normalized)
            if existing is not None and existing != decision:
                return False
            decisions[normalized] = decision
        return True
