#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
oci_realtime_fetcher.py
Realtime fetcher via OCI Logging Search API

Membaca log dari Logging Search:
- Query WAF log source (Log Group / Log Source)
- Mengambil event 60 detik terakhir
- Menormalkan output agar server.py bisa langsung pakai
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Any

import oci
from oci.loggingsearch.models import SearchLogsDetails


@dataclass
class OCIRealtimeConfig:
    tenancy_id: str
    user_id: str
    fingerprint: str
    private_key_path: str
    region: str
    web_app_firewall_policy_id: str


class OCIRealtimeFetcher:
    def __init__(
        self,
        tenancy_id: str,
        user_id: str,
        key_fingerprint: str,
        private_key_path: str,
        region: str,
        web_app_firewall_policy_id: str,
    ) -> None:

        self.conf = OCIRealtimeConfig(
            tenancy_id=tenancy_id,
            user_id=user_id,
            fingerprint=key_fingerprint,
            private_key_path=private_key_path,
            region=region,
            web_app_firewall_policy_id=web_app_firewall_policy_id,
        )

        # ============================================================
        # OCI SDK CONFIG
        # ============================================================
        self.oci_config = {
            "user": self.conf.user_id,
            "tenancy": self.conf.tenancy_id,
            "fingerprint": self.conf.fingerprint,
            "key_file": self.conf.private_key_path,
            "region": self.conf.region,
        }

        self.client = oci.loggingsearch.LogSearchClient(self.oci_config)

    # ======================================================================
    #  RETURN FORMAT (agar cocok dengan server.py)
    # ======================================================================
    def _normalize(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Map SearchResult ke bentuk standar dashboard."""
        data = result.get("data", {})

        return {
            "time": data.get("datetime"),
            "clientIp": data.get("clientAddress"),
            "host": data.get("requestHost"),
            "uri": data.get("requestUri"),
            "mitre_id": data.get("mitreTechnique"),
            "rule": data.get("wafAction"),
        }

    # ======================================================================
    #  QUERY LOGGING SEARCH (LAST 60 SECONDS)
    # ======================================================================
    def fetch_last_minute(self) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        start = now - timedelta(seconds=60)

        # ============================================================
        # WAF Logging Search Query
        #
        # Sesuaikan logSourceName dengan nama log source kamu
        # Kamu bisa cek di OCI Logging → Log Groups → Log
        # Biasanya:  "oci-waf-log"
        # ============================================================
        query = (
            f"search \"web_app_firewall_policy_id = '{self.conf.web_app_firewall_policy_id}'\" "
            f"| sort by datetime desc"
        )

        search_details = SearchLogsDetails(
            time_start=start,
            time_end=now,
            search_query=query,
            is_return_field_info=False,
        )

        try:
            resp = self.client.search_logs(search_details, limit=1000)
        except Exception as e:
            print("[ERROR] OCI Logging Search error:", e)
            return []

        results = getattr(resp.data, "results", [])
        normalized = [self._normalize(r.__dict__) for r in results]

        # Hilangkan record null
        return [e for e in normalized if e.get("host") or e.get("clientIp")]
