#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
severity_engine.py (Risk-Based Version)

Risk-based severity engine combining:
- MITRE ATT&CK technique impact
- CVSS-like scoring (heuristic or from mapping)
- Asset criticality (critical systems get higher severity)
- Volume-based escalation ("spike" detection) using count thresholds

This module is designed to be a drop-in replacement for the previous
SeverityEngine used by server.py. The public API is compatible:

    engine = SeverityEngine(mapping_path="severity_mapping.json", mode="auto")
    sev = engine.classify(mitre_id, count, hostname=..., identity=..., category_hint=None)

It will:
- Use severity_mapping.json (acunetix + cvss sections) as the primary mapping source.
- Optionally consume an extra JSON file "mitre_risk.json" if present, containing
  per-technique impact and cvss scores exported from MITRE ATT&CK/RESP or other tools.
"""

from __future__ import annotations

import json
import os
from typing import Optional, Dict, Any


SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SeverityEngine:
    def __init__(
        self,
        mapping_path: str = "severity_mapping.json",
        mode: str = "auto",
        mitre_risk_path: Optional[str] = None,
    ) -> None:
        """
        :param mapping_path: JSON file containing "acunetix" and "cvss" mappings.
        :param mode: kept for backward compatibility ("auto" is recommended).
        :param mitre_risk_path: optional JSON file with per-MITRE risk metadata, e.g.:

            {
              "T1190": {"impact": 40, "cvss": 9.8},
              "T1059": {"impact": 35, "cvss": 9.5},
              ...
            }

        If mitre_risk_path is None, the engine will try "mitre_risk.json" next to mapping_path.
        """
        self.mode = mode or "auto"

        base_dir = os.path.dirname(os.path.abspath(__file__))
        mapping_full = os.path.join(base_dir, mapping_path)

        try:
            with open(mapping_full, "r") as f:
                data = json.load(f)
        except Exception:
            # If mapping cannot be loaded, fallback to empty dicts (engine still works, but less rich).
            data = {}

        self.mapping_raw: Dict[str, Any] = data
        self.acu: Dict[str, Any] = data.get("acunetix", {}) or {}
        self.cvss: Dict[str, Any] = data.get("cvss", {}) or {}

        # Unified escalation / thresholds (if defined)
        self.escalation: Dict[str, Any] = (
            self.acu.get("escalation")
            or self.cvss.get("escalation")
            or {}
        )

        # critical asset keywords from mapping (lowercased)
        acu_kw = self.acu.get("critical_asset_keywords", []) or []
        cvss_kw = self.cvss.get("critical_asset_keywords", []) or []
        self.critical_asset_keywords = {k.lower() for k in (acu_kw + cvss_kw)}

        # Hard-coded asset criticality factors (can be tuned as needed)
        self.asset_criticality = {
            # Critical business systems
            "tos-nusantara.pelindo.co.id": 1.5,
            "phinnisi.pelindo.co.id": 1.4,
            "parama.pelindo.co.id": 1.3,
            "praya.pelindo.co.id": 1.2,
            "ptosc.pelindo.co.id": 1.1,
            "ptosr.pelindo.co.id": 1.1,
        }

        # Optional per-MITRE risk metadata (impact, cvss)
        if mitre_risk_path is None:
            mitre_risk_path = "mitre_risk.json"

        mitre_risk_full = os.path.join(base_dir, mitre_risk_path)
        if os.path.exists(mitre_risk_full):
            try:
                with open(mitre_risk_full, "r") as f:
                    self.mitre_risk = json.load(f) or {}
            except Exception:
                self.mitre_risk = {}
        else:
            self.mitre_risk = {}


    # ======================================================================
    # Public API
    # ======================================================================
    def classify(
        self,
        mitre_id: str,
        count: int,
        hostname: Optional[str] = None,
        identity: Optional[str] = None,
        category_hint: Optional[str] = None,
    ) -> str:
        """
        Compute final severity for a given MITRE technique and event count.

        - Looks at static mapping (acunetix/cvss category/severity).
        - Computes risk score from CVSS + MITRE impact + volume spike.
        - Adjusts based on asset criticality and critical keywords.
        - Converts risk score to severity (INFO..CRITICAL).
        - Takes the maximum between static severity and risk-based severity.
        """
        mitre_id = (mitre_id or "").strip()
        count = int(count or 0)

        base_sev, _category_from_map = self._base_severity(mitre_id, category_hint)

        if base_sev is None:
            base_sev = "LOW"

        # Compute risk-based score and derived severity
        risk_score = self._compute_risk_score(
            mitre_id=mitre_id,
            base_severity=base_sev,
            count=count,
            hostname=hostname,
            identity=identity,
        )
        risk_sev = self._severity_from_risk_score(risk_score)

        # Return the higher of the two severities (static vs. risk-based)
        final = self._max_severity(base_sev, risk_sev)
        return final


    # ======================================================================
    # Base severity from mapping (Acunetix + CVSS)
    # ======================================================================
    def _base_severity(
        self,
        mitre_id: str,
        category_hint: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Find a "static" base severity derived from mapping JSON, ignoring volume.
        Priority:
        1) acunetix.mitre_overrides[mitre_id]
        2) acunetix.mitre_to_category[mitre_id] → acunetix.category_to_severity
        3) cvss.mitre_to_category[mitre_id] → cvss.category_to_severity
        4) cvss.mitre_overrides[mitre_id] (if exists)
        """
        acu_overrides = (self.acu.get("mitre_overrides") or {})
        cvss_overrides = (self.cvss.get("mitre_overrides") or {})

        # 1) Acunetix overrides
        if mitre_id in acu_overrides:
            return acu_overrides[mitre_id], None

        # 2) Acunetix categorization
        category = category_hint
        if category is None:
            category = (self.acu.get("mitre_to_category") or {}).get(mitre_id)
        if category:
            sev = (self.acu.get("category_to_severity") or {}).get(category)
            if sev:
                return sev, category

        # 3) CVSS categorization
        if category is None:
            category = (self.cvss.get("mitre_to_category") or {}).get(mitre_id)
        if category:
            sev = (self.cvss.get("category_to_severity") or {}).get(category)
            if sev:
                return sev, category

        # 4) CVSS overrides (if present)
        if mitre_id in cvss_overrides:
            return cvss_overrides[mitre_id], category

        return None, category


    # ======================================================================
    # Risk score computation
    # ======================================================================
    def _compute_risk_score(
        self,
        mitre_id: str,
        base_severity: str,
        count: int,
        hostname: Optional[str],
        identity: Optional[str],
    ) -> float:
        """
        Build a numeric risk score from multiple factors:

        risk_score = (cvss_part + mitre_impact_part + volume_part) * asset_factor
        then optionally boosted by critical keywords.
        """
        base_severity = (base_severity or "LOW").upper()

        # 1) CVSS base (0–10)
        cvss_score = self._cvss_for_mitre(mitre_id, base_severity)

        # 2) MITRE impact (0–40)
        impact_score = self._impact_for_mitre(mitre_id, base_severity)

        # 3) Volume / spike factor (0–40)
        volume_score = self._volume_factor(count)

        # Raw risk
        risk = (cvss_score * 6.0) + impact_score + volume_score

        # 4) Asset criticality factor
        asset_factor = self._asset_factor(hostname, identity)
        risk *= asset_factor

        # 5) Critical keyword boost (mimic "crown jewels")
        if self._has_critical_keyword(hostname, identity):
            # Bump by 10 but not above 100
            risk += 10.0

        # Clamp 0..100
        if risk < 0:
            risk = 0.0
        if risk > 100:
            risk = 100.0

        return risk


    def _cvss_for_mitre(self, mitre_id: str, base_severity: str) -> float:
        """
        Determine a CVSS-like score for this technique.
        Priority:
        1) mitre_risk[mitre_id]["cvss"]
        2) cvss_thresholds defaults based on base_severity
        """
        # 1) If we have explicit CVSS from mitre_risk.json
        entry = self.mitre_risk.get(mitre_id) if self.mitre_risk else None
        if isinstance(entry, dict):
            val = entry.get("cvss")
            try:
                if val is not None:
                    v = float(val)
                    if 0.0 <= v <= 10.0:
                        return v
            except Exception:
                pass

        # 2) Fallback to heuristic based on base severity
        base_severity = base_severity.upper()
        thresholds = self.cvss.get("cvss_thresholds") or {
            "critical_min": 9.0,
            "high_min": 7.0,
            "medium_min": 4.0,
            "low_min": 0.1,
        }

        if base_severity == "CRITICAL":
            return max(9.5, thresholds.get("critical_min", 9.0))
        if base_severity == "HIGH":
            return max(7.5, thresholds.get("high_min", 7.0))
        if base_severity == "MEDIUM":
            return max(5.5, thresholds.get("medium_min", 4.0))
        if base_severity == "LOW":
            return max(3.0, thresholds.get("low_min", 0.1))
        # INFO or unknown
        return 1.0


    def _impact_for_mitre(self, mitre_id: str, base_severity: str) -> float:
        """
        MITRE impact score (0–40). Higher means more dangerous technique by nature.
        Priority:
        1) mitre_risk[mitre_id]["impact"]
        2) Heuristic derived from base severity
        """
        entry = self.mitre_risk.get(mitre_id) if self.mitre_risk else None
        if isinstance(entry, dict):
            val = entry.get("impact")
            try:
                if val is not None:
                    v = float(val)
                    if v >= 0:
                        return min(v, 40.0)
            except Exception:
                pass

        # Fallback heuristic
        sev = base_severity.upper()
        if sev == "CRITICAL":
            return 40.0
        if sev == "HIGH":
            return 30.0
        if sev == "MEDIUM":
            return 20.0
        if sev == "LOW":
            return 10.0
        return 5.0  # INFO/unknown


    def _volume_factor(self, count: int) -> float:
        """
        Volume / spike factor. Uses escalation thresholds from mapping if present.

        Idea:
        - If count exceeds "count_critical" → strong spike (+30)
        - Else if count exceeds "count_high" → moderate spike (+15)
        - Else if small but nonzero → minor contribution (+5)
        """
        count = int(count or 0)
        esc = self.escalation or {}

        count_high = esc.get("count_high", 20)
        count_critical = esc.get("count_critical", 200)

        if count >= count_critical:
            return 30.0
        if count >= count_high:
            return 15.0
        if count > 0:
            return 5.0
        return 0.0


    def _asset_factor(self, hostname: Optional[str], identity: Optional[str]) -> float:
        """
        Return multiplicative factor based on asset criticality.
        """
        hostname = (hostname or "").lower().strip()
        identity = (identity or "").lower().strip()

        # 1) Direct hostname mapping
        if hostname in self.asset_criticality:
            return float(self.asset_criticality[hostname])

        # 2) Keyword-based mapping using identity text
        text = f"{hostname} {identity}"
        if any(k in text for k in self.critical_asset_keywords):
            # treat as high importance if keyword hits
            return 1.4

        # 3) Default factor
        return 1.0


    def _has_critical_keyword(self, hostname: Optional[str], identity: Optional[str]) -> bool:
        """
        Check whether hostname or identity contains any "crown jewel" keyword
        to give an additional bump beyond asset_factor.
        """
        text = f"{hostname or ''} {identity or ''}".lower()
        if not text:
            return False
        for kw in self.critical_asset_keywords:
            if kw and kw in text:
                return True
        return False


    # ======================================================================
    # Map numeric risk score → severity & helpers
    # ======================================================================
    def _severity_from_risk_score(self, score: float) -> str:
        """
        Convert risk score 0..100 → severity buckets.
        """
        try:
            s = float(score)
        except Exception:
            s = 0.0

        if s >= 90.0:
            return "CRITICAL"
        if s >= 70.0:
            return "HIGH"
        if s >= 40.0:
            return "MEDIUM"
        if s > 0.0:
            return "LOW"
        return "INFO"


    @staticmethod
    def _rank(sev: str) -> int:
        sev = (sev or "").upper()
        try:
            return SEV_ORDER.index(sev)
        except ValueError:
            return 0  # INFO as default


    def _max_severity(self, a: str, b: str) -> str:
        """Return the more severe (higher) of two severity labels."""
        ra = self._rank(a)
        rb = self._rank(b)
        return a if ra >= rb else b
