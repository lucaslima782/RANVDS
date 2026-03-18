# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Selection profile for controlling which RANVDS modules run per generation.

Used by both PCAP analysis (controls which extractors run) and security
evaluation (controls which summaries and indicators are included).
"""

from __future__ import annotations

from dataclasses import dataclass, fields as dc_fields
from typing import Dict, Any, Iterable


@dataclass
class SelectionProfile:
    """
    Controls which per-generation analysis modules are active.

    All fields default to True (full analysis). Set any field to False to skip
    the corresponding extractor or security indicator.

    2G:
        enc_2g_cs:   CS (voice) encryption
        enc_2g_ps:   PS (data) encryption
        id_2g_voice: Voice identity (TMSI/IMSI)
        id_2g_data:  Data identity (PTMSI/IMSI)
        paging_2g:   Paging records

    3G:
        enc_3g:      Encryption (UEA)
        int_3g:      Integrity (UIA)
        id_3g_rrc:   RRC identity
        id_3g_nas:   NAS identity
        paging_3g:   Paging records

    4G:
        enc_4g_rrc:  RRC encryption
        int_4g_rrc:  RRC integrity
        enc_4g_nas:  NAS encryption
        int_4g_nas:  NAS integrity
        id_4g_rrc:   RRC identity
        id_4g_nas:   NAS identity
        paging_4g:   Paging records
        vops_4g:     IMS VoPS support indicator

    5G:
        enc_5g_rrc:  RRC encryption
        int_5g_rrc:  RRC integrity
        enc_5g_nas:  NAS encryption
        int_5g_nas:  NAS integrity
        id_5g_rrc:   RRC identity
        id_5g_nas:   NAS identity
        paging_5g:   Paging records
        suci_5g:     SUCI protection scheme indicator
        vops_5g:     VoPS 3GPP support indicator

    General:
        ue_capability:       UE Crypto Capabilities algorithms summary tab

    Capabilities Messages Security:
        ue_cap_security_4g:  UECapabilityInformation vs SecurityModeComplete check (4G)
        ue_cap_security_5g:  UECapabilityInformation vs SecurityModeComplete check (5G)

    VoPS Security:
        sip_ipsec:           IPSec EAlg usage check on SIP 401 responses (VoLTE/VoNR)
    """

    # 2G
    enc_2g_cs:   bool = True
    enc_2g_ps:   bool = True
    id_2g_voice: bool = True
    id_2g_data:  bool = True
    paging_2g:   bool = True

    # 3G
    enc_3g:      bool = True
    int_3g:      bool = True
    id_3g_rrc:   bool = True
    id_3g_nas:   bool = True
    paging_3g:   bool = True

    # 4G
    enc_4g_rrc:  bool = True
    int_4g_rrc:  bool = True
    enc_4g_nas:  bool = True
    int_4g_nas:  bool = True
    id_4g_rrc:   bool = True
    id_4g_nas:   bool = True
    paging_4g:   bool = True
    vops_4g:     bool = True

    # 5G
    enc_5g_rrc:  bool = True
    int_5g_rrc:  bool = True
    enc_5g_nas:  bool = True
    int_5g_nas:  bool = True
    id_5g_rrc:   bool = True
    id_5g_nas:   bool = True
    paging_5g:   bool = True
    suci_5g:     bool = True
    vops_5g:     bool = True

    # General
    ue_capability:       bool = True
    ue_cap_security_4g:  bool = True
    ue_cap_security_5g:  bool = True

    # VoPS Security
    sip_ipsec:           bool = True

    # -------------------------------------------------------------------------
    # Serialisation helpers
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, bool]:
        """Return a plain dict representation (JSON-serialisable)."""
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SelectionProfile":
        """Build a SelectionProfile from a dict, ignoring unknown keys."""
        valid = {f.name for f in dc_fields(cls)}
        return cls(**{k: bool(v) for k, v in d.items() if k in valid})

    # -------------------------------------------------------------------------
    # Filtering helpers used by the analysis flows
    # -------------------------------------------------------------------------

    def filter_sequences(self, sequences: Dict[str, Any]) -> Dict[str, Any]:
        """Return only the sequence keys whose module is enabled by this profile."""
        enabled: set[str] = set()
        if self.enc_2g_cs:   enabled |= {"2G CS"}
        if self.enc_2g_ps:   enabled |= {"2G PS"}
        if self.enc_3g:      enabled |= {"3G ENC", "3G ENC CS", "3G ENC PS"}
        if self.int_3g:      enabled |= {"3G INT", "3G INT CS", "3G INT PS"}
        if self.enc_4g_rrc:  enabled |= {"4G RRC ENC", "4G UP ENC"}
        if self.int_4g_rrc:  enabled |= {"4G RRC INT", "4G UP INT"}
        if self.enc_4g_nas:  enabled |= {"4G NAS ENC"}
        if self.int_4g_nas:  enabled |= {"4G NAS INT"}
        if self.enc_5g_rrc:  enabled |= {"5G RRC ENC", "5G SA UP ENC", "5G NSA UP ENC"}
        if self.int_5g_rrc:  enabled |= {"5G RRC INT", "5G SA UP INT", "5G NSA UP INT"}
        if self.enc_5g_nas:  enabled |= {"5G NAS ENC"}
        if self.int_5g_nas:  enabled |= {"5G NAS INT"}
        return {k: v for k, v in sequences.items() if k in enabled}

    def any_id_enabled(self) -> bool:
        """True if at least one identity module is active."""
        return any([
            self.id_2g_voice, self.id_2g_data,
            self.id_3g_rrc, self.id_3g_nas,
            self.id_4g_rrc, self.id_4g_nas,
            self.id_5g_rrc, self.id_5g_nas,
        ])

    def any_paging_enabled(self) -> bool:
        """True if at least one paging module is active."""
        return any([self.paging_2g, self.paging_3g, self.paging_4g, self.paging_5g])

    def filter_paging_stats(self, paging_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Return only the paging generations whose module is enabled."""
        keep = set()
        if self.paging_2g: keep.add("2G")
        if self.paging_3g: keep.add("3G")
        if self.paging_4g: keep.add("4G")
        if self.paging_5g: keep.add("5G")
        return {gen: v for gen, v in paging_stats.items() if gen in keep}

    def any_vops_enabled(self) -> bool:
        """True if at least one VoPS module is active."""
        return any([self.vops_4g, self.vops_5g])

    def filter_identity_records(self, records: list) -> list:
        """Return only IdentityRecords whose sheet generation is enabled."""
        enabled_sheets: set = set()
        if self.id_2g_voice or self.id_2g_data:
            enabled_sheets |= {"2G CS ID", "2G PS ID"}
        if self.id_3g_rrc or self.id_3g_nas:
            enabled_sheets |= {"3G RRC ID", "3G NAS ID"}
        if self.id_4g_rrc or self.id_4g_nas:
            enabled_sheets |= {"4G RRC ID", "4G NAS ID"}
        if self.id_5g_rrc or self.id_5g_nas:
            enabled_sheets |= {"5G RRC ID", "5G NAS ID"}
        return [r for r in records if (getattr(r, 'sheet', '') in enabled_sheets)]


# Convenience: human-readable label for each profile key (used by the GUI).
PROFILE_LABELS: Dict[str, str] = {
    "enc_2g_cs":   "2G CS Encryption",
    "enc_2g_ps":   "2G PS Encryption",
    "id_2g_voice": "2G Voice Identity",
    "id_2g_data":  "2G Data Identity",
    "paging_2g":   "2G Paging",
    "enc_3g":      "3G Encryption",
    "int_3g":      "3G Integrity",
    "id_3g_rrc":   "3G RRC Identity",
    "id_3g_nas":   "3G NAS Identity",
    "paging_3g":   "3G Paging",
    "enc_4g_rrc":  "4G RRC Encryption",
    "int_4g_rrc":  "4G RRC Integrity",
    "enc_4g_nas":  "4G NAS Encryption",
    "int_4g_nas":  "4G NAS Integrity",
    "id_4g_rrc":   "4G RRC Identity",
    "id_4g_nas":   "4G NAS Identity",
    "paging_4g":   "4G Paging",
    "vops_4g":     "4G VoPS",
    "enc_5g_rrc":  "5G RRC Encryption",
    "int_5g_rrc":  "5G RRC Integrity",
    "enc_5g_nas":  "5G NAS Encryption",
    "int_5g_nas":  "5G NAS Integrity",
    "id_5g_rrc":   "5G RRC Identity",
    "id_5g_nas":   "5G NAS Identity",
    "paging_5g":   "5G Paging",
    "suci_5g":     "5G SUCI",
    "vops_5g":     "5G VoPS",
    "ue_capability":       "UE Crypto Capabilities",
    "ue_cap_security_4g":  "4G Cap Msg Security",
    "ue_cap_security_5g":  "5G Cap Msg Security",
    "sip_ipsec":           "SIP IPSec (VoPS)",
}

# Group keys by generation for GUI layout.
PROFILE_GROUPS: Dict[str, list[str]] = {
    "General": ["ue_capability"],
    "2G": ["enc_2g_cs", "enc_2g_ps", "id_2g_voice", "id_2g_data", "paging_2g"],
    "3G": ["enc_3g", "int_3g", "id_3g_rrc", "id_3g_nas", "paging_3g"],
    "4G": ["enc_4g_rrc", "int_4g_rrc", "enc_4g_nas", "int_4g_nas",
           "id_4g_rrc", "id_4g_nas", "paging_4g", "vops_4g", "ue_cap_security_4g"],
    "5G": ["enc_5g_rrc", "int_5g_rrc", "enc_5g_nas", "int_5g_nas",
           "id_5g_rrc", "id_5g_nas", "paging_5g", "suci_5g", "vops_5g", "ue_cap_security_5g"],
    "VoPS": ["sip_ipsec"],
}

# Security evaluator menu: exactly 4 evaluation categories.
# Each entry is (key_or_keys, label).
# List key means all listed profile keys are toggled together.
SECURITY_MENU_GROUPS: Dict[str, list] = {
    "Cryptography Usage": [
        ("enc_2g_cs",  "2G CS Encryption"),
        ("enc_2g_ps",  "2G PS Encryption"),
        ("enc_3g",     "3G Encryption"),
        ("int_3g",     "3G Integrity"),
        ("enc_4g_rrc", "4G RRC Encryption"),
        ("int_4g_rrc", "4G RRC Integrity"),
        ("enc_4g_nas", "4G NAS Encryption"),
        ("int_4g_nas", "4G NAS Integrity"),
        ("enc_5g_rrc", "5G RRC Encryption"),
        ("int_5g_rrc", "5G RRC Integrity"),
        ("enc_5g_nas", "5G NAS Encryption"),
        ("int_5g_nas", "5G NAS Integrity"),
    ],
    "TMSI Randomness": [
        (["id_2g_voice", "id_2g_data"],  "2G"),
        (["id_3g_rrc",   "id_3g_nas"],   "3G"),
        (["id_4g_rrc",   "id_4g_nas"],   "4G"),
        (["id_5g_rrc",   "id_5g_nas"],   "5G"),
    ],
    "IMSI in Paging": [
        ("paging_2g", "2G"),
        ("paging_3g", "3G"),
        ("paging_4g", "4G"),
        ("paging_5g", "5G"),
    ],
    "5G SUCI": [
        ("suci_5g", "5G"),
    ],
    "VoPS": [
        ("vops_4g", "4G"),
        ("vops_5g", "5G"),
        ("sip_ipsec", "SIP IPSec"),
    ],
    "Cap Msg Security": [
        ("ue_cap_security_4g", "4G"),
        ("ue_cap_security_5g", "5G"),
    ],
}
