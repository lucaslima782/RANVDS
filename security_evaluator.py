# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Security evaluator utilities for building and reading the Security ODS."""

from __future__ import annotations

import datetime
import logging
import math
from scipy.special import gammaincc, erfc
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Iterable, Tuple, Set, Optional, Any

from odf.opendocument import load as load_ods
from odf.table import Table, TableRow, TableCell
from odf.text import P
from odf import teletype


# -----------------------------
# Security checker (Crypto)
# -----------------------------

# Weak ciphers by generation/category (labels must match the interpreted names you use elsewhere)
WEAK_2G_VOICE: Set[str] = {"A5/0", "A5/1", "A5/2"}
WEAK_2G_DATA: Set[str] = {"GEA0", "GEA1", "GEA2"}
WEAK_3G: Set[str] = {"UEA0", "UIA0"}
WEAK_4G: Set[str] = {"EEA0", "EIA0"}
WEAK_5G: Set[str] = {"NEA0", "NIA0"}

# Only these tabs should be processed for security analysis
ALLOWED_TABS: Set[str] = {
    "2G CS", "2G PS",
    "3G ENC", "3G INT",
    # 3G split by domain (CS/PS)
    "3G ENC CS", "3G ENC PS",
    "3G INT CS", "3G INT PS",
    "4G RRC ENC", "4G RRC INT",
    "4G NAS ENC", "4G NAS INT",
    "5G RRC ENC", "5G RRC INT",
    "5G NAS ENC", "5G NAS INT",
}


@dataclass
class GenerationSummary:
    """
    Summary of cipher usage for a generation.

    Attributes:
        name (str): Generation label for the row (e.g., "2G CS", "4G RRC ENC").
        changes (int): Number of cipher changes across the sequence.
        counts (Dict[str, int]): Cipher label usage counts.
        weak_in_use (bool): Whether any weak ciphers were used.
    """

    name: str
    changes: int
    counts: Dict[str, int] = field(default_factory=dict)
    weak_in_use: bool = False


@dataclass
class IdentityRecord:
    """
    Identity occurrence extracted from ODS ID sheets.

    Attributes:
        sheet (str): Sheet name where the identity was found.
        timestamp (str): Timestamp of the identity occurrence.
        message (str): Message type associated with the identity.
        id_type (str): Type of the identity (e.g., TMSI, PTMSI, MTMSI, 5G-S-TMSI, NG-5G-S-TMSI, 5G-GUTI).
        id_value (str): Value of the identity.
        domain (str): Domain associated with the identity (optional).
    """

    sheet: str
    timestamp: str
    message: str
    id_type: str
    id_value: str
    domain: str = ""


# Global counters for LUR pairing discards (by Randomness Summary label)
# e.g., "2G CS (TMSI)": int, "3G NAS CS (TMSI)": int
_PAIRING_DISCARDS_BY_LABEL: Dict[str, int] = {}
# Global counters for number of paired candidate messages actually used per label
# This counts message-level pairings (not ID occurrences) to derive total eligible packets
_PAIRING_USED_MSGS_BY_LABEL: Dict[str, int] = {}


def _count_changes(sequence: Iterable[str]) -> int:
    """
    Count how many times the cipher label changes across the sequence (ignoring empty labels).

    Args:
        sequence (Iterable[str]): Cipher labels in chronological order.

    Returns:
        int: Number of cipher changes.
    """
    prev = None
    changes = 0
    for val in sequence:
        if not val:
            continue
        if prev is None:
            prev = val
            continue
        if val != prev:
            changes += 1
            prev = val
    return changes


def _count_occurrences(sequence: Iterable[str]) -> Dict[str, int]:
    """
    Count occurrences of each cipher label in the sequence (ignoring empty labels).

    Args:
        sequence (Iterable[str]): Cipher labels in chronological order.

    Returns:
        Dict[str, int]: Cipher label usage counts.
    """
    counts: Dict[str, int] = {}
    for val in sequence:
        if not val:
            continue
        counts[val] = counts.get(val, 0) + 1
    return counts


def _has_weak(counts: Dict[str, int], weak_set: Set[str]) -> bool:
    """
    Check if any weak ciphers were used.

    Args:
        counts (Dict[str, int]): Cipher label usage counts.
        weak_set (Set[str]): Set of weak cipher labels.

    Returns:
        bool: Whether any weak ciphers were used.
    """
    return any((c in weak_set) and (counts.get(c, 0) > 0) for c in counts.keys())


def _ts_sort_key(ts: str):
    """
    Return a robust sort key for timestamps.

    Attempts ISO parsing, then common formats. Parsed values are prioritized and
    compared by epoch seconds; unparsed values fall back to the original string
    and are placed after parsed ones.

    Args:
        ts (str): Timestamp string.

    Returns:
        Tuple[int, str]: Sort key tuple.
    """
    s = (ts or "").strip()
    if not s:
        return (1, "")
    # Try ISO 8601 (supports 'Z' as UTC)
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso)
        return (0, dt.timestamp())
    except Exception:
        pass
    # Try a few common patterns
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return (0, dt.timestamp())
        except Exception:
            continue
    return (1, s)


def _parse_timestamp_to_epoch(ts: str) -> Optional[float]:
    """
    Parse a timestamp string to epoch seconds if possible; otherwise None.

    Mirrors the formats supported by _ts_sort_key so deduplication is consistent
    with chronological ordering.

    Args:
        ts (str): Timestamp string.

    Returns:
        Optional[float]: Epoch seconds or None.
    """
    s = (ts or "").strip()
    if not s:
        return None
    # Try ISO 8601 (supports 'Z' as UTC)
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso)
        return dt.timestamp()
    except Exception:
        pass
    # Try a few common patterns
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return dt.timestamp()
        except Exception:
            continue
    return None


def compute_crypto_summary(
    name: str,
    used_cipher_sequence: Iterable[str],
    weak_set: Set[str],
) -> GenerationSummary:
    """
    Build a summary for one generation from an ordered sequence of used cipher labels.

    Args:
        name (str): Generation label for the row (e.g., "2G CS", "4G RRC ENC").
        used_cipher_sequence (Iterable[str]): Cipher labels in chronological order.
        weak_set (Set[str]): Set of weak cipher labels for this generation.

    Returns:
        GenerationSummary: Summary of cipher usage for the generation.
    """
    seq = list(used_cipher_sequence)
    counts = _count_occurrences(seq)
    changes = _count_changes(seq)
    weak = _has_weak(counts, weak_set)
    return GenerationSummary(name=name, changes=changes, counts=counts, weak_in_use=weak)


def build_security_ods(output_path: Path, summaries: List[GenerationSummary], identities: List[IdentityRecord] | None = None, paging_stats: Dict[str, Dict[str, int]] | None = None, ts_margin_seconds: float = 0.0, tmsi_thresholds: Dict[str, float] | None = None) -> Path:
    """
    Create an ODS file with a Crypto Summary sheet showing, per generation.

    - number of cipher changes
    - weak cipher used flag
    - usage counts per cipher label observed

    The table will have dynamic columns for each cipher observed across all generations.

    Args:
        output_path (Path): Output file path.
        summaries (List[GenerationSummary]): List of generation summaries.
        identities (List[IdentityRecord] | None): List of identity records (optional).
        paging_stats (Dict[str, Dict[str, int]] | None): Paging statistics (optional).
        ts_margin_seconds (float): Timestamp margin in seconds (optional).
        tmsi_thresholds (Dict[str, float] | None): TMSI thresholds (optional).

    Returns:
        Path: Output file path.
    """
    import table_builder as _tb
    return _tb.build_security_ods(output_path, summaries, identities=identities, paging_stats=paging_stats, ts_margin_seconds=ts_margin_seconds, tmsi_thresholds=tmsi_thresholds)


# -----------------------------
# Helper to generate summaries from already-interpreted "used" series
# -----------------------------

def make_default_crypto_summaries(
    seq_2g_voice: Iterable[str] = (),
    seq_2g_data: Iterable[str] = (),
    seq_3g: Iterable[str] = (),
    seq_4g: Iterable[str] = (),
    seq_5g: Iterable[str] = (),
) -> List[GenerationSummary]:
    """
    Build summaries for common generations.

    Pass in already-interpreted sequences of used cipher labels (chronological).

    Args:
        seq_2g_voice (Iterable[str]): 2G voice cipher sequence (optional).
        seq_2g_data (Iterable[str]): 2G data cipher sequence (optional).
        seq_3g (Iterable[str]): 3G cipher sequence (optional).
        seq_4g (Iterable[str]): 4G cipher sequence (optional).
        seq_5g (Iterable[str]): 5G cipher sequence (optional).

    Returns:
        List[GenerationSummary]: List of generation summaries.
    """
    summaries: List[GenerationSummary] = []
    if seq_2g_voice:
        summaries.append(compute_crypto_summary("2G CS", seq_2g_voice, WEAK_2G_VOICE))
    if seq_2g_data:
        summaries.append(compute_crypto_summary("2G PS", seq_2g_data, WEAK_2G_DATA))
    if seq_3g:
        # Combine ENC/INT for 3G if you provide a unified series; otherwise call compute_crypto_summary separately
        summaries.append(compute_crypto_summary("3G", seq_3g, WEAK_3G))
    if seq_4g:
        summaries.append(compute_crypto_summary("4G", seq_4g, WEAK_4G))
    if seq_5g:
        summaries.append(compute_crypto_summary("5G", seq_5g, WEAK_5G))
    return summaries


# -----------------------------
# Example integration sketch (to be called from VDS.py)
# -----------------------------

def write_crypto_checker_ods(
    output_dir: Path,
    filename_prefix: str,
    sequences_by_gen: Dict[str, Iterable[str]],
    weak_sets_by_gen: Dict[str, Set[str]] | None = None,
    identities: List[IdentityRecord] | None = None,
    paging_stats: Dict[str, Dict[str, int]] | None = None,
    ts_margin_seconds: float = 0.0,
    tmsi_thresholds: Dict[str, float] | None = None,
) -> Path:
    """
    Write the security checker ODS from sequences per generation.

    sequences_by_gen keys (examples):
      - "2G CS", "2G PS"
      - "3G ENC", "3G INT" (unified) or split as "3G ENC CS", "3G ENC PS", "3G INT CS", "3G INT PS"
      - "4G RRC ENC", "4G RRC INT", "4G NAS ENC", "4G NAS INT"
      - "5G RRC ENC", "5G RRC INT", "5G NAS ENC", "5G NAS INT"
    Values: iterables of cipher labels (already interpreted), in chronological order.

    If weak_sets_by_gen is provided, it overrides the default weak sets for the given keys.

    Args:
        output_dir (Path): Output directory.
        filename_prefix (str): Output file name prefix.
        sequences_by_gen (Dict[str, Iterable[str]]): Sequences per generation.
        weak_sets_by_gen (Dict[str, Set[str]] | None): Weak sets per generation (optional).
        identities (List[IdentityRecord] | None): List of identity records (optional).
        paging_stats (Dict[str, Dict[str, int]] | None): Paging statistics (optional).
        ts_margin_seconds (float): Timestamp margin in seconds (optional).
        tmsi_thresholds (Dict[str, float] | None): TMSI thresholds (optional).

    Returns:
        Path: Output file path.
    """
    default_weak_map: Dict[str, Set[str]] = {
        "2G CS": WEAK_2G_VOICE,
        "2G PS": WEAK_2G_DATA,
        # 3G unified
        "3G ENC": WEAK_3G,
        "3G INT": WEAK_3G,
        # 3G split by domain
        "3G ENC CS": WEAK_3G,
        "3G ENC PS": WEAK_3G,
        "3G INT CS": WEAK_3G,
        "3G INT PS": WEAK_3G,
        "4G RRC ENC": WEAK_4G,
        "4G RRC INT": WEAK_4G,
        "4G NAS ENC": WEAK_4G,
        "4G NAS INT": WEAK_4G,
        "5G RRC ENC": WEAK_5G,
        "5G RRC INT": WEAK_5G,
        "5G NAS ENC": WEAK_5G,
        "5G NAS INT": WEAK_5G,
    }

    summaries: List[GenerationSummary] = []
    for gen_name, seq in sequences_by_gen.items():
        weak_set = (weak_sets_by_gen or {}).get(gen_name, default_weak_map.get(gen_name, set()))
        summaries.append(compute_crypto_summary(gen_name, seq, weak_set))

    # Default security report name: <ODS_stem>_Security.ods; ensure uniqueness with numeric suffix
    output_dir = Path(output_dir)
    base = output_dir / f"{filename_prefix}_Security.ods"
    out_path = base
    idx = 2
    while out_path.exists():
        out_path = output_dir / f"{filename_prefix}_Security_{idx}.ods"
        idx += 1
    return build_security_ods(out_path, summaries, identities=identities, paging_stats=paging_stats, ts_margin_seconds=ts_margin_seconds, tmsi_thresholds=tmsi_thresholds)


# -----------------------------
# ODS reader: extract used-cipher sequences per sheet
# -----------------------------

def _get_cell_text(cell) -> str:
    """
    Robustly extract all text from a TableCell, including nested spans.

    Args:
        cell (TableCell): Cell to extract text from.

    Returns:
        str: Extracted text.
    """
    try:
        return teletype.extractText(cell).strip()
    except Exception:
        texts = []
        for n in cell.getElementsByType(P):
            try:
                texts.append(teletype.extractText(n))
            except Exception:
                pass
        return " ".join(t.strip() for t in texts if t and t.strip())


def extract_sequences_from_ods(ods_path: Path, exclude_tabs: List[str] | None = None) -> Dict[str, List[str]]:
    """
    Parse an existing ODS and extract chronological sequences of cipher labels per sheet.

    Requirements:
      - Each processed sheet MUST contain a column named 'Algorithm'. This is the ONLY
        accepted source of used cipher values. No fallbacks are attempted.
      - Tabs listed in exclude_tabs are ignored (e.g., ['Resumo Geral']).
      - Only the allowed tabs defined in ALLOWED_TABS are processed.

    Sheets missing the 'Algorithm' column are skipped and a warning is logged.

    Special handling:
      - For 3G sheets titled '3G ENC' or '3G INT', if a 'Domain' column is present,
        the sequence is split into separate outputs per domain: '... CS' and '... PS'.
        If 'Domain' is absent, the unified title is used (legacy behavior).

    Args:
        ods_path (Path): ODS file path.
        exclude_tabs (List[str] | None): Tabs to exclude (optional).

    Returns:
        Dict[str, List[str]]: Sequences per sheet.
    """
    ods = load_ods(str(ods_path))
    exclude = set(exclude_tabs or [])
    sequences: Dict[str, List[str]] = {}
    # Required header
    required_header = "Algorithm"

    def _interpret_used_for_tab(title: str, raw: str) -> str:
        """
        Map raw used values to human-readable labels per tab.

        If the ODS already contains labels, return as-is. If it contains small
        integers (e.g., 0..3), convert per technology mapping.

        Args:
            title (str): Tab title.
            raw (str): Raw used value.

        Returns:
            str: Human-readable label.
        """
        if raw is None:
            return ""
        s = str(raw).strip()
        if s == "":
            return ""
        # If it already looks like a label (has letters or '/'), keep it
        if any(ch.isalpha() for ch in s) or "/" in s:
            return s
        # Try to parse as int code
        try:
            code = int(s)
        except ValueError:
            return s

        # 2G
        if title == "2G CS":
            return {0: "A5/1", 1: "A5/2", 2: "A5/3", 3: "A5/4"}.get(code, s)
        if title == "2G PS":
            return {0: "GEA0", 1: "GEA1", 2: "GEA2", 3: "GEA3"}.get(code, s)

        # 3G (ENC/INT; allow unified and CS/PS-specific sheet names)
        if title in ("3G ENC", "3G ENC CS", "3G ENC PS"):
            return {0: "UEA0", 1: "UEA1", 2: "UEA2"}.get(code, s)
        if title in ("3G INT", "3G INT CS", "3G INT PS"):
            return {0: "UIA1", 1: "UIA2"}.get(code, s)

        # 4G
        if title in ("4G RRC ENC", "4G NAS ENC"):
            return {0: "EEA0", 1: "128‑EEA1", 2: "128‑EEA2", 3: "128‑EEA3"}.get(code, s)
        if title in ("4G RRC INT", "4G NAS INT"):
            return {0: "EIA0", 1: "128‑EIA1", 2: "128‑EIA2", 3: "128‑EIA3"}.get(code, s)

        # 5G
        if title in ("5G RRC ENC", "5G NAS ENC"):
            return {0: "NEA0", 1: "NEA1", 2: "NEA2", 3: "NEA3"}.get(code, s)
        if title in ("5G RRC INT", "5G NAS INT"):
            return {0: "NIA0", 1: "NIA1", 2: "NIA2", 3: "NIA3"}.get(code, s)

        return s

    for table in ods.spreadsheet.getElementsByType(Table):
        title = table.getAttribute("name") or ""
        # Skip tabs not explicitly allowed
        if title not in ALLOWED_TABS:
            continue
        if title in exclude:
            continue

        # read rows
        rows = table.getElementsByType(TableRow)
        if not rows:
            continue
        # header
        header_cells = rows[0].getElementsByType(TableCell)
        headers = [_get_cell_text(c) for c in header_cells]
        if not headers:
            continue

        # locate 'Algorithm' column; if missing, skip this sheet
        if required_header not in headers:
            logging.warning("Sheet '%s' skipped: missing 'Algorithm' column", title)
            continue
        col_idx = headers.index(required_header)

        # Special split for 3G ENC/INT by Domain when available
        if title in ("3G ENC", "3G INT"):
            dom_idx = headers.index("Domain") if "Domain" in headers else None
            if dom_idx is None:
                # Legacy behavior: no domain column, keep unified sequence
                seq: List[str] = []
                for r in rows[1:]:
                    cells = r.getElementsByType(TableCell)
                    if not cells:
                        continue
                    if col_idx >= len(cells):
                        val = ""
                    else:
                        val = _get_cell_text(cells[col_idx])
                    seq.append(_interpret_used_for_tab(title, val))
                sequences[title] = seq
                continue

            seq_cs: List[str] = []
            seq_ps: List[str] = []
            for r in rows[1:]:
                cells = r.getElementsByType(TableCell)
                if not cells:
                    continue
                # Algorithm value
                if col_idx >= len(cells):
                    val = ""
                else:
                    val = _get_cell_text(cells[col_idx])
                used = _interpret_used_for_tab(title, val)
                # Domain value
                dom_v = _get_cell_text(cells[dom_idx]) if dom_idx < len(cells) else ""
                d = (dom_v or "").strip().upper()
                if d == "CS":
                    seq_cs.append(used)
                elif d == "PS":
                    seq_ps.append(used)
                else:
                    # Unknown/empty domain: ignore row in split view
                    pass
            if seq_cs:
                sequences[f"{title} CS"] = seq_cs
            if seq_ps:
                sequences[f"{title} PS"] = seq_ps
            continue

        # extract sequence from data rows (default behavior)
        seq: List[str] = []
        for r in rows[1:]:
            cells = r.getElementsByType(TableCell)
            if not cells:
                continue
            # pad
            if col_idx >= len(cells):
                val = ""
            else:
                val = _get_cell_text(cells[col_idx])
            seq.append(_interpret_used_for_tab(title, val))

        sequences[title] = seq

    return sequences

# ODS reader: extract identity items from ID tabs (Accept messages only)
# -----------------------------

def extract_ids_from_ods(ods_path: Path) -> List[IdentityRecord]:
    """
    Parse ID sheets and extract identities for selected messages per generation (RRC ID sheets are ignored).

      - 2G CS ID: Location Updating Request (paired to Location Updating Accept),
                  TMSI Reallocation Command (paired to TMSI Reallocation Complete)
      - 2G PS ID: Attach Accept (paired to Attach Complete),
                  Routing Area Update Accept (paired to Routing Area Update Complete),
                  P-TMSI Reallocation Command (paired to P-TMSI Reallocation Complete)
      - 3G NAS ID: PS domain -> Attach Accept (paired), Routing Area Update Accept (paired),
                                 P-TMSI Reallocation Command (paired);
                   CS domain -> Location Updating Request (paired), TMSI Reallocation Command (paired)
      - 4G NAS ID: Attach Accept (paired to Attach Complete),
                   Tracking Area Update Accept (paired to Tracking Area Update Complete),
                   GUTI Reallocation Command (paired to GUTI Reallocation Complete)
      - 5G NAS ID: Registration Accept (paired to Registration Complete)

    Only candidate messages that can be paired to their confirmation (closest preceding by
    Timestamp when parseable, else by Frame number, else by row index) are included and
    written to IDs Messages. Unpaired candidates are discarded but counted per category.

    Consider the following ID types (case/format-insensitive):
      - TMSI, PTMSI, MTMSI, 5G-S-TMSI, NG-5G-S-TMSI, 5G-GUTI

    Notes:
      - Skip any 'Paging' sheets.
      - Handle variants where columns are 'ID Type'+'ID', or 'ID Type 1'/'ID1' and 'ID Type 2'/'ID2'.
      - All candidate messages listed above are only included if paired to their corresponding
        confirmation message. Pairing picks the closest preceding candidate relative to each
        confirmation by Timestamp when parseable, else by Frame, else by row index.

    Args:
        ods_path (Path): ODS file path.

    Returns:
        List[IdentityRecord]: List of identity records.
    """
    ods = load_ods(str(ods_path))
    # Reset pairing discard counters for this extraction run
    try:
        _PAIRING_DISCARDS_BY_LABEL.clear()
    except Exception:
        pass
    # Reset used message counters as well
    try:
        _PAIRING_USED_MSGS_BY_LABEL.clear()
    except Exception:
        pass

    def canon_msg(s: str) -> str:
        return (s or "").upper().replace(" ", "").replace("-", "")

    # Allowed messages per sheet (canonicalized) for any fallback generic handling
    MSG = {
        "2G CS ID": {"LOCATIONUPDATINGREQUEST", "TMSIREALLOCATIONCOMMAND"},
        "2G PS ID": {"ATTACHACCEPT", "PTMSIREALLOCATIONCOMMAND", "ROUTINGAREAUPDATEACCEPT"},
        # 3G NAS handled separately due to domain
        "4G NAS ID": {"ATTACHACCEPT", "TRACKINGAREAUPDATEACCEPT"},
        "5G NAS ID": {"REGISTRATIONACCEPT"},
    }

    def canon_id_type(s: str) -> str:
        t = (s or "").upper().replace(" ", "").replace("_", "").replace("-", "")
        if "NG5GSTMSI" in t:
            return "NG-5G-S-TMSI"
        if "5GSTMSI" in t:
            return "5G-S-TMSI"
        if "5GGUTI" in t:
            return "5G-GUTI"
        if "GUTI" in t:
            return "GUTI"
        if "PTMSI" in t or "PTMSI" in t:
            return "PTMSI"
        if "MTMSI" in t:
            return "MTMSI"
        # Make sure plain TMSI does not catch 5G-S-TMSI
        if "TMSI" in t and "5G" not in t:
            return "TMSI"
        return s

    allowed_types = {"TMSI", "PTMSI", "MTMSI", "GUTI", "5G-S-TMSI", "NG-5G-S-TMSI", "5G-GUTI"}

    def get_text(cell) -> str:
        try:
            return teletype.extractText(cell).strip()
        except Exception:
            return ""

    id_records: List[IdentityRecord] = []

    def _parse_frame_num(s: str) -> Optional[int]:
        try:
            v = (s or "").strip()
            return int(v) if v and v.isdigit() else None
        except Exception:
            return None

    for table in ods.spreadsheet.getElementsByType(Table):
        title = table.getAttribute("name") or ""
        if "PAGING" in title.upper():
            continue
        # Only look at explicit ID sheets and skip any RRC ID sheets from security evaluation
        if "RRC ID" in title.upper():
            continue
        if not title.upper().endswith(" ID") and " NAS ID" not in title.upper():
            # Only look at explicit ID sheets
            continue

        rows = table.getElementsByType(TableRow)
        if not rows:
            continue
        headers = [get_text(c) for c in rows[0].getElementsByType(TableCell)]
        if not headers:
            continue
        hmap = {h: i for i, h in enumerate(headers)}
        # Common columns
        ts_idx = hmap.get("Timestamp")
        frame_idx = hmap.get("Frame")
        msg_idx = hmap.get("Message")
        dom_idx = hmap.get("Domain")
        # ID columns variants
        idtype_idx = hmap.get("ID Type")
        id_idx = hmap.get("ID")
        idtype1_idx = hmap.get("ID Type 1")
        id1_idx = hmap.get("ID1")
        idtype2_idx = hmap.get("ID Type 2")
        id2_idx = hmap.get("ID2")
        idp1_idx = hmap.get("ID Part 1")
        idp2_idx = hmap.get("ID Part 2")

        tu = (title or "").upper()
        special_2g_cs = (tu == "2G CS ID")
        special_2g_ps = (tu == "2G PS ID")
        special_3g = (tu == "3G NAS ID")
        special_4g_nas = (tu == "4G NAS ID")
        special_5g_nas = (tu == "5G NAS ID")

        # Accumulators for special pairing
        # 2G/3G CS (Location Updating and TMSI Reallocation)
        lur_rows: List[Dict[str, Any]] = []                 # candidate: LUR Request
        lur_accept_rows: List[Dict[str, Any]] = []          # confirm: LUR Accept
        tmsi_cmd_rows: List[Dict[str, Any]] = []            # candidate: TMSI/PTMSI/GUTI Realloc Command
        tmsi_cpl_rows: List[Dict[str, Any]] = []            # confirm: Realloc Complete

        # Per-technology/domain PS/NAS candidates and confirmations
        attach_acc_rows: List[Dict[str, Any]] = []          # candidate: Attach Accept
        attach_cpl_rows: List[Dict[str, Any]] = []          # confirm: Attach Complete
        rau_acc_rows: List[Dict[str, Any]] = []             # candidate: RAU/TAU Accept
        rau_cpl_rows: List[Dict[str, Any]] = []             # confirm: RAU/TAU Complete
        reg_acc_rows: List[Dict[str, Any]] = []             # candidate: Registration Accept (5G)
        reg_cpl_rows: List[Dict[str, Any]] = []             # confirm: Registration Complete (5G)

        # 3G NAS split collectors
        lur_rows_cs: List[Dict[str, Any]] = []
        lur_accept_rows_cs: List[Dict[str, Any]] = []
        tmsi_cmd_rows_cs: List[Dict[str, Any]] = []
        tmsi_cpl_rows_cs: List[Dict[str, Any]] = []
        attach_acc_rows_ps: List[Dict[str, Any]] = []
        attach_cpl_rows_ps: List[Dict[str, Any]] = []
        rau_acc_rows_ps: List[Dict[str, Any]] = []
        rau_cpl_rows_ps: List[Dict[str, Any]] = []
        ptmsi_cmd_rows_ps: List[Dict[str, Any]] = []
        ptmsi_cpl_rows_ps: List[Dict[str, Any]] = []

        # Generic (non-special) processing collector (fallback)
        generic_outputs: List[IdentityRecord] = []

        # Helper to extract up to two (type, value) pairs from a row
        def extract_row_id_pairs(cells) -> List[Tuple[str, str]]:
            pairs: List[Tuple[str, str]] = []
            # Single ID Type + ID (or ID1 fallback)
            if idtype_idx is not None and idtype_idx < len(cells):
                t = get_text(cells[idtype_idx])
                canon = canon_id_type(t)
                if canon in allowed_types:
                    if canon == "NG-5G-S-TMSI" and idp1_idx is not None and idp2_idx is not None and idp1_idx < len(cells) and idp2_idx < len(cells):
                        idv = f"{get_text(cells[idp1_idx])}"
                    else:
                        if id_idx is not None and id_idx < len(cells):
                            idv = get_text(cells[id_idx])
                        elif id1_idx is not None and id1_idx < len(cells):
                            idv = get_text(cells[id1_idx])
                        else:
                            idv = ""
                    if idv:
                        pairs.append((canon, idv))
            # Dual pairs (1 and 2)
            for (t_idx, v_idx) in ((idtype1_idx, id1_idx), (idtype2_idx, id2_idx)):
                if t_idx is None or t_idx >= len(cells):
                    continue
                t = get_text(cells[t_idx])
                canon = canon_id_type(t)
                if canon in allowed_types and v_idx is not None and v_idx < len(cells):
                    idv = get_text(cells[v_idx])
                    if idv:
                        pairs.append((canon, idv))
            return pairs

        # Iterate data rows
        for row_idx, r in enumerate(rows[1:]):
            cells = r.getElementsByType(TableCell)
            if not cells:
                continue
            ts = get_text(cells[ts_idx]) if ts_idx is not None and ts_idx < len(cells) else ""
            fr = get_text(cells[frame_idx]) if frame_idx is not None and frame_idx < len(cells) else ""
            frame_no = _parse_frame_num(fr)
            ep = _parse_timestamp_to_epoch(ts)
            msg = get_text(cells[msg_idx]) if msg_idx is not None and msg_idx < len(cells) else ""
            dom = get_text(cells[dom_idx]) if dom_idx is not None and dom_idx < len(cells) else ""

            cm = canon_msg(msg)
            dcanon = (dom or "").strip().upper()

            # Decide behavior per sheet/domain
            if special_2g_cs:
                # We need to see Accepts for pairing, even if we don't output them directly
                if cm == "LOCATIONUPDATINGACCEPT":
                    lur_accept_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                if cm == "LOCATIONUPDATINGREQUEST":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        lur_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "TMSIREALLOCATIONCOMMAND":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        tmsi_cmd_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "TMSIREALLOCATIONCOMPLETE":
                    tmsi_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                # Ignore other messages on this sheet
                continue

            if special_2g_ps:
                # 2G PS: Attach/RAU Accept and PTMSI Realloc Command, paired to their Completes
                if cm == "ATTACHACCEPT":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        attach_acc_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "ROUTINGAREAUPDATEACCEPT":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        rau_acc_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "PTMSIREALLOCATIONCOMMAND":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        tmsi_cmd_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "ATTACHCOMPLETE":
                    attach_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                if cm == "ROUTINGAREAUPDATECOMPLETE":
                    rau_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                if cm == "PTMSIREALLOCATIONCOMPLETE":
                    tmsi_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                # Ignore other messages on this sheet
                continue

            if special_3g:
                # Resolve domain from column or infer from message type if missing
                dom_res = dcanon
                if dom_res not in ("PS", "CS"):
                    if cm in {"ATTACHACCEPT", "ROUTINGAREAUPDATEACCEPT", "PTMSIREALLOCATIONCOMMAND"}:
                        dom_res = "PS"
                    elif cm in {"LOCATIONUPDATINGREQUEST", "TMSIREALLOCATIONCOMMAND"}:
                        dom_res = "CS"
                    else:
                        dom_res = ""
                if dom_res == "PS":
                    # PS domain: collect candidates and confirmations
                    if cm == "ATTACHACCEPT":
                        pairs = extract_row_id_pairs(cells)
                        if pairs:
                            attach_acc_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom_res})
                        continue
                    if cm == "ROUTINGAREAUPDATEACCEPT":
                        pairs = extract_row_id_pairs(cells)
                        if pairs:
                            rau_acc_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom_res})
                        continue
                    if cm == "PTMSIREALLOCATIONCOMMAND":
                        pairs = extract_row_id_pairs(cells)
                        if pairs:
                            ptmsi_cmd_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom_res})
                        continue
                    if cm == "ATTACHCOMPLETE":
                        attach_cpl_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                        continue
                    if cm == "ROUTINGAREAUPDATECOMPLETE":
                        rau_cpl_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                        continue
                    if cm == "PTMSIREALLOCATIONCOMPLETE":
                        ptmsi_cpl_rows_ps.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                        continue
                    # Ignore other PS messages
                    continue
                elif dom_res == "CS":
                    # CS domain: collect LUR and TMSI realloc with confirmations
                    if cm == "LOCATIONUPDATINGACCEPT":
                        lur_accept_rows_cs.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                        continue
                    if cm == "LOCATIONUPDATINGREQUEST":
                        pairs = extract_row_id_pairs(cells)
                        if pairs:
                            lur_rows_cs.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom_res})
                        continue
                    if cm == "TMSIREALLOCATIONCOMMAND":
                        pairs = extract_row_id_pairs(cells)
                        if pairs:
                            tmsi_cmd_rows_cs.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom_res})
                        continue
                    if cm == "TMSIREALLOCATIONCOMPLETE":
                        tmsi_cpl_rows_cs.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                        continue
                    # Ignore other CS messages
                    continue
                else:
                    # Unknown domain even after inference: ignore row
                    continue

            if special_4g_nas:
                # 4G NAS: Attach/TAU Accept and GUTI Realloc Command, paired to their Completes
                if cm == "ATTACHACCEPT":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        attach_acc_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "TRACKINGAREAUPDATEACCEPT":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        rau_acc_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "GUTIREALLOCATIONCOMMAND":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        tmsi_cmd_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "ATTACHCOMPLETE":
                    attach_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                if cm == "TRACKINGAREAUPDATECOMPLETE":
                    rau_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                if cm == "GUTIREALLOCATIONCOMPLETE":
                    tmsi_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                # Ignore other messages on this sheet
                continue

            if special_5g_nas:
                # 5G NAS: Registration Accept paired to Registration Complete
                if cm == "REGISTRATIONACCEPT":
                    pairs = extract_row_id_pairs(cells)
                    if pairs:
                        reg_acc_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx, "pairs": pairs, "msg": msg, "dom": dom})
                    continue
                if cm == "REGISTRATIONCOMPLETE":
                    reg_cpl_rows.append({"ts": ts, "ep": ep, "frame": frame_no, "row": row_idx})
                    continue
                # Ignore other messages on this sheet
                continue

            # Non-special sheets: use existing allow list
            allowed = MSG.get(tu, set())
            if cm not in allowed:
                continue
            pairs = extract_row_id_pairs(cells)
            for (idt, idv) in pairs:
                generic_outputs.append(IdentityRecord(sheet=title, timestamp=ts, domain=dom, message=msg, id_type=idt, id_value=idv))

        # Finalize for this sheet: apply pairing if needed, then extend id_records
        def _select_requests_for_accepts(accs: List[Dict[str, Any]], reqs: List[Dict[str, Any]]) -> Tuple[List[IdentityRecord], Set[int]]:
            # Map each accept to the closest preceding request; avoid adding the same request twice
            out: List[IdentityRecord] = []
            used_req_rows: Set[int] = set()
            # Sort accepts chronologically by timestamp sort key as a stable ordering
            accs_sorted = sorted(accs, key=lambda a: (0, a["ep"]) if a.get("ep") is not None else (1, a.get("ts", "")))
            for acc in accs_sorted:
                best = None
                best_key = None
                for req in reqs:
                    # Preceding condition by epoch, else by frame, else by row index
                    if acc.get("ep") is not None and req.get("ep") is not None:
                        if req["ep"] > acc["ep"]:
                            continue
                        delta = acc["ep"] - req["ep"]
                        key = (0, delta)
                    elif acc.get("frame") is not None and req.get("frame") is not None:
                        if req["frame"] > acc["frame"]:
                            continue
                        delta = acc["frame"] - req["frame"]
                        key = (1, float(delta))
                    else:
                        if req["row"] > acc["row"]:
                            continue
                        delta = acc["row"] - req["row"]
                        key = (2, float(delta))
                    if best is None or key < best_key:
                        best = req
                        best_key = key
                if best is not None and best["row"] not in used_req_rows:
                    used_req_rows.add(best["row"])
                    for (idt, idv) in best.get("pairs", []):
                        out.append(IdentityRecord(sheet=title, timestamp=best.get("ts", ""), domain=best.get("dom", ""), message=best.get("msg", ""), id_type=idt, id_value=idv))
            return out, used_req_rows

        # Apply pairing per special sheet/domain and aggregate discards by Randomness Summary label
        if special_2g_cs:
            # LUR: Request -> Accept
            paired_lur_2g, used_lur_2g = _select_requests_for_accepts(lur_accept_rows, lur_rows)
            id_records.extend(paired_lur_2g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["2G CS (TMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("2G CS (TMSI)", 0) + max(0, len(lur_rows) - len(used_lur_2g))
                _PAIRING_USED_MSGS_BY_LABEL["2G CS (TMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("2G CS (TMSI)", 0) + len(used_lur_2g)
            except Exception:
                pass
            # TMSI Realloc: Command -> Complete
            paired_tmsi_2g, used_tmsi_2g = _select_requests_for_accepts(tmsi_cpl_rows, tmsi_cmd_rows)
            id_records.extend(paired_tmsi_2g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["2G CS (TMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("2G CS (TMSI)", 0) + max(0, len(tmsi_cmd_rows) - len(used_tmsi_2g))
                _PAIRING_USED_MSGS_BY_LABEL["2G CS (TMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("2G CS (TMSI)", 0) + len(used_tmsi_2g)
            except Exception:
                pass

        if special_2g_ps:
            # Attach Accept -> Attach Complete
            paired_att_2g, used_att_2g = _select_requests_for_accepts(attach_cpl_rows, attach_acc_rows)
            id_records.extend(paired_att_2g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("2G PS (PTMSI)", 0) + max(0, len(attach_acc_rows) - len(used_att_2g))
                _PAIRING_USED_MSGS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("2G PS (PTMSI)", 0) + len(used_att_2g)
            except Exception:
                pass
            # RAU Accept -> RAU Complete
            paired_rau_2g, used_rau_2g = _select_requests_for_accepts(rau_cpl_rows, rau_acc_rows)
            id_records.extend(paired_rau_2g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("2G PS (PTMSI)", 0) + max(0, len(rau_acc_rows) - len(used_rau_2g))
                _PAIRING_USED_MSGS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("2G PS (PTMSI)", 0) + len(used_rau_2g)
            except Exception:
                pass
            # PTMSI Realloc: Command -> Complete
            paired_pt_2g, used_pt_2g = _select_requests_for_accepts(tmsi_cpl_rows, tmsi_cmd_rows)
            id_records.extend(paired_pt_2g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("2G PS (PTMSI)", 0) + max(0, len(tmsi_cmd_rows) - len(used_pt_2g))
                _PAIRING_USED_MSGS_BY_LABEL["2G PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("2G PS (PTMSI)", 0) + len(used_pt_2g)
            except Exception:
                pass

        if special_3g:
            # CS domain: LUR Request -> Accept
            paired_lur_3g_cs, used_lur_3g_cs = _select_requests_for_accepts(lur_accept_rows_cs, lur_rows_cs)
            id_records.extend(paired_lur_3g_cs)
            try:
                _PAIRING_DISCARDS_BY_LABEL["3G NAS CS (TMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("3G NAS CS (TMSI)", 0) + max(0, len(lur_rows_cs) - len(used_lur_3g_cs))
                _PAIRING_USED_MSGS_BY_LABEL["3G NAS CS (TMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("3G NAS CS (TMSI)", 0) + len(used_lur_3g_cs)
            except Exception:
                pass
            # CS domain: TMSI Realloc Command -> Complete
            paired_tmsi_3g_cs, used_tmsi_3g_cs = _select_requests_for_accepts(tmsi_cpl_rows_cs, tmsi_cmd_rows_cs)
            id_records.extend(paired_tmsi_3g_cs)
            try:
                _PAIRING_DISCARDS_BY_LABEL["3G NAS CS (TMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("3G NAS CS (TMSI)", 0) + max(0, len(tmsi_cmd_rows_cs) - len(used_tmsi_3g_cs))
                _PAIRING_USED_MSGS_BY_LABEL["3G NAS CS (TMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("3G NAS CS (TMSI)", 0) + len(used_tmsi_3g_cs)
            except Exception:
                pass
            # PS domain: Attach/RAU Accept -> Complete
            paired_att_3g_ps, used_att_3g_ps = _select_requests_for_accepts(attach_cpl_rows_ps, attach_acc_rows_ps)
            id_records.extend(paired_att_3g_ps)
            try:
                _PAIRING_DISCARDS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + max(0, len(attach_acc_rows_ps) - len(used_att_3g_ps))
                _PAIRING_USED_MSGS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + len(used_att_3g_ps)
            except Exception:
                pass
            paired_rau_3g_ps, used_rau_3g_ps = _select_requests_for_accepts(rau_cpl_rows_ps, rau_acc_rows_ps)
            id_records.extend(paired_rau_3g_ps)
            try:
                _PAIRING_DISCARDS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + max(0, len(rau_acc_rows_ps) - len(used_rau_3g_ps))
                _PAIRING_USED_MSGS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + len(used_rau_3g_ps)
            except Exception:
                pass
            # PS domain: PTMSI Realloc Command -> Complete
            paired_pt_3g_ps, used_pt_3g_ps = _select_requests_for_accepts(ptmsi_cpl_rows_ps, ptmsi_cmd_rows_ps)
            id_records.extend(paired_pt_3g_ps)
            try:
                _PAIRING_DISCARDS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + max(0, len(ptmsi_cmd_rows_ps) - len(used_pt_3g_ps))
                _PAIRING_USED_MSGS_BY_LABEL["3G NAS PS (PTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("3G NAS PS (PTMSI)", 0) + len(used_pt_3g_ps)
            except Exception:
                pass

        if special_4g_nas:
            # Attach Accept -> Attach Complete
            paired_att_4g, used_att_4g = _select_requests_for_accepts(attach_cpl_rows, attach_acc_rows)
            id_records.extend(paired_att_4g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("4G NAS (MTMSI)", 0) + max(0, len(attach_acc_rows) - len(used_att_4g))
                _PAIRING_USED_MSGS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("4G NAS (MTMSI)", 0) + len(used_att_4g)
            except Exception:
                pass
            # TAU Accept -> TAU Complete
            paired_tau_4g, used_tau_4g = _select_requests_for_accepts(rau_cpl_rows, rau_acc_rows)
            id_records.extend(paired_tau_4g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("4G NAS (MTMSI)", 0) + max(0, len(rau_acc_rows) - len(used_tau_4g))
                _PAIRING_USED_MSGS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("4G NAS (MTMSI)", 0) + len(used_tau_4g)
            except Exception:
                pass
            # GUTI Realloc: Command -> Complete
            paired_guti_4g, used_guti_4g = _select_requests_for_accepts(tmsi_cpl_rows, tmsi_cmd_rows)
            id_records.extend(paired_guti_4g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("4G NAS (MTMSI)", 0) + max(0, len(tmsi_cmd_rows) - len(used_guti_4g))
                _PAIRING_USED_MSGS_BY_LABEL["4G NAS (MTMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("4G NAS (MTMSI)", 0) + len(used_guti_4g)
            except Exception:
                pass

        if special_5g_nas:
            # Registration Accept -> Registration Complete
            paired_reg_5g, used_reg_5g = _select_requests_for_accepts(reg_cpl_rows, reg_acc_rows)
            id_records.extend(paired_reg_5g)
            try:
                _PAIRING_DISCARDS_BY_LABEL["5G NAS (5G-S-TMSI)"] = _PAIRING_DISCARDS_BY_LABEL.get("5G NAS (5G-S-TMSI)", 0) + max(0, len(reg_acc_rows) - len(used_reg_5g))
                _PAIRING_USED_MSGS_BY_LABEL["5G NAS (5G-S-TMSI)"] = _PAIRING_USED_MSGS_BY_LABEL.get("5G NAS (5G-S-TMSI)", 0) + len(used_reg_5g)
            except Exception:
                pass

        # Always include generic outputs (for any remaining non-special handling)
        id_records.extend(generic_outputs)

    # Ensure identities are in chronological order by Timestamp before returning
    id_records.sort(key=lambda r: _ts_sort_key(r.timestamp))
    return id_records


# -----------------------------
# ODS reader: extract paging stats per generation (messages and IMSI IDs)
# -----------------------------

def extract_paging_from_ods(ods_path: Path) -> Dict[str, Dict[str, int]]:
    """
    Read paging sheets (2G/3G/4G/5G) from an existing ODS and compute.

      - messages: total count of ID entries transmitted (e.g., if a paging row has 3 IDs, count 3)
      - imsi_ids: number of ID entries whose value looks like an IMSI (15-digit value)

    Returns a dict keyed by generation label: {"2G"|"3G"|"4G"|"5G": {"messages": int, "imsi_ids": int}}
    """
    ods = load_ods(str(ods_path))

    def get_text(cell) -> str:
        try:
            return teletype.extractText(cell).strip()
        except Exception:
            return ""

    def is_imsi_value(s: str) -> bool:
        v = (s or "").strip().replace(" ", "")
        # Accept explicit 0x/0X prefix followed by 15 digits
        if v.lower().startswith("0x") and v[2:].isdigit() and len(v[2:]) == 15:
            return True
        # Fallback: any value containing exactly 15 digits overall
        digits = ''.join(ch for ch in v if ch.isdigit())
        return len(digits) == 15

    stats: Dict[str, Dict[str, int]] = {g: {"messages": 0, "imsi_ids": 0} for g in ("2G", "3G", "4G", "5G")}

    for table in ods.spreadsheet.getElementsByType(Table):
        title = (table.getAttribute("name") or "").strip()
        tu = title.upper()
        if tu not in {"2G PAGING", "3G PAGING", "4G PAGING", "5G PAGING"}:
            continue

        # Map to generation key
        gen = title.split()[0] if " " in title else title
        gen = gen.upper().replace("PAGING", "").strip()
        if gen not in ("2G", "3G", "4G", "5G"):
            continue

        rows = table.getElementsByType(TableRow)
        if not rows:
            continue
        headers = [get_text(c) for c in rows[0].getElementsByType(TableCell)]
        hmap = {h: i for i, h in enumerate(headers)}

        # Commonly used indices per sheet type
        if gen == "2G":
            id_idxs = [hmap.get(n) for n in ("ID1", "ID2", "ID3", "ID4")]
            for r in rows[1:]:
                cells = r.getElementsByType(TableCell)
                if not cells:
                    continue
                # Count each non-empty ID value as one paging occurrence
                for idx in id_idxs:
                    if idx is not None and idx < len(cells):
                        val = get_text(cells[idx])
                        if val:
                            stats[gen]["messages"] += 1
                            if is_imsi_value(val):
                                stats[gen]["imsi_ids"] += 1
        elif gen == "3G":
            id_idx = hmap.get("ID")
            for r in rows[1:]:
                cells = r.getElementsByType(TableCell)
                if not cells:
                    continue
                if id_idx is not None and id_idx < len(cells):
                    val = get_text(cells[id_idx])
                    if val:
                        stats[gen]["messages"] += 1
                        if is_imsi_value(val):
                            stats[gen]["imsi_ids"] += 1
        elif gen == "4G":
            id_idxs = [hmap.get(n) for n in ("ID1", "ID2", "ID3", "ID4", "ID5")]
            for r in rows[1:]:
                cells = r.getElementsByType(TableCell)
                if not cells:
                    continue
                for v_idx in id_idxs:
                    if v_idx is not None and v_idx < len(cells):
                        val = get_text(cells[v_idx])
                        if val:
                            stats[gen]["messages"] += 1
                            if is_imsi_value(val):
                                stats[gen]["imsi_ids"] += 1
        elif gen == "5G":
            id_idx = hmap.get("ID")
            for r in rows[1:]:
                cells = r.getElementsByType(TableCell)
                if not cells:
                    continue
                if id_idx is not None and id_idx < len(cells):
                    val = get_text(cells[id_idx])
                    if val:
                        stats[gen]["messages"] += 1
                        if is_imsi_value(val):
                            stats[gen]["imsi_ids"] += 1

    return stats


# -----------------------------
# 4G TMSI randomness analysis (from IDs Messages)
# -----------------------------

def _normalize_hex_value(s: str, width: int = 8) -> str:
    """Normalize an ID string assumed to be HEX.

    - strips optional 0x/0X prefix
    - validates hex-only chars
    - lowercases
    - left-pads with zeros to 'width' hex digits if shorter (no truncation if longer)
    Returns empty string if invalid.
    """
    if s is None:
        return ""
    v = str(s).strip()
    if v.startswith(("0x", "0X")):
        v = v[2:]
    if not v:
        return ""
    if not all(ch in '0123456789abcdefABCDEF' for ch in v):
        return s
    hx = v.lower()
    if width and len(hx) < width:
        hx = hx.zfill(width)
    return hx


def _shannon_entropy(counts: Dict[Any, int]) -> float:
    """Plug-in (MLE) Shannon entropy in bits over an empirical histogram.
    
    Calculates H(X) = -Σ p(x) * log₂(p(x)) where p(x) is the empirical probability.
    Higher entropy indicates more randomness (max = log₂(n) for n unique values).
    """
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    # Sum over all observed values
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total  # Empirical probability
        h -= p * math.log2(p)  # Shannon entropy formula
    return h

def _miller_madow_correction(counts: Dict[Any, int]) -> float:
    """Miller–Madow bias correction term (add to plug-in entropy) in bits.
    
    For finite samples, raw Shannon entropy underestimates true entropy.
    This correction term compensates for the bias: (U - 1) / (2N * ln(2))
    where U = number of unique values, N = total samples.
    """
    N = sum(counts.values())  # Total sample count
    if N <= 0:
        return 0.0
    U = sum(1 for c in counts.values() if c > 0)  # Unique value count
    # Apply Miller-Madow correction formula
    return ((U - 1) / (2.0 * N)) / math.log(2.0)

def _min_entropy(counts: Dict[Any, int]) -> float:
    """Min-entropy H_inf = -log2(max_i p_i)."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    p_max = max(c for c in counts.values()) / total
    if p_max <= 0:
        return 0.0
    return -math.log2(p_max)

def _norm_entropy(h_bits: float, num_effective_bins: Optional[int]) -> float:
    """Normalize entropy to [0,1] by dividing by log2(K), K=effective bins."""
    if num_effective_bins is None or num_effective_bins <= 1:
        return 0.0
    denom = math.log2(num_effective_bins)
    if denom <= 0:
        return 0.0
    return min(1.0, max(0.0, h_bits / denom))

def _phi_sf(z: float) -> float:
    """Standard normal survival function 1 - Φ(z) (Gaussian Q-function).

    Uses SciPy's complementary error function via the identity
    1 - Φ(z) = 0.5 * erfc(z / √2).
    """
    # 1 - Phi(z) = 0.5 * erfc(z / sqrt(2))
    return float(0.5 * erfc(z / math.sqrt(2.0)))

def _gamma_inc_Q(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) = Γ(a, x) / Γ(a).

    Delegates to SciPy's ``gammaincc(a, x)``, which already returns the
    regularized upper incomplete gamma function Q(a, x). Results are
    clamped to [0, 1] for numerical robustness.
    """
    if a <= 0.0:
        return 1.0
    if x <= 0.0:
        return 1.0
    q = float(gammaincc(a, x))
    if q < 0.0:
        q = 0.0
    elif q > 1.0:
        q = 1.0
    return q

def _chi2_sf_wh(x: float, k: int) -> float:
    """Chi-square survival function via regularized incomplete gamma Q.

    For X ~ χ²_k, P(X ≥ x) = Q(k/2, x/2). This wrapper centralizes
    all chi-square p-value calculations so that changes to the underlying
    implementation (SciPy ``gammaincc``) happen in one place.
    """
    if x < 0 or k <= 0:
        return 1.0
    a = 0.5 * float(k)
    xx = 0.5 * float(x)
    return _gamma_inc_Q(a, xx)

def _fisher_combine_pvalues(pvals):
    """Combine independent p-values using Fisher's method.

    Given a sequence of p-values {p_i}, computes

        X = -2 * sum(log(p_i_clipped))  ~  2_{2k}

    where k is the number of valid p-values. Extremely small p-values
    are clipped to a tiny positive epsilon to avoid log(0) while still
    contributing a very large X. Returns (X, df, combined_p).
    """
    # Keep only finite p-values at or below 1.0 (NaNs/None are ignored).
    valid_raw = [p for p in pvals if p is not None and p <= 1.0]
    if not valid_raw:
        return 0.0, 0, None
    eps = 1e-308
    clipped = []
    for p in valid_raw:
        if p is None:
            continue
        # Clip to [eps, 1.0] to avoid log(0) and p>1 artifacts while
        # ensuring very small p still contribute strongly.
        if p <= 0.0:
            p = eps
        elif p > 1.0:
            p = 1.0
        clipped.append(p)
    if not clipped:
        return 0.0, 0, None
    # Fisher statistic and corresponding chi-square df and survival p-value.
    stat = -2.0 * sum(math.log(p) for p in clipped)
    df = 2 * len(clipped)
    return stat, df, _chi2_sf_wh(stat, df)

def compute_tmsi_randomness(records: List["IdentityRecord"], nibble_width: int = 8) -> Dict[str, Any]:
    """Compute randomness metrics for TMSI/PTMSI/MTMSI/5G-STMSI.

    Returns (concise core set):
      - samples, unique
      - collision_rate (reuse rate)
      - H_values_bits (plug-in), H_values_bits_mm (Miller–Madow corrected), H_values_norm
      - chi2_nibbles, chi2_nibbles_df, chi2_nibbles_p  # across all nibbles (16 bins, on UNIQUE IDs)
      - nibble_hist                                   # counts across all positions (UNIQUE IDs)
      - msb_hist, chi2_msb, chi2_msb_df, chi2_msb_p    # first nibble per UNIQUE value
      - lsn_hist, chi2_lsn, chi2_lsn_df, chi2_lsn_p    # last nibble per UNIQUE value
      - succ_hd_pairs, succ_hd_wbits, succ_hd_mean, succ_hd_mean_frac, succ_hd_z, succ_hd_p  # successive Hamming distance (UNIQUE, time-ordered)
    """
    # Normalize to hex strings (already hex; pad to fixed width)
    vals: List[str] = []
    for r in records:
        hx = _normalize_hex_value(r.id_value, width=nibble_width)  # your existing helper
        if hx:
            vals.append(hx)

    samples = len(vals)
    value_counts: Dict[str, int] = Counter(vals)
    unique = len(value_counts)
    collisions = max(0, samples - unique)
    collision_rate = (collisions / samples) if samples > 0 else 0.0
    # Use unique identifiers for chi-square analyses to maintain independence
    # vals_unique: List[str] = list(value_counts.keys())
    # Preserve the chronological order of FIRST appearance
    seen: Set[str] = set()
    vals_unique: List[str] = []
    for hx in vals:
        if hx not in seen:
            seen.add(hx)
            vals_unique.append(hx)

    # --- Full-value entropy family
    H_values_bits = _shannon_entropy(value_counts)
    H_values_bits_mm = H_values_bits + _miller_madow_correction(value_counts)
    # Normalize by log2(U) so results are comparable across sessions
    H_values_norm = _norm_entropy(H_values_bits, unique)

    # --- Nibble stats (0..F) across all nibbles of UNIQUE values
    nibble_list = [ch.upper() for hx in vals_unique for ch in hx if ch in '0123456789abcdefABCDEF']
    nibble_counts: Dict[str, int] = {d: 0 for d in "0123456789ABCDEF"}
    for ch in nibble_list:
        if ch in nibble_counts:
            nibble_counts[ch] += 1

    total_nibbles = sum(nibble_counts.values())
    chi2_nibbles = 0.0
    chi2_nibbles_df = 0
    chi2_nibbles_p = None
    if total_nibbles > 0 and vals_unique:
        width_nibbles_for_chi = nibble_width if (nibble_width and nibble_width > 0) else max((len(h) for h in vals_unique), default=0)
        if width_nibbles_for_chi > 0:
            per_pos_p = []
            for pos in range(width_nibbles_for_chi):
                pos_counts: Dict[str, int] = {d: 0 for d in "0123456789ABCDEF"}
                for hx in vals_unique:
                    if pos < len(hx):
                        d = hx[pos].upper()
                        if d in pos_counts:
                            pos_counts[d] += 1
                total_pos = sum(pos_counts.values())
                if total_pos <= 0:
                    continue
                exp_pos = total_pos / 16.0
                if exp_pos <= 0:
                    continue
                chi2_pos = 0.0
                for d in "0123456789ABCDEF":
                    o = pos_counts.get(d, 0)
                    chi2_pos += (o - exp_pos) ** 2 / exp_pos
                per_pos_p.append(_chi2_sf_wh(chi2_pos, 15))
            chi2_nibbles, chi2_nibbles_df, chi2_nibbles_p = _fisher_combine_pvalues(per_pos_p)

    # --- First nibble (MSB) histogram and chi-square (one per UNIQUE value)
    msb_counts: Dict[str, int] = {d: 0 for d in "0123456789ABCDEF"}
    for hx in vals_unique:
        d0 = hx[0].upper()
        if d0 in msb_counts:
            msb_counts[d0] += 1
    total_msb = sum(msb_counts.values())
    chi2_msb = 0.0
    chi2_msb_df = 15
    if total_msb > 0:
        exp_msb = total_msb / 16.0
        if exp_msb > 0:
            for d in "0123456789ABCDEF":
                o = msb_counts.get(d, 0)
                chi2_msb += (o - exp_msb) ** 2 / exp_msb
    chi2_msb_p = _chi2_sf_wh(chi2_msb, chi2_msb_df) if total_msb > 0 else None

    # --- Last nibble (LSB) histogram and chi-square (one per UNIQUE value)
    lsn_counts: Dict[str, int] = {d: 0 for d in "0123456789ABCDEF"}
    for hx in vals_unique:
        d = hx[-1].upper()
        if d in lsn_counts:
            lsn_counts[d] += 1
    total_lsn = sum(lsn_counts.values())
    chi2_lsn = 0.0
    chi2_lsn_df = 15
    if total_lsn > 0:
        exp_lsn = total_lsn / 16.0
        if exp_lsn > 0:
            for d in "0123456789ABCDEF":
                o = lsn_counts.get(d, 0)
                chi2_lsn += (o - exp_lsn) ** 2 / exp_lsn
    chi2_lsn_p = _chi2_sf_wh(chi2_lsn, chi2_lsn_df) if total_lsn > 0 else None

    # --- Successive Hamming distance (unique, ordered)
    # Determine bit width from configured nibble_width or max observed unique length
    width_nibbles = nibble_width if (nibble_width and nibble_width > 0) else (max((len(h) for h in vals_unique), default=0))
    wbits = width_nibbles * 4 if width_nibbles else 0
    succ_pairs = 0
    succ_mean = None
    succ_mean_frac = None
    succ_z = None
    succ_p = None
    if wbits > 0 and len(vals_unique) >= 2:
        # Left-pad to common width for fair bitwise comparison
        vu_pad = [h.zfill(width_nibbles) for h in vals_unique]
        dists: List[int] = []
        for i in range(1, len(vu_pad)):
            try:
                a = int(vu_pad[i-1], 16)
                b = int(vu_pad[i], 16)
            except ValueError:
                # Skip pairs with non-hex characters just in case
                continue
            d = (a ^ b).bit_count()
            dists.append(d)
        succ_pairs = len(dists)
        if succ_pairs > 0:
            # d_t: normalized Hamming distance for each successive pair (fraction of differing bits)
            d_norm = [d / wbits for d in dists]
            succ_mean_frac = sum(d_norm) / succ_pairs  # \bar{d}
            succ_mean = succ_mean_frac * wbits         # mean number of differing bits
            # Under H0: E[d_t] = 1/2, Var(d_t) = 1/(4 * wbits);
            # Var(\bar{d}) = 1 / (4 * wbits * succ_pairs)
            var_mean_frac = 0.25 / (wbits * succ_pairs)
            if var_mean_frac > 0:
                succ_z = (succ_mean_frac - 0.5) / math.sqrt(var_mean_frac)
                succ_p = min(1.0, 2.0 * _phi_sf(abs(succ_z)))

    return {
        # Core
        "samples": samples,
        "unique": unique,
        "collision_rate": collision_rate,

        # Value-level entropy
        "H_values_bits": H_values_bits,
        "H_values_bits_mm": H_values_bits_mm,
        "H_values_norm": H_values_norm,

        # Overall nibble chi-square
        "chi2_nibbles": chi2_nibbles,
        "chi2_nibbles_df": chi2_nibbles_df,
        "chi2_nibbles_p": chi2_nibbles_p,

        # All nibbles histogram (across all positions)
        "nibble_hist": nibble_counts,

        # MSB nibble analysis
        "msb_hist": msb_counts,
        "chi2_msb": chi2_msb,
        "chi2_msb_df": chi2_msb_df,
        "chi2_msb_p": chi2_msb_p,

        # LSB nibble analysis
        "lsn_hist": lsn_counts,
        "chi2_lsn": chi2_lsn,
        "chi2_lsn_df": chi2_lsn_df,
        "chi2_lsn_p": chi2_lsn_p,

        # Successive Hamming distance (unique, ordered)
        "succ_hd_pairs": succ_pairs,
        "succ_hd_wbits": wbits,
        "succ_hd_mean": succ_mean,
        "succ_hd_mean_frac": succ_mean_frac,
        "succ_hd_z": succ_z,
        "succ_hd_p": succ_p,
    }

# Backwards-compatible wrapper used by report builders
def compute_id_randomness(records: List["IdentityRecord"], nibble_width: int = 8) -> Dict[str, Any]:
    """Compute randomness metrics for IDs (backward-compatible wrapper).

    Delegates to `compute_tmsi_randomness` with the same parameters.
    """
    return compute_tmsi_randomness(records, nibble_width=nibble_width)
