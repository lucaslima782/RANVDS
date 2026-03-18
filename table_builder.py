# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""ODS table building utilities for RANVDS."""

from __future__ import annotations
import datetime
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow, TableCell
from odf.text import P
from odf.style import Style, TextProperties
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Iterable, Tuple, Set
import re

def interpret_value(name: str, raw: str) -> str:
    """Convert a raw capability value to a human-readable label.

    Rules:
    - For field "GSM_A5/1", the value 'False' indicates the algorithm is supported ("YES");
      any other value indicates it is not supported ("NO").
    - For other fields, the value 'True' represents support ("YES"); anything else is "NO".

    Args:
        name (str): Logical field name (e.g., "GSM_A5/1").
        raw (str): Raw value extracted from tshark.

    Returns:
        str: "YES", "NO" or "NOT FOUND" (if the field is missing).
    """
    # If no value, return "NOT FOUND"
    if not raw:
        return "NOT FOUND"
    # Special case for "GSM_A5/1": logic is inverted
    if name == "GSM_A5/1":
        return "YES" if raw == "False" else "NO"
    # For other fields, 'True' means support
    return "YES" if raw == "True" else "NO"


def interpret_used_value(name: str, raw: str) -> str:
    """Convert the raw 'algorithm in use' value to a label.

    Interpretation depends on the field type:
    - "2G CS": values 0..3 → A5/1..A5/4
    - "2G PS": values 0..3 → GEA0..GEA3
    - "3G C/I": values 0..2 → UEA0..UEA2 and 0..1 → UIA1/UIA2
    - "4G RRC/NAS C/I": values 0..3 → EEA0..EEA3 and EIA0..EIA3

    Args:
        name (str): Logical field name.
        raw (str): Raw value (string with decimal or hexadecimal number).

    Returns:
        str: Algorithm name or "Unknown(<value>)" if not mapped.
             Returns the original value if it cannot be interpreted.
    """
    # If no value, return "NOT FOUND"
    if not raw:
        return "NOT FOUND"
    try:
        # Try to convert the value to integer (accepts decimal and hexadecimal)
        val = int(raw, 0)
    except ValueError:
        # If conversion fails, return original value
        return raw

    # Perform mapping according to field type
    if name == "2G CS C":
        # 0-3 → A5/1 to A5/4
        return {0: "A5/1", 1: "A5/2", 2: "A5/3", 3: "A5/4"}.get(val, f"Unknown({val})")
    if name == "2G PS C":
        # 0-3 → GEA0 to GEA3
        return {0: "GEA0", 1: "GEA1", 2: "GEA2", 3: "GEA3"}.get(val, f"Unknown({val})")
    if name == "3G C":
        # 0-2 → UEA0 to UEA2
        return {0: "UEA0", 1: "UEA1", 2: "UEA2"}.get(val, f"Unknown({val})")
    if name == "3G I":
        # 0-1 → UIA1/UIA2
        return {0: "UIA1", 1: "UIA2"}.get(val, f"Unknown({val})")
    if name == "4G RRC C":
        # 0-3 → EEA0/128‑EEA1/2/3
        return {0: "EEA0", 1: "128‑EEA1", 2: "128‑EEA2", 3: "128‑EEA3"}.get(val, f"Unknown({val})")
    if name == "4G RRC I":
        # 0-3 → EIA0/128‑EIA1/2/3
        return {0: "EIA0", 1: "128‑EIA1", 2: "128‑EIA2", 3: "128‑EIA3"}.get(val, f"Unknown({val})")
    if name == "4G NAS C":
        # 0-3 → EEA0/128‑EEA1/2/3
        return {0: "EEA0", 1: "128‑EEA1", 2: "128‑EEA2", 3: "128‑EEA3"}.get(val, f"Unknown({val})")
    if name == "4G NAS I":
        # 0-3 → EIA0/128‑EIA1/2/3
        return {0: "EIA0", 1: "128‑EIA1", 2: "128‑EIA2", 3: "128‑EIA3"}.get(val, f"Unknown({val})")
    if name == "5G RRC C":
        # 0-3 → NEA0/128‑NEA1/2/3
        return {0: "NEA0", 1: "NEA1", 2: "NEA2", 3: "NEA3"}.get(val, f"Unknown({val})")
    if name == "5G RRC I":
        # 0-3 → NEA0/128‑NEA1/2/3
        return {0: "NIA0", 1: "NIA1", 2: "NIA2", 3: "NIA3"}.get(val, f"Unknown({val})")
    if name == "5G NAS C":
        # 0-3 → NEA0/128‑NEA1/2/3
        return {0: "NEA0", 1: "NEA1", 2: "NEA2", 3: "NEA3"}.get(val, f"Unknown({val})")
    if name == "5G NAS I":
        # 0-3 → NEA0/128‑NEA1/2/3
        return {0: "NIA0", 1: "NIA1", 2: "NIA2", 3: "NIA3"}.get(val, f"Unknown({val})")

    # If no known mapping, return the original value
    return raw

# --- Interpretation functions per sheet ---
def interpret_2g_voz(algo: str) -> str:
    """Map 2G CS algorithm code to label."""
    # 0-3 → A5/1 to A5/4
    mapping = {"0": "A5/1", "1": "A5/2", "2": "A5/3", "3": "A5/4"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_2g_dados(algo: str) -> str:
    """Map 2G PS algorithm code to label."""
    # 0-3 → GEA0 to GEA3
    mapping = {"0": "GEA0", "1": "GEA1", "2": "GEA2", "3": "GEA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_3g_enc(algo: str) -> str:
    """Map 3G encryption algorithm code to label."""
    # 0-3 → UEA0 to UEA2
    mapping = {"0": "UEA0", "1": "UEA1", "2": "UEA2"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_3g_int(algo: str) -> str:
    """Map 3G integrity algorithm code to label."""
    # 0-1 → UIA1/UIA2
    mapping = {"0": "UIA1", "1": "UIA2"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_4g_rrc_enc(algo: str) -> str:
    """Map 4G RRC encryption algorithm code to label."""
    # 0-3 → EEA0/128‑EEA1/2/3
    mapping = {"0": "EEA0", "1": "128‑EEA1", "2": "128‑EEA2", "3": "128‑EEA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_4g_rrc_int(algo: str) -> str:
    """Map 4G RRC integrity algorithm code to label."""
    # 0-3 → EIA0/128‑EIA1/2/3
    mapping = {"0": "EIA0", "1": "128‑EIA1", "2": "128‑EIA2", "3": "128‑EIA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_4g_nas_enc(algo: str) -> str:
    """Map 4G NAS encryption algorithm code to label."""
    # 0-3 → EEA0/128‑EEA1/2/3
    mapping = {"0": "EEA0", "1": "128‑EEA1", "2": "128‑EEA2", "3": "128‑EEA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_4g_nas_int(algo: str) -> str:
    """Map 4G NAS integrity algorithm code to label."""
    # 0-3 → EIA0/128‑EIA1/2/3
    mapping = {"0": "EIA0", "1": "128‑EIA1", "2": "128‑EIA2", "3": "128‑EIA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_5g_rrc_enc(algo: str) -> str:
    """Map 5G RRC encryption algorithm code to label."""
    # 0-3 → NEA0/128‑NEA1/2/3
    mapping = {"0": "NEA0", "1": "NEA1", "2": "NEA2", "3": "NEA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_5g_rrc_int(algo: str) -> str:
    """Map 5G RRC integrity algorithm code to label."""
    # 0-3 → NIA0/128‑NIA1/2/3
    mapping = {"0": "NIA0", "1": "NIA1", "2": "NIA2", "3": "NIA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_5g_nas_enc(algo: str) -> str:
    """Map 5G NAS encryption algorithm code to label."""
    # 0-3 → NEA0/128‑NEA1/2/3
    mapping = {"0": "NEA0", "1": "NEA1", "2": "NEA2", "3": "NEA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

def interpret_5g_nas_int(algo: str) -> str:
    """Map 5G NAS integrity algorithm code to label."""
    # 0-3 → NIA0/128‑NIA1/2/3
    mapping = {"0": "NIA0", "1": "NIA1", "2": "NIA2", "3": "NIA3"}
    return mapping.get(algo, f"Unknown({algo})") if algo else "NOT FOUND"

# --- Helper to select the correct interpretation function ---
def get_interpret_func_for_tab(title: str) -> Callable[[str], str]:
    """Return the interpretation function for a given sheet title."""
    if title == "2G CS":
        return interpret_2g_voz
    if title == "2G PS":
        return interpret_2g_dados
    if title == "3G ENC":
        return interpret_3g_enc
    if title == "3G INT":
        return interpret_3g_int
    if title == "4G RRC ENC":
        return interpret_4g_rrc_enc
    if title == "4G RRC INT":
        return interpret_4g_rrc_int
    if title == "4G NAS ENC":
        return interpret_4g_nas_enc
    if title == "4G NAS INT":
        return interpret_4g_nas_int
    if title == "5G RRC ENC":
        return interpret_5g_rrc_enc
    if title == "5G RRC INT":
        return interpret_5g_rrc_int
    if title == "5G NAS ENC":
        return interpret_5g_nas_enc
    if title == "5G NAS INT":
        return interpret_5g_nas_int
    return lambda x: x  # fallback: identity

def interpret_version(version: str) -> str:
    """Map GSMTAP version to a human-readable label."""
    if version == "2":
        return "GSMTAP V2"
    if version == "3":
        return "GSMTAP V3"
    return "NOT FOUND"

def interpret_payload(payloadfield: str, payload: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Map payload code to a label using translations config."""
    if translations_cfg is None:
        return "NOT FOUND"
    payload_dict = translations_cfg.get(payloadfield, {})
    inverted = {v: k for k, v in payload_dict.items()}
    return inverted.get(payload, "NOT FOUND")

def interpret_subtype(version: str, payload: str, subtypefield: str, subtype: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Map subtype code to a label, considering version and payload, via translations."""
    if translations_cfg is None:
        return "NOT FOUND"
    subtypefield_verify = subtypefield
    if version == "3":
        if payload == "0x0200": #GSM Um
            subtypefield_verify = subtypefield + "_GSMUm"
        elif payload == "0x0205": #GSM Abis
            return "GSM Abis"
        elif payload == "0x0303": #UMTS RRC
            subtypefield_verify = subtypefield + "_UMTSRRC"
        elif payload == "0x0403": #LTE RRC
            subtypefield_verify = subtypefield + "_LTERRC"
        elif payload == "0x0404": #LTE NAS
            subtypefield_verify = subtypefield + "_LTENAS"
        elif payload == "0x0503": #NR RRC
            subtypefield_verify = subtypefield + "_NRRRC"
        elif payload == "0x0504": #NR NAS
            subtypefield_verify = subtypefield + "_NRNAS"
    elif version == "2":
        if payload == "2": #GSM Abis
            return "GSM Abis"
    subtype_dict = translations_cfg.get(subtypefield_verify, {})
    inverted = {v: k for k, v in subtype_dict.items()}
    return inverted.get(subtype, "NOT FOUND")

def interpret_domain(domain: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Map domain value to a label using translations config."""
    if translations_cfg is None:
        return "NOT FOUND"
    domain_dict = translations_cfg.get("rrc.cn_DomainIdentity", {})
    inverted = {v: k for k, v in domain_dict.items()}
    return inverted.get(domain, "")

def interpret_message(message_field: str, message: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Map message value to a label using translations config."""
    if translations_cfg is None:
        return "NOT FOUND"
    if not message_field:
        return "NOT FOUND"
    if not message:
        return "NOT FOUND"
    message_dict = translations_cfg.get(message_field, {})
    inverted = {v: k for k, v in message_dict.items()}
    # If the message contains a comma, take only the part before it
    if ',' in message:
        message = message.split(',')[0]
    return inverted.get(message, "NOT FOUND")

def parse_hex_or_dec(val: str) -> str:
    """Convert a decimal or hexadecimal string (with/without 0x) to decimal string.

    Return the original value if conversion fails.
    """
    if not val:
        return ""
    val = val.strip()
    try:
        # Try normal int conversion (decimal or 0x-prefixed hex)
        return str(int(val, 0))
    except Exception:
        # If not, try to interpret as hex if it looks like hex (all hex chars, not just digits)
        if all(c in "0123456789abcdefABCDEF" for c in val) and not val.isdigit():
            try:
                return str(int(val, 16))
            except Exception:
                return val
        return val

def interpret_id_type(id_type: Optional[str], id_type_field: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Translate the ID Type value to a descriptive string (considering payload).

    Tolerant to None/"" and comma-separated lists.
    """
    # Safeguards for None/absence
    if not id_type:
        return ""
    if translations_cfg is None:
        return "NOT FOUND"
    id_type_dict = translations_cfg.get(id_type_field, {})
    inverted = {v: k for k, v in id_type_dict.items()}
    # Support for two types separated by comma
    if "," in id_type:
        parts = [p.strip() for p in id_type.split(",") if p.strip()]
        if len(parts) == 0:
            return ""
        if len(parts) == 1:
            return inverted.get(parts[0], "NOT FOUND")
        # Only the first two (aligns with current builder)
        return inverted.get(parts[0], "NOT FOUND") + ", " + inverted.get(parts[1], "NOT FOUND")
    return inverted.get(id_type, "NOT FOUND")

def interpret_vops(raw: Optional[str]) -> str:
    """Translate raw tshark boolean VoPS value to 'Supported' or 'Not Supported'."""
    if not raw:
        return ""
    return "Supported" if raw.strip().lower() in ("true", "1") else "Not Supported"


def interpret_scheme_type(scheme: Optional[str], scheme_field: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Translate the SUCI Scheme ID raw value to a descriptive string."""
    if not scheme:
        return ""
    if translations_cfg is None:
        return "NOT FOUND"
    scheme_dict = translations_cfg.get(scheme_field, {})
    inverted = {v: k for k, v in scheme_dict.items()}
    result = inverted.get(scheme)
    if result is None:
        try:
            result = inverted.get(hex(int(scheme, 0)))
        except (ValueError, TypeError):
            pass
    return result if result is not None else "NOT FOUND"

def interpret_sip_status(raw: Optional[str], field: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Translate a raw SIP status code number to its descriptive label."""
    if not raw:
        return ""
    if translations_cfg is None:
        return raw
    status_dict = translations_cfg.get(field, {})
    inverted = {v: k for k, v in status_dict.items()}
    if ',' in raw:
        raw = raw.split(',')[0].strip()
    return inverted.get(raw, raw)


def interpret_sip_sec_mechanism(raw: Optional[str], field: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Translate a raw SIP sec_mechanism identifier to a descriptive label."""
    if not raw:
        return ""
    if translations_cfg is None:
        return raw
    mech_dict = translations_cfg.get(field, {})
    inverted = {v: k for k, v in mech_dict.items()}
    if ',' in raw:
        raw = raw.split(',')[0].strip()
    return inverted.get(raw, raw)


def interpret_sip_ealg(raw: Optional[str], field: str, translations_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Translate a raw SIP sec_mechanism.ealg value to a descriptive label."""
    if not raw:
        return ""
    if translations_cfg is None:
        return raw
    ealg_dict = translations_cfg.get(field, {})
    inverted = {v: k for k, v in ealg_dict.items()}
    if ',' in raw:
        raw = raw.split(',')[0].strip()
    return inverted.get(raw, raw)


def format_id_hex(id_value: str) -> str:
    """Normalize IDs already in HEX to the form "0x" + lowercase digits.

    Exception: IMSI (15 decimal digits) is returned as-is.
    """
    if id_value is None or id_value == "":
        return ""
    s = id_value.strip()

    # 15 dígitos → decimal (IMSI)
    if len(s) == 15 and s.isdigit():
        return s

    # Caso contrário, tratar como HEX e normalizar
    # Remove prefixo se existir e valida apenas caracteres hex
    hex_digits = s[2:] if s.startswith(("0x", "0X")) else s
    if len(hex_digits) > 0 and all(c in "0123456789abcdefABCDEF" for c in hex_digits):
        return "0x" + hex_digits.lower()
    # If it contains invalid characters, return as-is
    return s

def format_timestamp(ts: str) -> str:
    """Convert a unix epoch timestamp (string or float) to a readable date in GMT-3."""
    if not ts:
        return ""
    try:
        dt = datetime.datetime.utcfromtimestamp(float(ts)) - datetime.timedelta(hours=3)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts

def get_first_version(resultados: Dict[str, List[Dict[str, str]]]) -> Optional[str]:
    """Return the first 'Version' value found in the resultados dict."""
    for registros in resultados.values():
        if registros and isinstance(registros, list):
            return registros[0].get("Version")
    return None

def add_sheet(doc: OpenDocumentSpreadsheet, title: str, data: Dict[str, List[Dict[str, str]]], cols: List[str], translations_cfg: Dict[str, Any]) -> None:
    """Add a sheet to the ODS document and populate it using interpreted fields."""
    if not data:
        return
    table = Table(name=title)
    doc.spreadsheet.addElement(table)
    # Header
    hdr = TableRow()
    for c in cols:
        cell = TableCell()
        cell.addElement(P(text=c))
        hdr.addElement(cell)
    table.addElement(hdr)
    # Data rows
    interpret_func = get_interpret_func_for_tab(title)
    if data is None:
        return
    for algo, entries in data.items():
        for e in entries:
            row = TableRow()
            for c in cols:
                if c == "Algorithm":
                    text = interpret_func(algo)
                elif c == "Timestamp":
                    text = format_timestamp(e.get(c, ""))
                elif c == "Version":
                    text = interpret_version(e.get(c, ""))
                elif c == "Payload":
                    text = interpret_payload(e.get("PayloadField", ""), e.get(c, ""), translations_cfg)
                elif c == "SubType":
                    text = interpret_subtype(e.get("Version", ""), e.get("Payload", ""), e.get("SubTypeField", ""), e.get(c, ""), translations_cfg)
                elif c in ("Domain", "Domain 1", "Domain 2", "Domain 3", "Domain 4", "Domain 5"):
                    text = interpret_domain(e.get(c, ""), translations_cfg)
                elif c == "Message":
                    text = interpret_message(e.get("MessageField", ""), e.get(c, ""), translations_cfg)
                elif c in ("LAC", "RAC", "Cell_ID", "TAC", "ARFCN", "ARFCN_NR", "Physical_Cell_ID", "CellID_2G", "CellID_3G", "RNC_3G", "CellID_4GRRC", "TAC_4GRRC", "CellID_NRNSA", "MCC", "MNC", "PLMN"):  # adicione mais conforme necessário
                    text = parse_hex_or_dec(e.get(c, ""))
                elif c in ("ID", "ID1", "ID2", "ID3", "ID4", "ID5", "ID Part 1", "ID Part 2"):
                    text = format_id_hex(e.get(c, ""))
                elif c in ("ID Type", "ID Type 1", "ID Type 2", "ID Type 3", "ID Type 4", "ID Type 5"):
                    text = interpret_id_type(e.get(c, ""), e.get("ID Type Field", ""), translations_cfg)
                elif c == "Scheme Type":
                    text = interpret_scheme_type(e.get(c, ""), e.get("Scheme Type Field", ""), translations_cfg)
                elif c == "VoPS":
                    text = interpret_vops(e.get(c, ""))
                elif c == "Status Code":
                    text = interpret_sip_status(e.get("StatusCode", ""), e.get("StatusCodeField", ""), translations_cfg)
                elif c == "Security Mechanism":
                    text = interpret_sip_sec_mechanism(e.get("SecMechanism", ""), e.get("SecMechanismField", ""), translations_cfg)
                elif c == "EAlg":
                    text = interpret_sip_ealg(e.get("EAlg", ""), e.get("EAlgField", ""), translations_cfg)
                elif c == "Method":
                    text = e.get("Method", "")
                elif c == "Realm":
                    text = e.get("Realm", "")
                else:
                    text = e.get(c, "")
                cell = TableCell()
                cell.addElement(P(text=text))
                row.addElement(cell)
            table.addElement(row)

def build_ods_table(
    alg_res: Dict[str, Dict[str, Any]],
    used_res: Dict[str, Dict[str, Any]],
    order: List[str],
    used_order: List[str],
    resultados_2g_voz_enc: Dict[str, List[Dict[str, str]]],
    resultados_2g_dados_enc: Dict[str, List[Dict[str, str]]],
    resultados_3g_enc: Dict[str, List[Dict[str, str]]],
    resultados_3g_int: Dict[str, List[Dict[str, str]]],
    resultados_4g_rrc_enc: Dict[str, List[Dict[str, str]]],
    resultados_4g_rrc_int: Dict[str, List[Dict[str, str]]],
    resultados_4g_nas_enc: Dict[str, List[Dict[str, str]]],
    resultados_4g_nas_int: Dict[str, List[Dict[str, str]]],
    resultados_5g_rrc_enc: Dict[str, List[Dict[str, str]]],
    resultados_5g_rrc_int: Dict[str, List[Dict[str, str]]],
    resultados_5g_nas_enc: Dict[str, List[Dict[str, str]]],
    resultados_5g_nas_int: Dict[str, List[Dict[str, str]]],
    resultados_2g_voz_id: Dict[str, List[Dict[str, str]]],
    resultados_2g_dados_id: Dict[str, List[Dict[str, str]]],
    resultados_3g_rrc_id: Dict[str, List[Dict[str, str]]],
    resultados_3g_nas_id: Dict[str, List[Dict[str, str]]],
    resultados_4g_rrc_id: Dict[str, List[Dict[str, str]]],
    resultados_4g_nas_id: Dict[str, List[Dict[str, str]]],
    resultados_5g_rrc_id: Dict[str, List[Dict[str, str]]],
    resultados_5g_nas_id: Dict[str, List[Dict[str, str]]],
    resultados_2g_paging: Dict[str, List[Dict[str, str]]],
    resultados_3g_paging: Dict[str, List[Dict[str, str]]],
    resultados_4g_paging: Dict[str, List[Dict[str, str]]],
    resultados_5g_paging: Dict[str, List[Dict[str, str]]],
    resultados_5g_sucischema: Dict[str, List[Dict[str, str]]],
    resultados_4g_vops: Dict[str, List[Dict[str, str]]],
    resultados_5g_vops: Dict[str, List[Dict[str, str]]],
    resultados_4g_ue_cap_security: Optional[List[Dict[str, Any]]] = None,
    resultados_5g_ue_cap_security: Optional[List[Dict[str, Any]]] = None,
    resultados_sip: Optional[Dict[str, List[Dict[str, str]]]] = None,
    country: str = "",
    operator: str = "",
    translations_cfg: Dict[str, Any] = None,
    out_fn: str = "",
    include_ue_capability: bool = True,
) -> None:
    """
    Generate an ODS spreadsheet with the results of supported and used algorithms.

    Parameters:
        alg_res: support results (name->{{chosen_value, packets_different}})
        used_res: usage results
        country: name of the country
        operator: name of the operator
        out_fn: full path to the output file
        order: order of display of supported algorithms
        used_order: order of display of used algorithms
    """
    # Create document and table
    doc = OpenDocumentSpreadsheet()

    # Summary tab: creates a table to display a general summary of the results
    if include_ue_capability:
        summary = Table(name="UE Crypto Capabilities")
        doc.spreadsheet.addElement(summary)

        hdr = TableRow()
        for h in ["Country","Operator","", "Algorithm","Capability","","Algorithm","Chosen"]:
            cell = TableCell()
            cell.addElement(P(text=h))
            hdr.addElement(cell)
        summary.addElement(hdr)

        for i in range(max(len(order), len(used_order))):
            row = TableRow()
            if i == 0:
                c1 = TableCell(); c1.addElement(P(text=country)); row.addElement(c1)
                c2 = TableCell(); c2.addElement(P(text=operator)); row.addElement(c2)
            else:
                row.addElement(TableCell()); row.addElement(TableCell())
            row.addElement(TableCell())
            if i < len(order):
                name = order[i]
                registro = alg_res.get(name)
                v: str = registro.get("chosen_value", "") if registro else ""
                c3 = TableCell(); c3.addElement(P(text=name)); row.addElement(c3)
                c4 = TableCell(); c4.addElement(P(text=interpret_value(name, v))); row.addElement(c4)
            else:
                row.addElement(TableCell()); row.addElement(TableCell())
            row.addElement(TableCell())
            if i < len(used_order):
                name2 = used_order[i]
                registro2 = used_res.get(name2)
                chosen_text = ""
                if registro2:
                    v2: str = registro2.get("chosen_value", "")
                    all_vals: List[str] = registro2.get("all_values") or []
                    source_vals = all_vals if all_vals else ([v2] if v2 else [])
                    labels: List[str] = []
                    for raw_code in source_vals:
                        label = interpret_used_value(name2, raw_code)
                        if label and label not in labels:
                            labels.append(label)
                    chosen_text = ", ".join(labels)
                c6 = TableCell(); c6.addElement(P(text=name2)); row.addElement(c6)
                c7 = TableCell(); c7.addElement(P(text=chosen_text)); row.addElement(c7)
            else:
                row.addElement(TableCell()); row.addElement(TableCell())
            summary.addElement(row)

    # Add tables for each type of result
    # Encryption results
    add_sheet(doc, "2G CS",   resultados_2g_voz_enc, ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Message","ARFCN","LAC","Cell_ID","Algorithm"], translations_cfg)
    add_sheet(doc, "2G PS", resultados_2g_dados_enc,["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Message","LAC","RAC","Algorithm"], translations_cfg)
    add_sheet(doc, "3G ENC",       resultados_3g_enc,      ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Domain","Message","ARFCN","RNC_ID","Cell_ID","Algorithm"], translations_cfg)
    add_sheet(doc, "3G INT",       resultados_3g_int,      ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Domain","Message","ARFCN","RNC_ID","Cell_ID","Algorithm"], translations_cfg)
    version_4g = get_first_version(resultados_4g_rrc_enc)
    if version_4g == "2":
        add_sheet(doc, "4G RRC ENC",   resultados_4g_rrc_enc,  ["Timestamp","Frame","Version","Payload","SubType","Message","MCC","MNC","ARFCN","TAC","Cell_ID","Algorithm"], translations_cfg)
        add_sheet(doc, "4G RRC INT",   resultados_4g_rrc_int,  ["Timestamp","Frame","Version","Payload","SubType","Message","MCC","MNC","ARFCN","TAC","Cell_ID","Algorithm"], translations_cfg)
    elif version_4g == "3":
        add_sheet(doc, "4G RRC ENC",   resultados_4g_rrc_enc,  ["Timestamp","Frame","Version","Payload","SubType","Message","MCC","MNC","ARFCN","TAC","Cell_ID","PCI","Algorithm"], translations_cfg)
        add_sheet(doc, "4G RRC INT",   resultados_4g_rrc_int,  ["Timestamp","Frame","Version","Payload","SubType","Message","MCC","MNC","ARFCN","TAC","Cell_ID","PCI","Algorithm"], translations_cfg)
    add_sheet(doc, "4G NAS ENC",   resultados_4g_nas_enc,  ["Timestamp","Frame","Version","Payload","SubType","Message","Algorithm"], translations_cfg)
    add_sheet(doc, "4G NAS INT",   resultados_4g_nas_int,  ["Timestamp","Frame","Version","Payload","SubType","Message","Algorithm"], translations_cfg)
    add_sheet(doc, "5G RRC ENC",   resultados_5g_rrc_enc,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","Cell_ID","Algorithm"], translations_cfg)
    add_sheet(doc, "5G RRC INT",   resultados_5g_rrc_int,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","Cell_ID","Algorithm"], translations_cfg)
    add_sheet(doc, "5G NAS ENC",   resultados_5g_nas_enc,  ["Timestamp","Frame","Version","Payload","SubType","Message","Algorithm"], translations_cfg)
    add_sheet(doc, "5G NAS INT",   resultados_5g_nas_int,  ["Timestamp","Frame","Version","Payload","SubType","Message","Algorithm"], translations_cfg)
    # Identity results
    add_sheet(doc, "2G CS ID",   resultados_2g_voz_id,  ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Message","ARFCN","LAC","ID Type","ID"], translations_cfg)
    add_sheet(doc, "2G PS ID",   resultados_2g_dados_id,  ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Message","ARFCN","LAC","ID Type","ID"], translations_cfg)
    add_sheet(doc, "3G RRC ID",   resultados_3g_rrc_id,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","ID Type","ID"], translations_cfg)
    add_sheet(doc, "3G NAS ID",   resultados_3g_nas_id,  ["Timestamp","Frame","Version","Payload","SubType","Domain","Message","ARFCN","ID Type","ID"], translations_cfg)
    version_4g_rrc_id = get_first_version(resultados_4g_rrc_id)
    if version_4g_rrc_id == "2":
        add_sheet(doc, "4G RRC ID",   resultados_4g_rrc_id,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","ID Type","ID"], translations_cfg)
    elif version_4g_rrc_id == "3":
        add_sheet(doc, "4G RRC ID",   resultados_4g_rrc_id,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","PCI","ID Type","ID"], translations_cfg)
    add_sheet(doc, "4G NAS ID",   resultados_4g_nas_id,  ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","LAC","Message","ID Type 1","MMEGID 1","MMECODE 1","ID1","ID Type 2","MMEGID 2","MMECODE 2","ID2"], translations_cfg)
    add_sheet(doc, "5G RRC ID",   resultados_5g_rrc_id,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","PCI","ID Type","ID Part 1","ID Part 2"], translations_cfg)
    add_sheet(doc, "5G NAS ID",   resultados_5g_nas_id,  ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","LAC","Message","ARFCN","ID Type 1","AMF Region ID 1","AMF Set ID 1","AMF Pointer 1","ID1","ID Type 2","AMF Region ID 2","AMF Set ID 2","AMF Pointer 2","ID2"], translations_cfg)
    # Paging results
    add_sheet(doc, "2G Paging",   resultados_2g_paging,  ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","LAC","Message","ARFCN","Cell","ID Type","ID1", "ID2", "ID3", "ID4"], translations_cfg)
    add_sheet(doc, "3G Paging",   resultados_3g_paging,  ["Timestamp","Frame","Version","Payload","SubType","Domain","Message","ARFCN","ID Type","ID"], translations_cfg)
    add_sheet(doc, "4G Paging",   resultados_4g_paging,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","Paging Record","Domain 1","ID Type 1","MMEC 1","ID1","Domain 2","ID Type 2","MMEC 2","ID2","Domain 3","ID Type 3","MMEC 3","ID3","Domain 4","ID Type 4","MMEC 4","ID4","Domain 5","ID Type 5","MMEC 5","ID5"], translations_cfg)
    add_sheet(doc, "5G Paging",   resultados_5g_paging,  ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","ID Type","ID"], translations_cfg)
    # SUCI Schema results
    add_sheet(doc, "5G SUCI", resultados_5g_sucischema, ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","Message","ARFCN","ID Type","Scheme Type"], translations_cfg)
    # VoPS results
    add_sheet(doc, "4G VoPS", resultados_4g_vops, ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","TAC","PCI","Message","ARFCN","VoPS"], translations_cfg)
    add_sheet(doc, "5G VoPS", resultados_5g_vops, ["Timestamp","Frame","Version","Payload","SubType","MCC","MNC","TAC","PCI","Message","ARFCN","VoPS"], translations_cfg)
    # UE Capability security check results
    add_sheet(doc, "4G UE Cap Security", {"records": resultados_4g_ue_cap_security}, ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","PCI"], translations_cfg)
    add_sheet(doc, "5G UE Cap Security", {"records": resultados_5g_ue_cap_security}, ["Timestamp","Frame","Version","Payload","SubType","Message","ARFCN","PCI"], translations_cfg)
    # SIP results
    add_sheet(doc, "SIP", resultados_sip, ["Timestamp","Frame","Method","Status Code","Realm","Security Mechanism","EAlg"], translations_cfg)
    out_path = Path(out_fn)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))


def build_security_ods(output_path: Path, summaries: List["GenerationSummary"], identities: List["IdentityRecord"] | None = None, paging_stats: Dict[str, Dict[str, int]] | None = None, ts_margin_seconds: float = 0.0, tmsi_thresholds: Dict[str, float] | None = None, suci_stats: Optional[Any] = None, vops_stats: Optional[Any] = None, ue_cap_security_stats: Optional[Any] = None, sip_ipsec_stats: Optional[Any] = None) -> Path:
    """Create an ODS file with a Crypto Summary sheet showing, per generation.

    - number of cipher changes
    - weak cipher used flag
    - usage counts per cipher label observed

    The table will have dynamic columns for each cipher observed across all generations.
    """
    # Lazy import to avoid circular imports at module import time
    import security_evaluator as se

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect all distinct cipher labels to generate columns deterministically
    all_ciphers: Set[str] = set()
    for s in summaries:
        all_ciphers.update(s.counts.keys())
    # Sort columns by order: A5, GEA, UEA, UIA, EEA, EIA, NEA, NIA
    def _cipher_sort_key(label: str) -> Tuple[int, int, str]:
        s = str(label).upper().replace("‑", "-")
        s_no = s[4:] if s.startswith("128-") else s
        def num_after(pattern: str) -> int:
            m = re.search(rf"{pattern}[/\-]?(\d+)", s_no)
            return int(m.group(1)) if m else 0
        if "A5" in s_no:
            return (0, num_after("A5"), s)
        if "GEA" in s_no:
            return (1, num_after("GEA"), s)
        if "UEA" in s_no:
            return (2, num_after("UEA"), s)
        if "UIA" in s_no:
            return (3, num_after("UIA"), s)
        if "EEA" in s_no:
            return (4, num_after("EEA"), s)
        if "EIA" in s_no:
            return (5, num_after("EIA"), s)
        if "NEA" in s_no:
            return (6, num_after("NEA"), s)
        if "NIA" in s_no:
            return (7, num_after("NIA"), s)
        return (999, 0, s)

    cipher_cols = sorted(all_ciphers, key=_cipher_sort_key)

    summary_by_name = {s.name: s for s in summaries}
    metrics_map: Dict[str, Dict[str, Any]] = {}
    _th_s = tmsi_thresholds or {}
    try:
        _collision_max_s = float(_th_s.get("collision_max", 0.01))
    except Exception:
        _collision_max_s = 0.01
    try:
        _h_norm_min_s = float(_th_s.get("h_norm_min", 0.99))
    except Exception:
        _h_norm_min_s = 0.99
    try:
        _succ_hamm_p_min_s = float(_th_s.get("succ_hamm_p_min", 0.01))
    except Exception:
        _succ_hamm_p_min_s = 0.01
    try:
        _chi2_p_min_s = float(_th_s.get("chi2_p_min", 0.01))
    except Exception:
        _chi2_p_min_s = 0.01
    _tmsi_label_map_s = {
        "2G CS": "2G CS (TMSI)",
        "2G PS": "2G PS (PTMSI)",
        "3G CS": "3G NAS CS (TMSI)",
        "3G PS": "3G NAS PS (PTMSI)",
        "4G":    "4G NAS (MTMSI)",
        "5G":    "5G NAS (5G-S-TMSI)",
    }

    doc = OpenDocumentSpreadsheet()

    # Define bold styles for headers
    header_para = Style(name="HeaderPara", family="paragraph")
    header_para.addElement(TextProperties(fontweight="bold", fontweightasian="bold", fontweightcomplex="bold"))
    doc.automaticstyles.addElement(header_para)
    header_cell = Style(name="HeaderCell", family="table-cell")
    header_cell.addElement(TextProperties(fontweight="bold", fontweightasian="bold", fontweightcomplex="bold"))
    doc.automaticstyles.addElement(header_cell)
    bold_cell = Style(name="BoldCell", family="table-cell")
    bold_cell.addElement(TextProperties(fontweight="bold", fontweightasian="bold", fontweightcomplex="bold"))
    doc.automaticstyles.addElement(bold_cell)
    pass_para = Style(name="PassPara", family="paragraph")
    pass_para.addElement(TextProperties(fontweight="bold", color="#007700"))
    doc.automaticstyles.addElement(pass_para)
    fail_para = Style(name="FailPara", family="paragraph")
    fail_para.addElement(TextProperties(fontweight="bold", color="#CC0000"))
    doc.automaticstyles.addElement(fail_para)

    def _add_bold_header_cells(row: TableRow, titles: Iterable[str]) -> None:
        for title in titles:
            cell = TableCell(stylename=header_cell)
            p = P(stylename=header_para, text=title)
            cell.addElement(p)
            row.addElement(cell)

    table = Table(name="Crypto Summary")
    doc.spreadsheet.addElement(table)

    # Header row
    hdr = TableRow()
    _add_bold_header_cells(hdr, ["Generation", "Changes", "Status"] + cipher_cols)
    table.addElement(hdr)

    # Data rows
    def yes_no(flag: bool) -> str:
        return "Fail" if flag else "Pass"

    for s in summaries:
        row = TableRow()
        total_used = sum(s.counts.values())
        cells = [s.name, str(total_used), yes_no(s.weak_in_use)]
        cells.extend(str(s.counts.get(c, 0)) for c in cipher_cols)
        for idx, v in enumerate(cells):
            if idx == 2:  # Status column
                cell = TableCell(stylename=bold_cell)
                p = P(stylename=header_para, text=v)
            else:
                cell = TableCell()
                p = P(text=v)
            cell.addElement(p)
            row.addElement(cell)
        table.addElement(row)

    # Add IDs tab with selected messages across generations
    if identities:
        tab2 = Table(name="IDs Messages")
        doc.spreadsheet.addElement(tab2)
        hdr2 = TableRow()
        _add_bold_header_cells(hdr2, ("Generation", "Timestamp", "Domain", "Message", "ID Type", "ID"))
        tab2.addElement(hdr2)

        # Sort by robust Timestamp key to reflect real allocation order
        for rec in sorted(identities, key=lambda r: se._ts_sort_key(r.timestamp)):
            row = TableRow()
            vals = [rec.sheet, rec.timestamp, rec.domain or "", rec.message, rec.id_type, rec.id_value]
            for v in vals:
                cell = TableCell(); cell.addElement(P(text=v)); row.addElement(cell)
            tab2.addElement(row)

    # Randomness Summary tab (all categories in columns)
    if identities:
        # Build datasets per category
        def _canon(s: str) -> str:
            return (s or "").strip().upper()

        def _gen_from_sheet(sheet: str) -> str:
            ss = (sheet or "").strip().upper()
            for g in ("2G", "3G", "4G", "5G"):
                if ss.startswith(g):
                    return g
            return ss.split()[0] if ss else ""

        def _deduplicate_records(recs: List["IdentityRecord"], margin: float) -> Tuple[List["IdentityRecord"], int]:
            """Deduplicate by (generation, domain, message, id_type, id_value) within a time margin.

            Returns (deduped_records, discarded_count).
            """
            margin = max(0.0, float(margin or 0.0))
            buckets: Dict[Tuple[str, str, str, str, str], List[Tuple[Optional[float], str]]] = {}
            out: List["IdentityRecord"] = []
            discards = 0
            for rec in sorted(recs, key=lambda r: se._ts_sort_key(r.timestamp)):
                gen = _gen_from_sheet(rec.sheet)
                domu = (rec.domain or "").strip().upper()
                msgc = (rec.message or "").upper().replace(" ", "").replace("-", "")
                idt = (rec.id_type or "").strip().upper()
                idv = (rec.id_value or "").strip()
                key = (gen, domu, msgc, idt, idv)
                ep = se._parse_timestamp_to_epoch(rec.timestamp)
                seen = buckets.setdefault(key, [])
                is_dup = False
                for pep, praw in seen:
                    if ep is not None and pep is not None:
                        if abs(ep - pep) <= margin:
                            is_dup = True
                            break
                    else:
                        if margin <= 0.0 and (rec.timestamp or "").strip() == (praw or "").strip():
                            is_dup = True
                            break
                if is_dup:
                    discards += 1
                else:
                    seen.append((ep, rec.timestamp))
                    out.append(rec)
            return out, discards

        cats: List[Tuple[str, List["IdentityRecord"], int]] = []

        src_2g_cs_raw = [r for r in identities if _canon(r.sheet) == "2G CS ID" and _canon(r.id_type) == "TMSI" and r.id_value]
        src_2g_cs_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("2G CS (TMSI)", src_2g_cs_raw, 8))

        src_2g_ps_raw = [r for r in identities if _canon(r.sheet) == "2G PS ID" and _canon(r.id_type) == "TMSI" and r.id_value]
        src_2g_ps_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("2G PS (PTMSI)", src_2g_ps_raw, 8))

        src_3g_cs_raw = [r for r in identities if _canon(r.sheet) == "3G NAS ID" and _canon(r.domain) == "CS" and _canon(r.id_type) == "TMSI" and r.id_value]
        src_3g_cs_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("3G NAS CS (TMSI)", src_3g_cs_raw, 8))

        src_3g_ps_raw = [r for r in identities if _canon(r.sheet) == "3G NAS ID" and _canon(r.domain) == "PS" and _canon(r.id_type) == "TMSI" and r.id_value]
        src_3g_ps_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("3G NAS PS (PTMSI)", src_3g_ps_raw, 8))

        src_4g_raw = [r for r in identities if _canon(r.sheet) == "4G NAS ID" and _canon(r.id_type) == "GUTI" and r.id_value]
        src_4g_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("4G NAS (MTMSI)", src_4g_raw, 8))

        src_5g_raw = [r for r in identities if _canon(r.sheet) == "5G NAS ID" and _canon(r.id_type) == "5G-GUTI" and r.id_value]
        src_5g_raw.sort(key=lambda r: se._ts_sort_key(r.timestamp))
        cats.append(("5G NAS (5G-S-TMSI)", src_5g_raw, 8))

        # Deduplicate per category, compute counts and metrics
        labels = [name for name, _, _ in cats]
        metrics_map: Dict[str, Dict[str, Any]] = {}
        total_by_label: Dict[str, int] = {}
        discarded_by_label: Dict[str, int] = {}
        used_by_label: Dict[str, int] = {}
        for name, raw_recs, w in cats:
            total = len(raw_recs)
            # Apply retransmission filter among already-paired records using configured window (seconds)
            deduped, disc = _deduplicate_records(raw_recs, ts_margin_seconds)
            m = se.compute_id_randomness(deduped, nibble_width=w) if deduped else {}
            metrics_map[name] = m
            total_by_label[name] = total
            discarded_by_label[name] = disc
            used_by_label[name] = int(m.get("samples", 0))

        tab_rand = Table(name="Randomness Summary")
        doc.spreadsheet.addElement(tab_rand)

        # Metrics matrix header
        hdr = TableRow()
        _add_bold_header_cells(hdr, (["Metric"] + labels))
        tab_rand.addElement(hdr)

        def _add_metric_row(metric_name: str, key: str, fmt: str | None = None, bold: bool = False) -> None:
            row = TableRow()
            # Metric name cell
            if bold:
                cell = TableCell(stylename=bold_cell)
                cell.addElement(P(stylename=header_para, text=metric_name))
            else:
                cell = TableCell(); cell.addElement(P(text=metric_name))
            row.addElement(cell)
            # Values
            for label in labels:
                m = metrics_map.get(label, {})
                # If metric missing, leave blank (instead of 0/0.0000) when formatting numbers
                val = m.get(key, None if fmt else 0)
                if isinstance(val, (int, float)) and fmt:
                    # For p-values, prefer scientific notation, but if underflow produced 0.0 show "< 1e-308"
                    if key.endswith("_p"):
                        if float(val) == 0.0:
                            sval = "< 1e-308"
                        else:
                            sval = f"{val:.2e}"
                    else:
                        sval = f"{val:.4f}"
                else:
                    sval = "" if val is None else str(val)
                if bold:
                    cell = TableCell(stylename=bold_cell); cell.addElement(P(stylename=header_para, text=sval))
                else:
                    cell = TableCell(); cell.addElement(P(text=sval))
                row.addElement(cell)
            tab_rand.addElement(row)

        def _add_status_row(title: str, check_fn, bold: bool = False) -> None:
            row = TableRow()
            # Title
            if bold:
                cell = TableCell(stylename=bold_cell); cell.addElement(P(stylename=header_para, text=title))
            else:
                cell = TableCell(); cell.addElement(P(text=title))
            row.addElement(cell)
            # Values
            for label in labels:
                m = metrics_map.get(label, {})
                try:
                    ok = check_fn(m)
                except Exception:
                    ok = None
                # Render N/A when the check is not applicable (None), else Pass/Fail
                if ok is None:
                    sval = "N/A"
                else:
                    sval = ("Pass" if ok else "Fail")
                if bold:
                    cell = TableCell(stylename=bold_cell); cell.addElement(P(stylename=header_para, text=sval))
                else:
                    cell = TableCell(); cell.addElement(P(text=sval))
                row.addElement(cell)
            tab_rand.addElement(row)

        # Counts
        def _add_counts_row(title: str, values: Dict[str, int]) -> None:
            row = TableRow()
            cell = TableCell(); cell.addElement(P(text=title)); row.addElement(cell)
            for label in labels:
                v = str(values.get(label, 0))
                cell = TableCell(); cell.addElement(P(text=v)); row.addElement(cell)
            tab_rand.addElement(row)

        # Additional count: filtered by confirmation-based pairing
        try:
            pairing_discards = {label: int(se._PAIRING_DISCARDS_BY_LABEL.get(label, 0) or 0) for label in labels}
        except Exception:
            pairing_discards = {label: 0 for label in labels}
        # Total Samples should represent all eligible packets (allowed messages per sheet):
        # compute as message-level paired candidates plus those filtered out by pairing.
        # Use global _PAIRING_USED_MSGS_BY_LABEL which tracks message-level used counts.
        try:
            used_msgs_by_label = {label: int(se._PAIRING_USED_MSGS_BY_LABEL.get(label, 0) or 0) for label in labels}
        except Exception:
            used_msgs_by_label = {label: 0 for label in labels}
        total_candidates_by_label = {label: int(used_msgs_by_label.get(label, 0)) + int(pairing_discards.get(label, 0)) for label in labels}
        _add_counts_row("Total Samples", total_candidates_by_label)
        _add_counts_row("Filtered by confirmation pairing", pairing_discards)
        # New filter for retransmissions within configured seconds among already-paired records
        try:
            secs_val = int(ts_margin_seconds) if (ts_margin_seconds is not None and float(ts_margin_seconds) > 0) else None
        except Exception:
            secs_val = None
        filt_label = f"Filtered retransmissions ({secs_val}sec threshold)" if secs_val else "Filtered retransmissions"
        _add_counts_row(filt_label, discarded_by_label)
        # Used Samples should reflect the deduplicated set that enters randomness evaluation
        _add_counts_row("Used Samples", used_by_label)
        _add_metric_row("Unique IDs", "unique")

        th = tmsi_thresholds or {}
        try:
            collision_max = float(th.get("collision_max", 0.01))
        except Exception:
            collision_max = 0.01
        try:
            h_norm_min = float(th.get("h_norm_min", 0.99))
        except Exception:
            h_norm_min = 0.99
        try:
            succ_hamm_p_min = float(th.get("succ_hamm_p_min", 0.01))
        except Exception:
            succ_hamm_p_min = 0.01
        try:
            chi2_p_min = float(th.get("chi2_p_min", 0.01))
        except Exception:
            chi2_p_min = 0.01

        # Core metrics
        _add_metric_row("Reuse Rate", "collision_rate", fmt=".4f", bold=True)
        _add_status_row(
            f"Status (Reuse rate < {collision_max})",
            lambda m: (m.get("collision_rate") < collision_max) if (m.get("collision_rate") is not None and m.get("samples", 0) >= 2) else False,
            bold=True,
        )

        # Full-value Shannon entropy (with normalized and Miller–Madow)
        _add_metric_row("Shannon H(values) [bits]", "H_values_bits", fmt=".4f")
        _add_metric_row("Shannon H(values) [bits] (Miller–Madow)", "H_values_bits_mm", fmt=".4f")
        _add_metric_row("H(values) normalized [0..1]", "H_values_norm", fmt=".4f", bold=True)
        _add_status_row(
            f"Status (H_norm > {h_norm_min})",
            lambda m: (m.get("H_values_norm") > h_norm_min) if (m.get("H_values_norm") is not None and m.get("unique", 0) > 1) else False,
            bold=True,
        )

        # Successive Hamming distance (unique, ordered)
        _add_metric_row("Succ. Hamming pairs", "succ_hd_pairs")
        _add_metric_row("Succ. Hamming bit width per ID [bits]", "succ_hd_wbits")
        _add_metric_row("Succ. Hamming mean [bits]", "succ_hd_mean", fmt=".4f")
        _add_metric_row("Succ. Hamming mean fraction [0..1]", "succ_hd_mean_frac", fmt=".4f")
        _add_metric_row("Succ. Hamming z-score", "succ_hd_z", fmt=".4f")
        _add_metric_row("Succ. Hamming p-value", "succ_hd_p", fmt=".4f", bold=True)
        _add_status_row(
            f"Status (Succ. Hamming p > {succ_hamm_p_min})",
            lambda m: (
                (m.get("succ_hd_p") > succ_hamm_p_min)
            ) if (m.get("succ_hd_pairs", 0) > 0 and m.get("succ_hd_p") is not None) else (False if m.get("unique", 0) <= 1 else None),
            bold=True,
        )

        # Nibble-level Pearson chi-square across all nibbles (16 bins)
        _add_metric_row("Chi-square nibbles statistic", "chi2_nibbles", fmt=".4f")
        _add_metric_row("Chi-square nibbles df", "chi2_nibbles_df")
        _add_metric_row("Chi-square nibbles p-value", "chi2_nibbles_p", fmt=".4f", bold=True)
        _add_status_row(
            f"Status (Chi-square p > {chi2_p_min})",
            lambda m: (m.get("chi2_nibbles_p") > chi2_p_min) if (m.get("chi2_nibbles_p") is not None) else (False if m.get("unique", 0) <= 1 else None),
            bold=True,
        )

        # MSB/LSB nibble chi-square
        _add_metric_row("Chi-square MSB (first nibble) statistic", "chi2_msb", fmt=".4f")
        _add_metric_row("Chi-square MSB (first nibble) df", "chi2_msb_df")
        _add_metric_row("Chi-square MSB (first nibble) p-value", "chi2_msb_p", fmt=".4f")
        _add_metric_row("Chi-square LSB (last nibble) statistic", "chi2_lsn", fmt=".4f")
        _add_metric_row("Chi-square LSB (last nibble) df", "chi2_lsn_df")
        _add_metric_row("Chi-square LSB (last nibble) p-value", "chi2_lsn_p", fmt=".4f")

        # Spacer
        tab_rand.addElement(TableRow())

        # All Nibbles histogram section
        hdrb_all = TableRow()
        _add_bold_header_cells(hdrb_all, (["All Nibbles"] + labels))
        tab_rand.addElement(hdrb_all)
        for nib in "0123456789ABCDEF":
            row = TableRow()
            cell = TableCell(); cell.addElement(P(text=nib)); row.addElement(cell)
            for label in labels:
                cnt = metrics_map.get(label, {}).get("nibble_hist", {}).get(nib, 0)
                cell = TableCell(); cell.addElement(P(text=str(cnt))); row.addElement(cell)
            tab_rand.addElement(row)

        # Spacer
        tab_rand.addElement(TableRow())

        # First Nibble (MSB) histogram section
        hdrb = TableRow()
        _add_bold_header_cells(hdrb, (["First Nibble (MSB)"] + labels))
        tab_rand.addElement(hdrb)
        for nib in "0123456789ABCDEF":
            row = TableRow()
            cell = TableCell(); cell.addElement(P(text=nib)); row.addElement(cell)
            for label in labels:
                cnt = metrics_map.get(label, {}).get("msb_hist", {}).get(nib, 0)
                cell = TableCell(); cell.addElement(P(text=str(cnt))); row.addElement(cell)
            tab_rand.addElement(row)

        # Spacer
        tab_rand.addElement(TableRow())

        # Last Nibble (LSB) histogram section
        hdrc = TableRow()
        _add_bold_header_cells(hdrc, (["Last Nibble (LSB)"] + labels))
        tab_rand.addElement(hdrc)
        for nib in "0123456789ABCDEF":
            row = TableRow()
            cell = TableCell(); cell.addElement(P(text=nib)); row.addElement(cell)
            for label in labels:
                cnt = metrics_map.get(label, {}).get("lsn_hist", {}).get(nib, 0)
                cell = TableCell(); cell.addElement(P(text=str(cnt))); row.addElement(cell)
            tab_rand.addElement(row)

    # Add Paging Summary tab (counts per generation)
    if paging_stats:
        tab4 = Table(name="Paging Summary")
        doc.spreadsheet.addElement(tab4)
        hdr4 = TableRow()
        _add_bold_header_cells(hdr4, ("Generation", "Paging Messages", "IMSI IDs", "Status"))
        tab4.addElement(hdr4)

        order = ["2G", "3G", "4G", "5G"]
        for gen in order:
            stats = paging_stats.get(gen, {})
            msgs_i = int(stats.get("messages", 0) or 0)
            imsis_i = int(stats.get("imsi_ids", 0) or 0)
            status = "Pass" if (imsis_i == 0) else "Fail"
            msgs = str(msgs_i)
            imsis = str(imsis_i)
            row = TableRow()
            cells_vals = (gen, msgs, imsis, status)
            for idx, v in enumerate(cells_vals):
                if idx == 3:
                    cell = TableCell(stylename=bold_cell)
                    p = P(stylename=header_para, text=v)
                else:
                    cell = TableCell()
                    p = P(text=v)
                cell.addElement(p)
                row.addElement(cell)
            tab4.addElement(row)

    # Add 5G SUCI Stats tab
    if suci_stats is not None:
        tab_suci = Table(name="5G SUCI Stats")
        doc.spreadsheet.addElement(tab_suci)

        def _mc(text: str, bold: bool = False) -> TableCell:
            cell = TableCell(stylename=bold_cell if bold else None)
            cell.addElement(P(stylename=header_para if bold else None, text=text))
            return cell

        null_scheme_count = suci_stats.scheme_counts.get("NULL scheme", 0)
        status = "Fail" if null_scheme_count > 0 else "Pass"

        hdr_s = TableRow()
        _add_bold_header_cells(hdr_s, ("Metric", "Count"))
        tab_suci.addElement(hdr_s)
        row = TableRow()
        row.addElement(_mc("Completed Registrations", bold=True))
        row.addElement(_mc(str(suci_stats.completed), bold=True))
        tab_suci.addElement(row)
        row = TableRow()
        row.addElement(_mc("Status (NULL scheme)", bold=True))
        row.addElement(_mc(status, bold=True))
        tab_suci.addElement(row)

        tab_suci.addElement(TableRow())

        hdr_id = TableRow()
        _add_bold_header_cells(hdr_id, ("ID Type", "Count"))
        tab_suci.addElement(hdr_id)
        for id_type, count in sorted(suci_stats.id_type_counts.items()):
            row = TableRow()
            row.addElement(_mc(id_type))
            row.addElement(_mc(str(count)))
            tab_suci.addElement(row)

        tab_suci.addElement(TableRow())

        hdr_sc = TableRow()
        _add_bold_header_cells(hdr_sc, ("SUCI Scheme Type", "Count"))
        tab_suci.addElement(hdr_sc)
        for scheme, count in sorted(suci_stats.scheme_counts.items()):
            row = TableRow()
            row.addElement(_mc(scheme))
            row.addElement(_mc(str(count)))
            tab_suci.addElement(row)

    # Add VoPS Stats tab
    if vops_stats is not None:
        tab_vops = Table(name="VoPS Stats")
        doc.spreadsheet.addElement(tab_vops)

        def _vc(text: str, bold: bool = False) -> TableCell:
            if bold:
                cell = TableCell(stylename=bold_cell)
                cell.addElement(P(stylename=header_para, text=text))
            else:
                cell = TableCell()
                cell.addElement(P(text=text))
            return cell

        def _vops_status(supported: int, not_supported: int) -> str:
            if supported == 0 and not_supported == 0:
                return "N/A"
            return "Fail" if not_supported > 0 else "Pass"

        # ── Summary section (per generation) ─────────────────────────────
        hdr_sum = TableRow()
        _add_bold_header_cells(hdr_sum, ("Generation", "Supported", "Not Supported", "Status"))
        tab_vops.addElement(hdr_sum)

        for gen, sup, not_sup in (
            ("4G", vops_stats.supported_4g, vops_stats.not_supported_4g),
            ("5G", vops_stats.supported_5g, vops_stats.not_supported_5g),
        ):
            status = _vops_status(sup, not_sup)
            row = TableRow()
            row.addElement(_vc(gen))
            row.addElement(_vc(str(sup)))
            row.addElement(_vc(str(not_sup)))
            row.addElement(_vc(status, bold=True))
            tab_vops.addElement(row)

        # ── Per-quintuplet breakdown ──────────────────────────────────────
        if vops_stats.quintuplets:
            tab_vops.addElement(TableRow())   # blank separator row

            hdr_qui = TableRow()
            _add_bold_header_cells(hdr_qui, ("Generation", "MCC", "MNC", "TAC", "PCI", "ARFCN", "Supported", "Not Supported", "Status"))
            tab_vops.addElement(hdr_qui)

            for q in vops_stats.quintuplets:
                row = TableRow()
                row.addElement(_vc(q.generation))
                row.addElement(_vc(q.mcc))
                row.addElement(_vc(q.mnc))
                row.addElement(_vc(q.tac))
                row.addElement(_vc(q.pci))
                row.addElement(_vc(q.arfcn))
                row.addElement(_vc(str(q.supported)))
                row.addElement(_vc(str(q.not_supported)))
                row.addElement(_vc(q.status, bold=True))
                tab_vops.addElement(row)

    # Add SIP IPSec Stats tab
    if sip_ipsec_stats is not None:
        tab_sip = Table(name="SIP IPSec Stats")
        doc.spreadsheet.addElement(tab_sip)

        def _sc(text: str, bold: bool = False) -> TableCell:
            if bold:
                cell = TableCell(stylename=bold_cell)
                cell.addElement(P(stylename=header_para, text=text))
            else:
                cell = TableCell()
                cell.addElement(P(text=text))
            return cell

        hdr_sip = TableRow()
        _add_bold_header_cells(hdr_sip, ("Criteria", "Pass (valid EAlg)", "Fail (null/absent EAlg)", "Status"))
        tab_sip.addElement(hdr_sip)
        row_sip = TableRow()
        row_sip.addElement(_sc("IPSec EAlg at SIP 401"))
        row_sip.addElement(_sc(str(sip_ipsec_stats.pass_count)))
        row_sip.addElement(_sc(str(sip_ipsec_stats.fail_count)))
        row_sip.addElement(_sc(sip_ipsec_stats.status, bold=True))
        tab_sip.addElement(row_sip)

    # Add UE Cap Security Stats tab
    if ue_cap_security_stats is not None:
        tab_ucs = Table(name="UE Cap Security Stats")
        doc.spreadsheet.addElement(tab_ucs)

        def _cc(text: str, bold: bool = False) -> TableCell:
            if bold:
                cell = TableCell(stylename=bold_cell)
                cell.addElement(P(stylename=header_para, text=text))
            else:
                cell = TableCell()
                cell.addElement(P(text=text))
            return cell

        def _ucs_status(before: int, after: int, unknown: int) -> str:
            if before == 0 and after == 0 and unknown == 0:
                return "N/A"
            return "Fail" if before > 0 else "Pass"

        hdr_ucs = TableRow()
        _add_bold_header_cells(hdr_ucs, ("Generation", "Before Security", "After Security", "Unknown", "Status"))
        tab_ucs.addElement(hdr_ucs)

        for gen, before, after, unknown in (
            ("4G", ue_cap_security_stats.before_4g, ue_cap_security_stats.after_4g, ue_cap_security_stats.unknown_4g),
            ("5G", ue_cap_security_stats.before_5g, ue_cap_security_stats.after_5g, ue_cap_security_stats.unknown_5g),
        ):
            status = _ucs_status(before, after, unknown)
            row = TableRow()
            row.addElement(_cc(gen))
            row.addElement(_cc(str(before)))
            row.addElement(_cc(str(after)))
            row.addElement(_cc(str(unknown)))
            row.addElement(_cc(status, bold=True))
            tab_ucs.addElement(row)

    _GEN_COLS = ["2G CS", "2G PS", "3G CS", "3G PS", "4G", "5G"]

    def _summ_cell(text: str) -> TableCell:
        cell = TableCell()
        if text == "Pass":
            cell.addElement(P(stylename=pass_para, text=text))
        elif text == "Fail":
            cell.addElement(P(stylename=fail_para, text=text))
        else:
            cell.addElement(P(text=text))
        return cell

    def _enc_status_s(col: str) -> str:
        if col == "2G CS":
            s = summary_by_name.get("2G CS")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "2G PS":
            s = summary_by_name.get("2G PS")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "3G CS":
            s = summary_by_name.get("3G ENC CS") or summary_by_name.get("3G ENC")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "3G PS":
            s = summary_by_name.get("3G ENC PS") or summary_by_name.get("3G ENC")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "4G":
            cands = [summary_by_name[k] for k in ("4G RRC ENC", "4G NAS ENC", "4G UP ENC") if k in summary_by_name]
            return "-" if not cands else ("Fail" if any(c.weak_in_use for c in cands) else "Pass")
        if col == "5G":
            cands = [summary_by_name[k] for k in ("5G RRC ENC", "5G NAS ENC", "5G SA UP ENC", "5G NSA UP ENC") if k in summary_by_name]
            return "-" if not cands else ("Fail" if any(c.weak_in_use for c in cands) else "Pass")
        return "-"

    def _int_status_s(col: str) -> str:
        if col in ("2G CS", "2G PS"):
            return "-"
        if col == "3G CS":
            s = summary_by_name.get("3G INT CS") or summary_by_name.get("3G INT")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "3G PS":
            s = summary_by_name.get("3G INT PS") or summary_by_name.get("3G INT")
            return "-" if s is None else ("Fail" if s.weak_in_use else "Pass")
        if col == "4G":
            cands = [summary_by_name[k] for k in ("4G RRC INT", "4G NAS INT", "4G UP INT") if k in summary_by_name]
            return "-" if not cands else ("Fail" if any(c.weak_in_use for c in cands) else "Pass")
        if col == "5G":
            cands = [summary_by_name[k] for k in ("5G RRC INT", "5G NAS INT", "5G SA UP INT", "5G NSA UP INT") if k in summary_by_name]
            return "-" if not cands else ("Fail" if any(c.weak_in_use for c in cands) else "Pass")
        return "-"

    def _tmsi_status_s(col: str, check_fn) -> str:
        label = _tmsi_label_map_s.get(col)
        if not label:
            return "-"
        m = metrics_map.get(label)
        if not m:
            return "-"
        try:
            ok = check_fn(m)
        except Exception:
            ok = None
        return "-" if ok is None else ("Pass" if ok else "Fail")

    def _paging_status_s(col: str) -> str:
        if not paging_stats:
            return "-"
        gen_key = {"2G PS": "2G", "3G PS": "3G", "4G": "4G", "5G": "5G"}.get(col)
        if gen_key is None:
            return "-"
        st = paging_stats.get(gen_key, {})
        if not st or int(st.get("messages", 0) or 0) == 0:
            return "-"
        return "Pass" if int(st.get("imsi_ids", 0) or 0) == 0 else "Fail"

    def _suci_status_s(col: str) -> str:
        if col != "5G" or suci_stats is None:
            return "-"
        if suci_stats.completed == 0:
            return "-"
        return "Fail" if suci_stats.scheme_counts.get("NULL scheme", 0) > 0 else "Pass"

    def _vops_status_s(col: str) -> str:
        if vops_stats is None:
            return "-"
        if col == "4G":
            sup, not_sup = vops_stats.supported_4g, vops_stats.not_supported_4g
        elif col == "5G":
            sup, not_sup = vops_stats.supported_5g, vops_stats.not_supported_5g
        else:
            return "-"
        if sup == 0 and not_sup == 0:
            return "-"
        return "Fail" if not_sup > 0 else "Pass"

    def _uec_status_s(col: str) -> str:
        if ue_cap_security_stats is None:
            return "-"
        if col == "4G":
            before, after, unk = ue_cap_security_stats.before_4g, ue_cap_security_stats.after_4g, ue_cap_security_stats.unknown_4g
        elif col == "5G":
            before, after, unk = ue_cap_security_stats.before_5g, ue_cap_security_stats.after_5g, ue_cap_security_stats.unknown_5g
        else:
            return "-"
        if before == 0 and after == 0 and unk == 0:
            return "-"
        return "Fail" if before > 0 else "Pass"
    
    def _sip_ipsec_status_s(col: str) -> str:
        if sip_ipsec_stats is None:
            return "-"
        if col not in ("4G", "5G"):
            return "-"
        if sip_ipsec_stats.pass_count == 0 and sip_ipsec_stats.fail_count == 0:
            return "-"
        return "Fail" if sip_ipsec_stats.fail_count > 0 else "Pass"

    tab_summ = Table(name="Summary")
    hdr_summ = TableRow()
    _add_bold_header_cells(hdr_summ, ["Category", "Criteria"] + _GEN_COLS)
    tab_summ.addElement(hdr_summ)

    def _add_summ_row(category: str, criteria: str, values: List[str]) -> None:
        row = TableRow()
        cell = TableCell(); cell.addElement(P(text=category)); row.addElement(cell)
        cell = TableCell(); cell.addElement(P(text=criteria)); row.addElement(cell)
        for v in values:
            row.addElement(_summ_cell(v))
        tab_summ.addElement(row)

    _add_summ_row("Cryptography Usage", "Weak/Null Encryption",
        [_enc_status_s(c) for c in _GEN_COLS])
    _add_summ_row("Cryptography Usage", "Weak/Null Integrity",
        [_int_status_s(c) for c in _GEN_COLS])
    _add_summ_row("TMSI Randomness", "Reuse Rate",
        [_tmsi_status_s(c, lambda m, _t=_collision_max_s: (m.get("collision_rate") < _t) if (m.get("collision_rate") is not None and m.get("samples", 0) >= 2) else None) for c in _GEN_COLS])
    _add_summ_row("TMSI Randomness", "Shannon Entropy",
        [_tmsi_status_s(c, lambda m, _t=_h_norm_min_s: (m.get("H_values_norm") > _t) if (m.get("H_values_norm") is not None and m.get("unique", 0) > 1) else None) for c in _GEN_COLS])
    _add_summ_row("TMSI Randomness", "Hamming Distance",
        [_tmsi_status_s(c, lambda m, _t=_succ_hamm_p_min_s: (m.get("succ_hd_p") > _t) if (m.get("succ_hd_pairs", 0) > 0 and m.get("succ_hd_p") is not None) else (False if m.get("unique", 0) <= 1 else None)) for c in _GEN_COLS])
    _add_summ_row("TMSI Randomness", "Nibbles Distribution",
        [_tmsi_status_s(c, lambda m, _t=_chi2_p_min_s: (m.get("chi2_nibbles_p") > _t) if m.get("chi2_nibbles_p") is not None else (False if m.get("unique", 0) <= 1 else None)) for c in _GEN_COLS])
    _add_summ_row("IMSI Exposure", "IMSI in Paging",
        [_paging_status_s(c) for c in _GEN_COLS])
    _add_summ_row("IMSI Exposure", "No encryption on SUCI",
        [_suci_status_s(c) for c in _GEN_COLS])
    _add_summ_row("Forced downgrade", "No VoPS for voice calls",
        [_vops_status_s(c) for c in _GEN_COLS])
    _add_summ_row("VoPS Security", "No IPSec on SIP 401",
        [_sip_ipsec_status_s(c) for c in _GEN_COLS])
    _add_summ_row("Exposed UE information", "UE Capabilities without security",
        [_uec_status_s(c) for c in _GEN_COLS])

    tab_summ.parentNode = doc.spreadsheet
    doc.spreadsheet.childNodes.insert(0, tab_summ)

    doc.save(str(output_path))
    return output_path
