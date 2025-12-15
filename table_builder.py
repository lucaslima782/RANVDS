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
    country: str,
    operator: str,
    translations_cfg: Dict[str, Any],
    out_fn: str,
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
    summary = Table(name="UE Capability")
    doc.spreadsheet.addElement(summary)
    
    # Header of the summary table
    hdr = TableRow()
    headers = ["Country","Operator","", "Algorithm","Capability","","Algorithm","Chosen"]
    for h in headers:
        cell = TableCell()
        cell.addElement(P(text=h))
        hdr.addElement(cell)
    summary.addElement(hdr)
    
    # Calculate the total number of rows needed for the summary table
    total_rows = max(len(order), len(used_order))
    
    # Fill the summary table with the results
    for i in range(total_rows):
        row = TableRow()
        
        # First column: country and operator
        if i == 0:
            c1 = TableCell(); c1.addElement(P(text=country)); row.addElement(c1)
            c2 = TableCell(); c2.addElement(P(text=operator)); row.addElement(c2)
        else:
            row.addElement(TableCell()); row.addElement(TableCell())
        
        # Empty column to separate the information
        row.addElement(TableCell())
        
        # Information about supported algorithms
        if i < len(order):
            name = order[i]
            registro = alg_res.get(name)
            if registro:
                v: str = registro.get("chosen_value", "")
            else:
                v = ""
            c3 = TableCell(); c3.addElement(P(text=name)); row.addElement(c3)
            c4 = TableCell(); c4.addElement(P(text=interpret_value(name, v))); row.addElement(c4)
        else:
            row.addElement(TableCell()); row.addElement(TableCell())
        
        # Empty column to separate the information
        row.addElement(TableCell())
        
        # Information about used algorithms
        if i < len(used_order):
            name2 = used_order[i]
            registro2 = used_res.get(name2)
            chosen_text = ""
            if registro2:
                v2: str = registro2.get("chosen_value", "")
                all_vals: List[str] = registro2.get("all_values") or []
                labels: List[str] = []
                source_vals = all_vals if all_vals else ([v2] if v2 else [])
                for raw_code in source_vals:
                    label = interpret_used_value(name2, raw_code)
                    if label and label not in labels:
                        labels.append(label)
                chosen_text = ", ".join(labels)
            c6 = TableCell(); c6.addElement(P(text=name2)); row.addElement(c6)
            c7 = TableCell(); c7.addElement(P(text=chosen_text)); row.addElement(c7)
        else:
            row.addElement(TableCell()); row.addElement(TableCell())
        
        # Add the row to the summary table
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
    out_path = Path(out_fn)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))


def build_security_ods(output_path: Path, summaries: List["GenerationSummary"], identities: List["IdentityRecord"] | None = None, paging_stats: Dict[str, Dict[str, int]] | None = None, ts_margin_seconds: float = 0.0, tmsi_thresholds: Dict[str, float] | None = None) -> Path:
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

    doc.save(str(output_path))
    return output_path
