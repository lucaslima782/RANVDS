# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""pcapanalyzer: extract algorithms, identities, and paging records from tshark output.

This module provides helpers used by RANVDS to parse 2G–5G captures.
"""
from collections import defaultdict
import configparser
from typing import Any, DefaultDict, Dict, List, Tuple, Optional


# -----------------------------------------------------------------------------
# ID CONVERSION UTILITIES
# -----------------------------------------------------------------------------

def decimal_id_to_hex(id_str: str, prefix: bool = True, even_length: bool = True, min_nibbles: Optional[int] = None) -> str:
    """Convert an identifier string to hexadecimal.

    Behavior:
    - If it contains HEX indicators ("0x"/"0X" or letters A-F/a-f), just NORMALIZE:
      lowercase, apply optional padding and prefix according to parameters.
    - Otherwise, if it is pure decimal, convert to HEX.
    - Return empty string for invalid inputs.

    Parameters:
    - prefix: add '0x' to the return value.
    - even_length: force an even number of HEX digits by left-padding with zero.
    - min_nibbles: minimum width in nibbles (left-pad with zeros to reach it).
    """
    if id_str is None:
        return ""
    s = str(id_str).strip()
    if not s:
        return ""

    def _apply_padding(h: str) -> str:
        """Pad hex string to satisfy min_nibbles and even_length constraints."""
        if min_nibbles is not None and len(h) < min_nibbles:
            h = h.zfill(min_nibbles)
        if even_length and (len(h) % 2 == 1):
            h = '0' + h
        return h

    # HEX with prefix 0x/0X
    if s.startswith(("0x", "0X")):
        hex_digits = s[2:]
        if not hex_digits:
            return ""
        if not all(c in "0123456789abcdefABCDEF" for c in hex_digits):
            return ""
        hx = _apply_padding(hex_digits.lower())
        return ('0x' + hx) if prefix else hx

    # If it contains letters A-F/a-f, treat as raw HEX
    if any(c.isalpha() for c in s):
        if not all(c in "0123456789abcdefABCDEF" for c in s):
            return ""
        hx = _apply_padding(s.lower())
        return ('0x' + hx) if prefix else hx

    # Pure decimal → convert
    if s.isdigit():
        try:
            n = int(s, 10)
        except Exception:
            return ""
        hx = format(n, 'x')
        hx = _apply_padding(hx)
        return ('0x' + hx) if prefix else hx

    return ""


# -----------------------------------------------------------------------------
# CRYPTOGRAPHY FUNCTIONS
# -----------------------------------------------------------------------------

# 2G Voice

def extract_2g_voice_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract 2G (GSM) voice confidentiality algorithm information.

    Correlate relevant fields from signaling packets.

    Args:
        packets: List of packet dicts extracted from the PCAP.
        used_algorithms_fields: Mapping for algorithms-in-use fields by name.
        gsm_fields: GSM-specific field mappings.
        misc_fields: Generic/miscellaneous field mappings.
        translations_cfg: Translations and friendly names for some fields.

    Returns:
        dict: Mapping algorithm → list of usage records.
    """
    results = defaultdict(list)

    # --- Mapping of field names of interest (from configuration) ---
    ts_field = misc_fields.get("Timestamp")  # Packet timestamp field
    frame_field = misc_fields.get("Frame")   # Packet frame number field
    gsmtap_arfcn_field = misc_fields.get("ARFCN")  # Radio channel (ARFCN)
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_payload_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType2")

    # GSM-specific fields
    msg_rr_type_field = gsm_fields.get("DTAPRRType")
    if msg_rr_type_field is not None:
        msg_rr_type_SIT6value = translations_cfg.get(msg_rr_type_field, "System Information Type 6")
    lac_field = gsm_fields.get("LAC_2G")
    cell_field = gsm_fields.get("CellID_2G")
    mcc_field = gsm_fields.get("MCC_2G")
    mnc_field = gsm_fields.get("MNC_2G")

    # Algorithm-in-use field (e.g., "2G CS C")
    algo_field = used_algorithms_fields.get("2G CS C")

    # --- Preprocessing: sort packets by frame number for efficient temporal searches ---
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))

    # --- Main loop: iterate over packets to extract relevant data ---
    for pkt in packets:
        # Get the algorithm-in-use value for this packet
        algo = pkt["fields"].get(algo_field)
        # If there is no algorithm identified, skip this packet
        if not algo:
            continue

        # Extract key packet parameters
        version = pkt["fields"].get(gsmtap_version_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        payload = pkt["fields"].get(gsmtap_payload_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        message = pkt["fields"].get(msg_rr_type_field)

        # Initialize variables for cell and location data
        lac = cell = mcc = mnc = ""
        closest_ref = None  # Reference to the closest SIT6 packet
        closest_frame = -1
        next_ref = None

        # Find the closest SIT6 packet to retrieve cell and location information
        next_frame = None
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if ref["fields"].get(msg_rr_type_field) == msg_rr_type_SIT6value and ref["fields"].get(gsmtap_arfcn_field) == arfcn:
                if ref_frame < frame and ref_frame > closest_frame:
                    closest_frame = ref_frame
                    closest_ref = ref
                elif ref_frame > frame and (next_frame is None or ref_frame < next_frame):
                    next_frame = ref_frame
                    next_ref = ref
        if closest_ref:
            lac  = closest_ref["fields"].get(lac_field, "")
            cell = closest_ref["fields"].get(cell_field, "")
            mcc  = closest_ref["fields"].get(mcc_field, "")
            mnc  = closest_ref["fields"].get(mnc_field, "")
        elif next_ref:
            lac  = next_ref["fields"].get(lac_field, "")
            cell = next_ref["fields"].get(cell_field, "")
            mcc  = next_ref["fields"].get(mcc_field, "")
            mnc  = next_ref["fields"].get(mnc_field, "")

        # Append the result to the list for this algorithm
        results[algo].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_payload_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "MessageField": msg_rr_type_field,
            "Message": message,
            "ARFCN": arfcn,
            "LAC": lac,
            "Cell_ID": cell,
            "Algorithm": algo
        })
    return results

# 2G Data
def extract_2g_data_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> Dict[str, List[Dict[str, str]]]:
    """
    Extract 2G (GPRS) data confidentiality algorithm information.

    Correlate relevant fields from signaling packets to build a technical summary.

    Args:
        packets: List of packet dicts extracted from the PCAP.
        used_algorithms_fields: Mapping for algorithms-in-use fields by name.
        gsm_fields: GSM-specific field mappings.
        misc_fields: Generic/miscellaneous field mappings.
        translations_cfg: Translations and friendly names for some fields.

    Returns:
        dict: Mapping algorithm → list of usage records.
    """
    results = defaultdict(list)

    # --- Field name mapping (from configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Packet timestamp field
    frame_field = misc_fields.get("Frame")   # Packet frame number field
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_payload_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType")

    # GSM-specific fields
    msg_gmm_type_field = gsm_fields.get("DTAPMsgTypeData")
    if msg_gmm_type_field is not None:
        msg_gmm_type_AttAcptvalue = translations_cfg.get(msg_gmm_type_field, "Attach Accept")
    lac_field = gsm_fields.get("LAC_2G")
    mcc_field = gsm_fields.get("MCC_2G_Dados")
    mnc_field = gsm_fields.get("MNC_2G_Dados")
    rac_field = gsm_fields.get("RAC_2G_Dados")

    # Algorithm-in-use field (e.g., "2G PS C")
    algo_field = used_algorithms_fields.get("2G PS C")

    # --- Preprocessing: sort packets by frame number for efficient temporal searches ---
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))

    # --- Main loop: iterate over packets to extract relevant data ---
    for pkt in packets:
        # Get the algorithm-in-use value for this packet
        algo = pkt["fields"].get(algo_field)
        # If no algorithm is identified, skip this packet
        if not algo:
            continue

        # Extract key packet parameters
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_payload_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(msg_gmm_type_field)

        # Find the nearest Attach Accept to extract MCC, MNC and LAC
        lac = rac = mcc = mnc = ""
        closest_ref = None
        closest_frame = None
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if ref_frame > frame and ref["fields"].get(msg_gmm_type_field) == msg_gmm_type_AttAcptvalue:
                if closest_frame is None or ref_frame < closest_frame:
                    closest_ref = ref
                    closest_frame = ref_frame
        if closest_ref:
            lac  = closest_ref["fields"].get(lac_field, "")
            rac  = closest_ref["fields"].get(rac_field, "")
            mcc  = closest_ref["fields"].get(mcc_field, "")
            mnc  = closest_ref["fields"].get(mnc_field, "")
        results[algo].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_payload_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "MessageField": msg_gmm_type_field,
            "Message": message,
            "LAC": lac,
            "RAC": rac,
            "Algorithm": algo
        })
    return results

# Helper for 3G
def extract_3g_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    umts_fields: Dict[str, str],
    misc_fields: Dict[str, str]
) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, List[Dict[str, str]]]]:
    """
    Extract 3G (UMTS) confidentiality and integrity algorithms.

    Correlate relevant fields from signaling packets.

    Args:
        packets: List of packet dicts extracted from the PCAP.
        used_algorithms_fields: Mapping for algorithms-in-use fields by name.
        umts_fields: UMTS/3G-specific field mappings.
        misc_fields: Generic/miscellaneous field mappings.

    Returns:
        Tuple[dict, dict]: Two dicts grouping results by confidentiality and integrity algorithm, respectively.
    """
    results1 = defaultdict(list)  # Confidentiality results
    results2 = defaultdict(list)  # Integrity results

    # --- Field name mapping (from configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Packet timestamp field
    frame_field = misc_fields.get("Frame")   # Packet frame number field
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_payload_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType2")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")

    # UMTS-specific fields
    message_field = umts_fields.get("RRCMsgType")
    if message_field is not None:
        message_field_verify = message_field + "_DL-DCCH"
    sib_type_field = umts_fields.get("SIB_TYPE_3G")
    cipher_field = used_algorithms_fields.get("3G C")      # Confidentiality algorithm
    integrity_field = used_algorithms_fields.get("3G I")   # Integrity algorithm
    rnc_field = umts_fields.get("RNC_3G")
    cell_field = umts_fields.get("CellID_3G")
    mcc_field = umts_fields.get("MCC_3G")
    mnc_field = umts_fields.get("MNC_3G")
    domain_field = umts_fields.get("DOMAIN")

    # --- Create index for fast packet lookup by ARFCN (radio channel) ---
    arfcn_index = defaultdict(list)
    for pkt in packets:
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        if arfcn:
            arfcn_index[arfcn].append(pkt)

    # --- Main loop: extract confidentiality/integrity data from packets ---
    for pkt in packets:
        cipher = pkt["fields"].get(cipher_field)
        integ  = pkt["fields"].get(integrity_field)
        # Only process if at least one of the algorithms is present
        if not (cipher or integ):
            continue

        ts     = pkt["fields"].get(ts_field)
        frame  = pkt["fields"].get(frame_field)
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_payload_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        arfcn  = pkt["fields"].get(gsmtap_arfcn_field)
        domain = pkt["fields"].get(domain_field)
        message = pkt["fields"].get(message_field)
        frame = int(frame)

        # Find the closest prior SIB3 (for RNC and Cell ID)
        rnc = cell = ""
        sib3_frame = -1
        for ref in arfcn_index[arfcn]:
            ref_frame = ref["fields"].get(frame_field)
            sib = ref["fields"].get(sib_type_field)
            if ref_frame and sib == "3":
                ref_frame = int(ref_frame)
                if ref_frame < frame and ref_frame > sib3_frame:
                    rnc  = ref["fields"].get(rnc_field, "")
                    cell = ref["fields"].get(cell_field, "")
                    sib3_frame = ref_frame
        # Find the closest prior SIB0 (for MCC and MNC)
        mcc = mnc = ""
        sib0_frame = -1
        for ref in arfcn_index[arfcn]:
            ref_frame = ref["fields"].get(frame_field)
            sib = ref["fields"].get(sib_type_field)
            if ref_frame and sib == "0":
                ref_frame = int(ref_frame)
                if ref_frame < frame and ref_frame > sib0_frame:
                    mcc  = ref["fields"].get(mcc_field, "")
                    mnc  = ref["fields"].get(mnc_field, "")
                    sib0_frame = ref_frame

        # Store results
        if cipher:
            results1[cipher].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": gsmtap_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "MessageField": message_field_verify,
                "Domain": domain,
                "Message": message,
                "ARFCN": arfcn,
                "RNC_ID": rnc,
                "Cell_ID": cell,
                "Algorithm": cipher
            })
        if integ:
            results2[integ].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": gsmtap_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "MessageField": message_field_verify,
                "Domain": domain,
                "Message": message,
                "ARFCN": arfcn,
                "RNC_ID": rnc,
                "Cell_ID": cell,
                "Algorithm": integ
            })

    return results1, results2

# Helper for 4G
# 4G (RRC)
def extract_4g_rrc_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    lterrc_fields: Dict[str, str],
    misc_fields: Dict[str, str]
) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, List[Dict[str, str]]]]:
    """
    Extract 4G (LTE RRC) confidentiality and integrity algorithms.

    Correlate relevant fields from signaling packets.

    Args:
        packets: List of packet dicts extracted from the PCAP.
        used_algorithms_fields: Mapping for algorithms-in-use fields by name.
        lterrc_fields: LTE RRC-specific field mappings.
        misc_fields: Generic/miscellaneous field mappings.

    Returns:
        Tuple[dict, dict]: Two dicts grouping results by confidentiality and integrity algorithm, respectively.
    """
    results1 = defaultdict(list)  # Confidentiality results
    results2 = defaultdict(list)  # Integrity results

    # --- Field mapping for interest fields (according to the configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Timestamp field of the packet
    frame_field = misc_fields.get("Frame")   # Frame number of the packet
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    gsmtap_pci_field = misc_fields.get("PCIV3")

    # LTE RRC-specific fields
    tac_field = lterrc_fields.get("TAC_4GRRC")
    cell_field = lterrc_fields.get("CellID_4GRRC")
    plmn_field = lterrc_fields.get("PLMN_4GRRC")
    sib1_field = lterrc_fields.get("SIB1_4GRRC")
    message_field = lterrc_fields.get("C1Message")
    if message_field is not None:
        message_field_verify = message_field + "_DL-DCCH"

    # Used algorithm fields
    cipher_field = used_algorithms_fields.get("4G RRC C")      # Confidentiality algorithm
    integrity_field = used_algorithms_fields.get("4G RRC I")   # Integrity algorithm

    # --- Create index for fast packet lookup by ARFCN (radio channel) ---
    arfcn_index = defaultdict(list)
    for pkt in packets:
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        if version == "2":
            gsmtap_arfcn_field = misc_fields.get("ARFCN")
        elif version == "3":
            gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
        else:
            gsmtap_arfcn_field = misc_fields.get("ARFCN")
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        if arfcn:
            arfcn_index[arfcn].append(pkt)

    # (function continues: main loop and extraction logic below)

            gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
        else:
            gsmtap_arfcn_field = None
        arfcn = pkt["fields"].get(gsmtap_arfcn_field) if gsmtap_arfcn_field else None
        if arfcn is not None:
            arfcn_index[arfcn].append(pkt)

    # Process packets
    for pkt in packets:
        cipher = pkt["fields"].get(cipher_field)
        integ  = pkt["fields"].get(integrity_field)
        if not (cipher or integ):
            continue
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        if version == "2":
            gsmtap_arfcn_field = misc_fields.get("ARFCN")
            gsmtap_payload_field = misc_fields.get("Payload")
            gsmtap_sub_type_field = misc_fields.get("SubType2")
        elif version == "3":
            gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
            gsmtap_payload_field = misc_fields.get("PayloadV3")
            gsmtap_sub_type_field = misc_fields.get("SubTypeV3")
        else:
            gsmtap_arfcn_field = None
        ts     = pkt["fields"].get(ts_field)
        frame  = pkt["fields"].get(frame_field)
        payload = pkt["fields"].get(gsmtap_payload_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        pci  = pkt["fields"].get(gsmtap_pci_field) if version == "3" else None
        frame = int(frame)

        # Find the closest prior SIB1, or the next one if none prior, to retrieve (TAC, CellID, PLMN)
        tac = cell = plmn = ""
        sib1_frame = -1
        sib1_next_frame = None
        sib1_next = None
        for ref in arfcn_index.get(arfcn, []):
            ref_frame = ref["fields"].get(frame_field)
            sib1 = ref["fields"].get(sib1_field)
            if ref_frame and sib1:
                ref_frame = int(ref_frame)
                if ref_frame < frame and ref_frame > sib1_frame:
                    tac  = ref["fields"].get(tac_field, "")
                    cell = ref["fields"].get(cell_field, "")
                    plmn = ref["fields"].get(plmn_field, "")
                    sib1_frame = ref_frame
                elif ref_frame > frame and (sib1_next_frame is None or ref_frame < sib1_next_frame):
                    sib1_next_frame = ref_frame
                    sib1_next = ref
        if sib1_frame == -1 and sib1_next:
            tac  = sib1_next["fields"].get(tac_field, "")
            cell = sib1_next["fields"].get(cell_field, "")
            plmn = sib1_next["fields"].get(plmn_field, "")

        # Split PLMN into MCC/MNC automatically when possible
        mcc = ""
        mnc = ""
        if plmn:
            try:
                # Accepts formats like "7,2,4,1,1" or list/tuple
                if isinstance(plmn, (list, tuple)):
                    digits = [str(d).strip().lower() for d in plmn]
                else:
                    digits = [s.strip().lower() for s in str(plmn).split(',') if s.strip()]

                # Normalize digits and padding marker (f/0xF/15)
                norm = []
                for d in digits:
                    if d in ("f", "0xf", "15"):
                        norm.append("f")
                    else:
                        # keep only the last nibble when hex like 0x7
                        if d.startswith("0x") and len(d) > 2:
                            norm.append(d[-1])
                        else:
                            norm.append(d)

                # Build MCC/MNC according to the number of digits
                if len(norm) >= 6:
                    mcc = ''.join(norm[0:3])
                    if norm[5] == 'f':
                        mnc = ''.join(norm[3:5])
                    else:
                        mnc = ''.join(norm[3:6])
                elif len(norm) == 5:
                    mcc = ''.join(norm[0:3])
                    mnc = ''.join(norm[3:5])
                elif len(norm) >= 3:
                    mcc = ''.join(norm[0:3])
                    mnc = ''.join(norm[3:])
                # remove any remaining non-numeric characters
                mcc = ''.join(ch for ch in mcc if ch.isdigit())
                mnc = ''.join(ch for ch in mnc if ch.isdigit())
            except Exception:
                # On any error, keep MCC/MNC empty to avoid breaking the flow
                mcc = mnc = ""

        # Create the results dictionary
        if cipher:
            results1[cipher].append(
                {
                    "Timestamp": ts,
                    "Frame": frame,
                    "Version": version,
                    "PayloadField": gsmtap_payload_field,
                    "Payload": payload,
                    "SubTypeField": gsmtap_sub_type_field,
                    "SubType": sub_type,
                    "MessageField": message_field_verify,
                    "Message": message,
                    "MCC": mcc,
                    "MNC": mnc,
                    "ARFCN": arfcn,
                    "TAC": tac,
                    "Cell_ID": cell,
                    "PCI": pci,
                    "Algorithm": cipher
                }
            )
        if integ:
            results2[integ].append(
                {
                    "Timestamp": ts,
                    "Frame": frame,
                    "Version": version,
                    "PayloadField": gsmtap_payload_field,
                    "Payload": payload,
                    "SubTypeField": gsmtap_sub_type_field,
                    "SubType": sub_type,
                    "MessageField": message_field_verify,
                    "Message": message,
                    "MCC": mcc,
                    "MNC": mnc,
                    "ARFCN": arfcn,
                    "TAC": tac,
                    "Cell_ID": cell,
                    "PCI": pci,
                    "Algorithm": integ
                }
            )
    return results1, results2

# 4G (NAS)
def extract_4g_nas_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    ltenas_fields: Dict[str, str],
    misc_fields: Dict[str, str]
) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, List[Dict[str, str]]]]:
    """
    Extract 4G (LTE NAS) confidentiality and integrity algorithms.

    Correlate relevant fields from signaling packets.

    Args:
        packets (list): List of dictionaries, each representing a packet extracted from the PCAP.
        used_algorithms_fields (dict): Algo
        ltenas_fields (dict): Fields specific to LTE NAS.
        misc_fields (dict): Generic/miscellaneous fields.

    Returns:
        Tuple[dict, dict]: Two dictionaries grouping results by confidentiality and integrity algorithm, respectively.
    """
    results1 = defaultdict(list)  # Confidentiality results
    results2 = defaultdict(list)  # Integrity results

    # --- Field mapping for interest fields (according to the configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Timestamp field of the packet
    frame_field = misc_fields.get("Frame")   # Frame number of the packet
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    # Fields specific to LTE NAS
#    message_field = ltenas_fields.get("NASMsgType")
#    message_field_5g = ltenas_fields.get("5G_NASMsgType")
    # Fields for algorithms used
    cipher_field = used_algorithms_fields.get("4G NAS C")  # Confidentiality algorithm
    integrity_field = used_algorithms_fields.get("4G NAS I")  # Integrity algorithm

    # --- Main loop: iterates through all packets to extract confidentiality/integrity data ---
    for pkt in packets:
        enc = pkt["fields"].get(cipher_field)
        integ = pkt["fields"].get(integrity_field)
        # Only process if at least one of the algorithms is present
        if not (enc or integ):
            continue

        ts = pkt["fields"].get(ts_field)
        frame = pkt["fields"].get(frame_field)
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        # Select payload and sub_type fields based on header version
        if version == "2":
            gsmtap_payload_field = misc_fields.get("Payload")
            gsmtap_sub_type_field = misc_fields.get("SubType2")
        elif version == "3":
            gsmtap_payload_field = misc_fields.get("PayloadV3")
            gsmtap_sub_type_field = misc_fields.get("SubTypeV3")
        else:
            gsmtap_payload_field = misc_fields.get("Payload")
            gsmtap_sub_type_field = misc_fields.get("SubType2")
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        payload = pkt["fields"].get(gsmtap_payload_field)
        if payload in ["0x0503", "0x0504"]: # NR RRC and NR NAS
            message_field = ltenas_fields.get("5G_NASMsgType")
            message = pkt["fields"].get(message_field)
        elif payload in ["0x0403", "0x0404"]: #4G RRC e 4G NAS
            message_field = ltenas_fields.get("NASMsgType")
            message = pkt["fields"].get(message_field)
        else:
            message_field = None
            message = None
        # Add results to dictionaries
        results1[enc].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_payload_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field,
            "Message": message,
            "Algorithm": enc
        })
        results2[integ].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_payload_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field,
            "Message": message,
            "Algorithm": integ
        })
    return results1, results2

# Auxiliary function for 5G RRC
def extract_5g_rrc_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    nrrrc_fields: Dict[str, str],
    misc_fields: Dict[str, str]
) -> Dict[str, List[Dict[str, str]]]:
    """
    Extract 5G (NR RRC) confidentiality and integrity algorithms.

    Correlate relevant fields from signaling packets.

    Args:
        packets (list): List of dictionaries, each representing a packet extracted from the PCAP.
        used_algorithms_fields (dict): Fields for algorithms used, mapped by name.
        nrrrc_fields (dict): Fields specific to 5G RRC.
        misc_fields (dict): Generic/miscellaneous fields.

    Returns:
        dict: Dictionary grouping results by confidentiality algorithm.
    """
    results1 = defaultdict(list)  # Confidentiality results
    results2 = defaultdict(list)  # Integrity results

    # --- Field mapping for interest fields (according to the configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Timestamp field of the packet
    frame_field = misc_fields.get("Frame")   # Frame number of the packet
    version_field = misc_fields.get("VersionV3")
    payload_field = misc_fields.get("PayloadV3")
    sub_type_field = misc_fields.get("SubTypeV3")
    arfcn_field = misc_fields.get("ARFCNV3")
    cell_field = misc_fields.get("PCIV3")

    # Field for algorithm of confidentiality
    cipher_field = used_algorithms_fields.get("5G RRC C")
    integrity_field = used_algorithms_fields.get("5G RRC I")

    # --- Main loop: iterates through all packets to extract confidentiality data ---
    for pkt in packets:
        enc = pkt["fields"].get(cipher_field)
        integ = pkt["fields"].get(integrity_field)
        # Only process if at least one of the algorithms is present
        if not enc and not integ:
            continue
        ts = pkt["fields"].get(ts_field)
        frame = pkt["fields"].get(frame_field)
        version = pkt["fields"].get(version_field)
        payload = pkt["fields"].get(payload_field)
        sub_type = pkt["fields"].get(sub_type_field)
        if payload in ["0x0403", "0x0404"]: # 4G RRC and 4G NAS
            message_field = nrrrc_fields.get("4G_C1Message")
            message_field_verify = message_field + "_DL-DCCH"
        elif payload in ["0x0503", "0x0504"]: # 5G RRC and 5G NAS
            message_field = nrrrc_fields.get("C1Message")
            message_field_verify = message_field + "_DL-DCCH"
        message = pkt["fields"].get(message_field)
        arfcn = pkt["fields"].get(arfcn_field)
        cell = pkt["fields"].get(cell_field)

        # Build the results dictionary for each algorithm identified
        results1[enc].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": payload_field,
            "Payload": payload,
            "SubTypeField": sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field_verify,
            "Message": message,
            "ARFCN": arfcn,
            "Cell_ID": cell,
            "Algorithm": enc
        })
        results2[integ].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": payload_field,
            "Payload": payload,
            "SubTypeField": sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field_verify,
            "Message": message,
            "ARFCN": arfcn,
            "Cell_ID": cell,
            "Algorithm": integ
        })
    return results1, results2

# Auxiliary function for 5G NAS
def extract_5g_nas_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    nrnas_fields: Dict[str, str],
    misc_fields: Dict[str, str]
) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, List[Dict[str, str]]]]:
    """
    Extract 5G (NR NAS) confidentiality and integrity algorithms.

    Correlate relevant fields from signaling packets.

    Args:
        packets (list): List of dictionaries, each representing a packet extracted from the PCAP.
        used_algorithms_fields (dict): Fields for algorithms used, mapped by name.
        nrnas_fields (dict): Fields specific to 5G NAS.
        misc_fields (dict): Generic/miscellaneous fields.

    Returns:
        Tuple[dict, dict]: Two dictionaries grouping results by confidentiality and integrity algorithm, respectively.
    """
    results1 = defaultdict(list)  # Results of confidentiality
    results2 = defaultdict(list)  # Results of integrity

    # --- Field mapping for interest fields (according to the configuration file) ---
    ts_field = misc_fields.get("Timestamp")  # Timestamp field of the packet
    frame_field = misc_fields.get("Frame")   # Frame number of the packet
    version_field = misc_fields.get("VersionV3")
    payload_field = misc_fields.get("PayloadV3")
    sub_type_field = misc_fields.get("SubTypeV3")
    # Fields specific to 5G NAS
    message_field = nrnas_fields.get("NASMsgType")
    message_field_4g = nrnas_fields.get("4G_NASMsgType")
    # Fields for algorithms used
    cipher_field = used_algorithms_fields.get("5G NAS C")  # Algorithm of confidentiality
    integrity_field = used_algorithms_fields.get("5G NAS I")  # Algorithm of integrity

    # --- Main loop: iterates through all packets to extract confidentiality/integrity data ---
    for pkt in packets:
        enc = pkt["fields"].get(cipher_field)
        integ = pkt["fields"].get(integrity_field)
        # Only process if at least one of the algorithms is present
        if not (enc or integ):
            continue
        ts = pkt["fields"].get(ts_field)
        frame = pkt["fields"].get(frame_field)
        version = pkt["fields"].get(version_field)
        payload = pkt["fields"].get(payload_field)
        if payload in ["0x0403", "0x0404"]: # 4G RRC and 4G NAS
            message_field = nrnas_fields.get("4G_NASMsgType")
        elif payload in ["0x0503", "0x0504"]: # 5G RRC and 5G NAS
            message_field = nrnas_fields.get("NASMsgType")
        sub_type = pkt["fields"].get(sub_type_field)
        message = pkt["fields"].get(message_field)

        # Add results to dictionaries
        results1[enc].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": payload_field,
            "Payload": payload,
            "SubTypeField": sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field,
            "Message": message,
            "Algorithm": enc
        })
        results2[integ].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": payload_field,
            "Payload": payload,
            "SubTypeField": sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field,
            "Message": message,
            "Algorithm": integ
        })
    return results1, results2

# -----------------------------------------------------------------------------
#  FUNCTIONS FOR ID
# -----------------------------------------------------------------------------

def extract_2g_voice_id(
    packets: List[Dict[str, Any]],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract GSM (2G CS) identity-related messages from provided packets.

    Captures Location Updating, Identity and CM Service messages and associates
    the closest System Information Type 4 (SIT4) to recover LAC/MCC/MNC/ARFCN.
    IMSI values are not exposed (empty string) for privacy; TMSI is hex-normalized.

    Args:
        packets: List of packet dicts.
        gsm_fields: GSM field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType2")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # GSM headers
    mcc_field = gsm_fields.get("MCC_2G")
    mnc_field = gsm_fields.get("MNC_2G")
    lac_field = gsm_fields.get("LAC_2G")
    msg_mm_type_field = gsm_fields.get("DTAPMsgTypeVoice")
    if msg_mm_type_field is not None:
        msg_mm_type_LUReqvalue = translations_cfg.get(msg_mm_type_field, "Location Updating Request")
        msg_mm_type_LUAcpvalue = translations_cfg.get(msg_mm_type_field, "Location Updating Accept")
        msg_mm_type_IDResvalue = translations_cfg.get(msg_mm_type_field, "Identity Response")
        msg_mm_type_IDReqvalue = translations_cfg.get(msg_mm_type_field, "Identity Request")
        msg_mm_type_CMServReqvalue = translations_cfg.get(msg_mm_type_field, "CM Service Request")
        msg_mm_type_CMServAcpvalue = translations_cfg.get(msg_mm_type_field, "CM Service Accept")
        msg_mm_type_TMSIRealocCmdvalue = translations_cfg.get(msg_mm_type_field, "TMSI Reallocation Command")
        msg_mm_type_TMSIRealocCmpvalue = translations_cfg.get(msg_mm_type_field, "TMSI Reallocation Complete")
    msg_rr_type_field = gsm_fields.get("DTAPRRType")
    if msg_rr_type_field is not None:
        msg_rr_type_SIT4value = translations_cfg.get(msg_rr_type_field, "System Information Type 4")
    if gsmtap_type_field is not None:
        gsm_type_field_values = [translations_cfg.get(gsmtap_type_field,"GSM Um"),translations_cfg.get(gsmtap_type_field,"GSM Abis")]
    mobileid_type_field = gsm_fields.get("MobileIDTypeLegacy")
    if mobileid_type_field is not None:
        mobileid_tmsi_field_value = translations_cfg.get(mobileid_type_field,"TMSI")
        mobileid_imsi_field_value = translations_cfg.get(mobileid_type_field,"IMSI")
    tmsi_field = gsm_fields.get("TMSI")
    imsi_field = gsm_fields.get("IMSI")
    # Create per-frame index for efficient lookup
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))
    for pkt in packets:
      # GSM filter (GSM Um / GSM Abis)
        if pkt["fields"].get(gsmtap_type_field) not in gsm_type_field_values:
            continue
        # Filter accepted GSM MM messages (Location Updating, Identity, CM Service, TMSI Reallocation)
        if msg_mm_type_field is None or pkt["fields"].get(msg_mm_type_field) not in [msg_mm_type_LUReqvalue,msg_mm_type_LUAcpvalue,msg_mm_type_IDReqvalue,msg_mm_type_IDResvalue,msg_mm_type_CMServReqvalue,msg_mm_type_CMServAcpvalue,msg_mm_type_TMSIRealocCmdvalue,msg_mm_type_TMSIRealocCmpvalue]:
            continue
        idtype = pkt["fields"].get(mobileid_type_field)
 #       if idtype not in [mobileid_tmsi_field_value,mobileid_imsi_field_value]:
 #           continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(msg_mm_type_field)
        if idtype == mobileid_tmsi_field_value:
            id = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
        elif idtype == mobileid_imsi_field_value:
            # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
            id = ""
        else:
            id = ""

        # Find nearest SIT 4
        lac = arfcn = mcc = mnc = ""
        closest_ref = None
        closest_frame = -1
        next_ref = None
        next_frame = None
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if ref["fields"].get(msg_rr_type_field) == msg_rr_type_SIT4value:
                if ref_frame < frame and ref_frame > closest_frame:
                    closest_frame = ref_frame
                    closest_ref = ref
                elif ref_frame > frame and (next_frame is None or ref_frame < next_frame):
                    next_frame = ref_frame
                    next_ref = ref
        if closest_ref:
            lac  = closest_ref["fields"].get(lac_field, "")
            mcc  = closest_ref["fields"].get(mcc_field, "")
            mnc  = closest_ref["fields"].get(mnc_field, "")
            arfcn = closest_ref["fields"].get(gsmtap_arfcn_field, "")
        elif next_ref:
            lac  = next_ref["fields"].get(lac_field, "")
            mcc  = next_ref["fields"].get(mcc_field, "")
            mnc  = next_ref["fields"].get(mnc_field, "")
            arfcn = next_ref["fields"].get(gsmtap_arfcn_field, "")

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "Message": message,
            "MessageField": msg_mm_type_field,
            "ARFCN": arfcn,
            "LAC": lac,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_2g_data_id(
    packets: List[Dict[str, Any]],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract GPRS/EDGE (2G PS) identity-related messages from provided packets.

    Captures Attach, Routing Area Update, Identity and Service messages, and
    associates the closest System Information Type 4 (SIT4) to recover
    LAC/MCC/MNC/ARFCN. IMSI values are not exposed; TMSI/PTMSI is hex-normalized.

    Args:
        packets: List of packet dicts.
        gsm_fields: GSM field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType2")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # GSM headers
    if gsmtap_type_field is not None:
        gsmtap_type_field_values = [translations_cfg.get(gsmtap_type_field,"GSM Um"),translations_cfg.get(gsmtap_type_field,"GSM Abis")]
    mobileid_type_field = gsm_fields.get("MobileIDTypeLegacy")
    if mobileid_type_field is not None:
        mobileid_type_TMSI = translations_cfg.get(mobileid_type_field,"TMSI")
        mobileid_type_IMSI = translations_cfg.get(mobileid_type_field,"IMSI")
    dtap_gmm_type_field = gsm_fields.get("DTAPMsgTypeData")
    if dtap_gmm_type_field is not None:
        dtap_gmm_type_AttReqvalue = translations_cfg.get(dtap_gmm_type_field,"Attach Request")
        dtap_gmm_type_AttAcptvalue = translations_cfg.get(dtap_gmm_type_field,"Attach Accept")
        dtap_gmm_type_AttCompvalue = translations_cfg.get(dtap_gmm_type_field,"Attach Complete")
        dtap_gmm_type_pTMSIReallocvalue = translations_cfg.get(dtap_gmm_type_field,"P-TMSI Reallocation Command")
        dtap_gmm_type_pTMSIReallocCmpvalue = translations_cfg.get(dtap_gmm_type_field,"P-TMSI Reallocation Complete")
        dtap_gmm_type_RoutAreaUpReqvalue = translations_cfg.get(dtap_gmm_type_field,"Routing Area Update Request")
        dtap_gmm_type_RoutAreaUpAcptvalue = translations_cfg.get(dtap_gmm_type_field,"Routing Area Update Accept")
        dtap_gmm_type_RoutAreaUpCmpvalue = translations_cfg.get(dtap_gmm_type_field,"Routing Area Update Complete")
        dtap_gmm_type_IDReqvalue = translations_cfg.get(dtap_gmm_type_field,"Identity Request")
        dtap_gmm_type_IDResvalue = translations_cfg.get(dtap_gmm_type_field,"Identity Response")
        dtap_gmm_type_ServReqvalue = translations_cfg.get(dtap_gmm_type_field,"Service Request")
        dtap_gmm_type_ServAcptvalue = translations_cfg.get(dtap_gmm_type_field,"Service Accept")
    msg_rr_type_field = gsm_fields.get("DTAPRRType")
    if msg_rr_type_field is not None:
        msg_rr_type_SIT4value = translations_cfg.get(msg_rr_type_field,"System Information Type 4")
    mcc_field = gsm_fields.get("MCC_2G")
    mnc_field = gsm_fields.get("MNC_2G")
    lac_field = gsm_fields.get("LAC_2G")
    tmsi_field = gsm_fields.get("TMSI")
    imsi_field = gsm_fields.get("IMSI")
    # Create per-frame index for efficient lookup
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))
    for pkt in packets:
      # GSM filter (GSM Um / GSM Abis)
        if pkt["fields"].get(gsmtap_type_field) not in gsmtap_type_field_values:
            continue
        # Filter accepted GPRS messages (Attach, RA Update, Identity, Service, P‑TMSI Reallocation)
        if pkt["fields"].get(dtap_gmm_type_field) not in [dtap_gmm_type_AttReqvalue,dtap_gmm_type_AttAcptvalue,dtap_gmm_type_AttCompvalue,dtap_gmm_type_pTMSIReallocvalue,dtap_gmm_type_pTMSIReallocCmpvalue,dtap_gmm_type_RoutAreaUpReqvalue,dtap_gmm_type_RoutAreaUpAcptvalue,dtap_gmm_type_RoutAreaUpCmpvalue,dtap_gmm_type_IDReqvalue,dtap_gmm_type_IDResvalue,dtap_gmm_type_ServReqvalue,dtap_gmm_type_ServAcptvalue]:
            continue
        idtype = pkt["fields"].get(mobileid_type_field)
 #       if idtype not in [mobileid_type_TMSI,mobileid_type_IMSI]:
 #           continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(dtap_gmm_type_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        if idtype == mobileid_type_TMSI:
            id = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
        elif idtype == mobileid_type_IMSI:
            # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
            id = ""
        else:
            id = ""

        # Find closest SIT 4
        lac = arfcn = mcc = mnc = ""
        closest_ref = None
        closest_frame = -1
        next_ref = None
        next_frame = None
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if ref["fields"].get(msg_rr_type_field) == msg_rr_type_SIT4value:
                if ref_frame < frame and ref_frame > closest_frame:
                    closest_frame = ref_frame
                    closest_ref = ref
                elif ref_frame > frame and (next_frame is None or ref_frame < next_frame):
                    next_frame = ref_frame
                    next_ref = ref
        if closest_ref:
            lac  = closest_ref["fields"].get(lac_field, "")
            mcc  = closest_ref["fields"].get(mcc_field, "")
            mnc  = closest_ref["fields"].get(mnc_field, "")
            arfcn = closest_ref["fields"].get(gsmtap_arfcn_field, "")
        elif next_ref:
            lac  = next_ref["fields"].get(lac_field, "")
            mcc  = next_ref["fields"].get(mcc_field, "")
            mnc  = next_ref["fields"].get(mnc_field, "")
            arfcn = next_ref["fields"].get(gsmtap_arfcn_field, "")

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "MessageField": dtap_gmm_type_field,
            "Message": message,
            "ARFCN": arfcn,
            "LAC": lac,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_3g_rrc_id(
    packets: List[Dict[str, Any]],
    umts_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 3G (UMTS RRC) IDs from CCCH messages around RRCConnectionRequest/Setup.

    Uses DL/UL CCCH discriminator, pulls TMSI/PTMSI (hex-normalized) and hides IMSI.

    Args:
        packets: List of packet dicts.
        umts_fields: UMTS field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # UMTS headers
    if gsmtap_type_field is not None:
        gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field,"UMTS RRC")
    mobileid_type_field = umts_fields.get("MobileIDType")
    tmsi_field = umts_fields.get("TMSI")
    ptmsi_field = umts_fields.get("PTMSI")
    imsi_field = umts_fields.get("IMSI")
    if mobileid_type_field is not None:
        mobileid_type_TMSI_value = translations_cfg.get(mobileid_type_field,"TMSI")
        mobileid_type_PTMSI_value = translations_cfg.get(mobileid_type_field,"PTMSI")
        mobileid_type_IMSI_value = translations_cfg.get(mobileid_type_field,"IMSI")
    rrc_message_field = umts_fields.get("RRCMsgType")
    if rrc_message_field is not None:
        rrc_message_field_verify_1 = rrc_message_field + "_DL-CCCH"
        rrc_message_field_verify_2 = rrc_message_field + "_UL-CCCH"
    if gsmtap_sub_type_field is not None:
        gsmtap_sub_type_RRCDLCCCH_value = translations_cfg.get(gsmtap_sub_type_field,"RRC DL-CCCH")
        gsmtap_sub_type_RRCULCCCH_value = translations_cfg.get(gsmtap_sub_type_field,"RRC UL-CCCH")
    for pkt in packets:
      # UMTS RRC filter (payload RRC)
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        # Filter DL-CCCH / UL-CCCH
        if pkt["fields"].get(gsmtap_sub_type_field) not in [gsmtap_sub_type_RRCDLCCCH_value,gsmtap_sub_type_RRCULCCCH_value]:
            continue
        idtype = pkt["fields"].get(mobileid_type_field)
 #       if idtype not in [mobileid_type_TMSI_value,mobileid_type_PTMSI_value,mobileid_type_IMSI_value]:
 #           continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        if sub_type == gsmtap_sub_type_RRCDLCCCH_value:
            message_field_verify = rrc_message_field_verify_1
        elif sub_type == gsmtap_sub_type_RRCULCCCH_value:
            message_field_verify = rrc_message_field_verify_2
        message = pkt["fields"].get(rrc_message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        if idtype == mobileid_type_TMSI_value:
            id = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
        elif idtype == mobileid_type_PTMSI_value:
            id = decimal_id_to_hex(pkt["fields"].get(ptmsi_field))
        elif idtype == mobileid_type_IMSI_value:
            # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
            id = ""
        else:
            continue
        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field_verify,
            "Message": message,
            "ARFCN": arfcn,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_3g_nas_id(
    packets: List[Dict[str, Any]],
    umts_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 3G (UMTS NAS) IDs from MM/GMM messages across CS/PS domains.

    Uses the DOMAIN field to select MM (CS) or GMM (PS) message family.
    Hex-normalizes TMSI values and hides IMSI for privacy.

    Args:
        packets: List of packet dicts.
        umts_fields: UMTS field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # UMTS headers
    if gsmtap_type_field is not None:
        gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field,"UMTS RRC")
    mobileid_type_field = umts_fields.get("MobileIDTypeLegacy")
    tmsi_field = umts_fields.get("TMSI_NAS")
    imsi_field = umts_fields.get("IMSI")
    if mobileid_type_field is not None:
        mobileid_type_TMSI_value = translations_cfg.get(mobileid_type_field,"TMSI")
        mobileid_type_IMSI_value = translations_cfg.get(mobileid_type_field,"IMSI")
    dtap_message_mm_field = umts_fields.get("DTAPMsgTypeVoice")
    dtap_message_gmm_field = umts_fields.get("DTAPMsgTypeData")
    if dtap_message_mm_field is not None:
        msg_mm_type_LUReqvalue = translations_cfg.get(dtap_message_mm_field, "Location Updating Request")
        msg_mm_type_LUAcpvalue = translations_cfg.get(dtap_message_mm_field, "Location Updating Accept")
        msg_mm_type_IDResvalue = translations_cfg.get(dtap_message_mm_field, "Identity Response")
        msg_mm_type_IDReqvalue = translations_cfg.get(dtap_message_mm_field, "Identity Request")
        msg_mm_type_CMServReqvalue = translations_cfg.get(dtap_message_mm_field, "CM Service Request")
        msg_mm_type_CMServAcpvalue = translations_cfg.get(dtap_message_mm_field, "CM Service Accept")
        msg_mm_type_TMSIRealocCmdvalue = translations_cfg.get(dtap_message_mm_field, "TMSI Reallocation Command")
        msg_mm_type_TMSIRealocCmpvalue = translations_cfg.get(dtap_message_mm_field, "TMSI Reallocation Complete")
    if dtap_message_gmm_field is not None:
        dtap_gmm_type_AttReqvalue = translations_cfg.get(dtap_message_gmm_field,"Attach Request")
        dtap_gmm_type_AttAcptvalue = translations_cfg.get(dtap_message_gmm_field,"Attach Accept")
        dtap_gmm_type_AttCompvalue = translations_cfg.get(dtap_message_gmm_field,"Attach Complete")
        dtap_gmm_type_pTMSIReallocvalue = translations_cfg.get(dtap_message_gmm_field,"P-TMSI Reallocation Command")
        dtap_gmm_type_pTMSIReallocCmpvalue = translations_cfg.get(dtap_message_gmm_field,"P-TMSI Reallocation Complete")
        dtap_gmm_type_RoutAreaUpReqvalue = translations_cfg.get(dtap_message_gmm_field,"Routing Area Update Request")
        dtap_gmm_type_RoutAreaUpAcptvalue = translations_cfg.get(dtap_message_gmm_field,"Routing Area Update Accept")
        dtap_gmm_type_RoutAreaUpCmpvalue = translations_cfg.get(dtap_message_gmm_field,"Routing Area Update Complete")
        dtap_gmm_type_IDReqvalue = translations_cfg.get(dtap_message_gmm_field,"Identity Request")
        dtap_gmm_type_IDResvalue = translations_cfg.get(dtap_message_gmm_field,"Identity Response")
        dtap_gmm_type_ServReqvalue = translations_cfg.get(dtap_message_gmm_field,"Service Request")
        dtap_gmm_type_ServAcptvalue = translations_cfg.get(dtap_message_gmm_field,"Service Accept")
    if gsmtap_sub_type_field is not None:
        gsmtap_sub_type_RRCDLDCCH_value = translations_cfg.get(gsmtap_sub_type_field,"RRC DL-DCCH")
        gsmtap_sub_type_RRCULDCCH_value = translations_cfg.get(gsmtap_sub_type_field,"RRC UL-DCCH")
    domain_field = umts_fields.get("DOMAIN")
    for pkt in packets:
      # Filter UMTS RRC (payload == 12)
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        # Filter DL-DCCH / UL-DCCH
        if pkt["fields"].get(gsmtap_sub_type_field) not in [gsmtap_sub_type_RRCDLDCCH_value,gsmtap_sub_type_RRCULDCCH_value]:
            continue
        if pkt["fields"].get(dtap_message_mm_field) not in [msg_mm_type_LUReqvalue,msg_mm_type_LUAcpvalue,msg_mm_type_IDResvalue,msg_mm_type_IDReqvalue,msg_mm_type_CMServReqvalue,msg_mm_type_CMServAcpvalue,msg_mm_type_TMSIRealocCmdvalue,msg_mm_type_TMSIRealocCmpvalue] and pkt["fields"].get(dtap_message_gmm_field) not in [dtap_gmm_type_AttReqvalue,dtap_gmm_type_AttAcptvalue,dtap_gmm_type_AttCompvalue,dtap_gmm_type_pTMSIReallocvalue,dtap_gmm_type_pTMSIReallocCmpvalue,dtap_gmm_type_RoutAreaUpReqvalue,dtap_gmm_type_RoutAreaUpAcptvalue,dtap_gmm_type_RoutAreaUpCmpvalue,dtap_gmm_type_IDReqvalue,dtap_gmm_type_IDResvalue,dtap_gmm_type_ServReqvalue,dtap_gmm_type_ServAcptvalue]:
            continue
        idtype = pkt["fields"].get(mobileid_type_field)
 #       if idtype not in [mobileid_type_TMSI_value,mobileid_type_IMSI_value]:
 #           continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        domain = pkt["fields"].get(domain_field)
        if domain == "0": #CS
            message_field = dtap_message_mm_field
            message = pkt["fields"].get(dtap_message_mm_field)
        elif domain == "1": #PS
            message_field = dtap_message_gmm_field
            message = pkt["fields"].get(dtap_message_gmm_field)
        else:
            message_field = None
            message = None
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        if idtype == mobileid_type_TMSI_value:
            id = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
        elif idtype == mobileid_type_IMSI_value:
            # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
            id = ""
        else:
            id = ""
        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MessageField": message_field,
            "Domain": domain,
            "Message": message,
            "ARFCN": arfcn,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_4g_rrc_id(
    packets: List[Dict[str, Any]],
    lterrc_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 4G (LTE RRC) IDs around RRCConnectionRequest/Setup messages.

    Handles GSMTAP v2/v3 differences, maps MTMSI/RandomValue when present,
    and finds nearest RRCConnectionSetup to enrich ARFCN.

    Args:
        packets: List of packet dicts.
        lterrc_fields: LTE RRC field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    gsmtap_pci_field = misc_fields.get("PCIV3")
    # 4G RRC headers
    mobileid_type_field = lterrc_fields.get("MobileIDType")
    mtmsi_field = lterrc_fields.get("MTMSI")
    randomvalue_field = lterrc_fields.get("RANDOM_VALUE")
    if mobileid_type_field is not None:
        mobileid_type_MTMSI_value = translations_cfg.get(mobileid_type_field,"MTMSI")
        mobileid_type_RandomValue_value = translations_cfg.get(mobileid_type_field,"RandomValue")
    rrc_message_field = lterrc_fields.get("C1Message")
    if rrc_message_field is not None:
        rrc_message_field_ULCCCH_verify = rrc_message_field + "_UL-CCCH"
        rrc_message_RRCConReq_value = translations_cfg.get(rrc_message_field_ULCCCH_verify,"rrcConnectionRequest")
        rrc_message_RRCConReeReq_value = translations_cfg.get(rrc_message_field_ULCCCH_verify,"rrcConnectionReestablishmentRequest")
        rrc_message_field_DLCCCH_verify = rrc_message_field + "_DL-CCCH"
        rrc_message_RRCConSetup_value = translations_cfg.get(rrc_message_field_DLCCCH_verify,"rrcConnectionSetup")
        rrc_message_RRCConRee_value = translations_cfg.get(rrc_message_field_DLCCCH_verify,"rrcConnectionReestablishment")
    rrc_sub_type_field = lterrc_fields.get("SubType")
    # Create frame index for efficient lookup
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))

    for pkt in packets:
        # Initialize per-packet vars to avoid UnboundLocalError when version is unexpected
        gsmtap_type_field = None
        gsmtap_arfcn_field = None
        rrc_sub_type_field_verify = None
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        if version == "3":
            rrc_sub_type_field = misc_fields.get("SubTypeV3")
            if rrc_sub_type_field is not None:
                rrc_sub_type_field_verify = rrc_sub_type_field + "_LTERRC"
            gsmtap_type_field = misc_fields.get("PayloadV3")
            gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
        elif version == "2":
            rrc_sub_type_field = misc_fields.get("SubType2")
            if rrc_sub_type_field is not None:
                rrc_sub_type_field_verify = rrc_sub_type_field
            gsmtap_type_field = misc_fields.get("Payload")
            gsmtap_arfcn_field = misc_fields.get("ARFCN")
        else:
            # Unknown or unsupported GSMTAP version for LTE; skip packet
            continue
        if gsmtap_type_field is not None:
            gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field, "LTE RRC")
        else:
            # Missing payload field mapping; skip packet safely
            continue
        if not rrc_sub_type_field_verify:
            # Cannot determine subtype discriminator; skip
            continue
        # 4G RRC filter (LTE RRC payload)
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        # RRCConnectionRequest/Setup filter
        rrc_sub_type_RRCULCCCH_value = translations_cfg.get(rrc_sub_type_field_verify, "RRC UL-CCCH")
        rrc_sub_type_RRCDLCCCH_value = translations_cfg.get(rrc_sub_type_field_verify, "RRC DL-CCCH")
        if pkt["fields"].get(rrc_sub_type_field) not in [rrc_sub_type_RRCULCCCH_value,rrc_sub_type_RRCDLCCCH_value]:
            continue
        if pkt["fields"].get(rrc_message_field) not in [rrc_message_RRCConReq_value, rrc_message_RRCConReeReq_value, rrc_message_RRCConSetup_value, rrc_message_RRCConRee_value]:
            continue
        if pkt["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCULCCCH_value:
            messagefield = rrc_message_field_ULCCCH_verify
        elif pkt["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCDLCCCH_value:
            messagefield = rrc_message_field_DLCCCH_verify
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(rrc_sub_type_field)
        message = pkt["fields"].get(rrc_message_field)
        pci = pkt["fields"].get(gsmtap_pci_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        if idtype == mobileid_type_MTMSI_value:
            id = decimal_id_to_hex(pkt["fields"].get(mtmsi_field))
        elif idtype == mobileid_type_RandomValue_value:
            id = decimal_id_to_hex(pkt["fields"].get(randomvalue_field))
        else:
            id = None

        # Find nearest RRCConnectionSetup
        closest_ref = None
        closest_distance = None
        arfcn = ""  # Default value in case setup message is not found
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            rrc_sub_type_RRCDLCCCH_value = translations_cfg.get(rrc_sub_type_field_verify, "RRC DL-CCCH")
            ref_msg = ref["fields"].get(rrc_message_field) or ""
            if rrc_message_RRCConSetup_value in ref_msg and ref["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCDLCCCH_value:
                distance = abs(ref_frame - frame)
                if closest_distance is None or distance < closest_distance:
                    closest_distance = distance
                    closest_ref = ref
        if closest_ref:
            arfcn = closest_ref["fields"].get(gsmtap_arfcn_field, "")

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": rrc_sub_type_field,
            "SubType": sub_type,
            "MessageField": messagefield,
            "Message": message,
            "ARFCN": arfcn,
            "PCI": pci,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_4g_nas_id(
    packets: List[Dict[str, Any]],
    ltenas_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 4G (LTE NAS) IDs from NAS messages carrying user identifiers.

    Supports Attach, TAU, Identity, Service and GUTI Reallocation flows.
    TAU requesting multiple GUTIs is handled with two slots; IMSI is not exposed.

    Args:
        packets: List of packet dicts.
        ltenas_fields: LTE NAS field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    # 4G NAS headers
    mobileid_type_field = ltenas_fields.get("MobileIDType")
    mobileid_type_field_legacy = ltenas_fields.get("MobileIDTypeLegacy")
    if mobileid_type_field is not None:
        mobileid_type_imsi_value = translations_cfg.get(mobileid_type_field,"IMSI")
        mobileid_type_GUTI_value = translations_cfg.get(mobileid_type_field,"GUTI")
    mmegroupid_field = ltenas_fields.get("MMEGroupID")
    mmecode_field = ltenas_fields.get("MMECode")
    mtmsi_field = ltenas_fields.get("MTMSI")
    imsi_field = ltenas_fields.get("IMSI")
    nas_msg_type_field = ltenas_fields.get("NASMsgType")
    if nas_msg_type_field is not None:
        nas_msg_type_AttReq_value = translations_cfg.get(nas_msg_type_field,"Attach Request")
        nas_msg_type_AttAcpt_value = translations_cfg.get(nas_msg_type_field,"Attach Accept")
        nas_msg_type_AttComp_value = translations_cfg.get(nas_msg_type_field,"Attach Complete")
        nas_msg_type_GUTIRealoc_value = translations_cfg.get(nas_msg_type_field,"GUTI Reallocation Command")
        nas_msg_type_GUTIRealocComp_value = translations_cfg.get(nas_msg_type_field,"GUTI Reallocation Complete")
        nas_msg_type_TrackAreaUpdReq_value = translations_cfg.get(nas_msg_type_field,"Tracking Area Update Request")
        nas_msg_type_TrackAreaUpdAc_value = translations_cfg.get(nas_msg_type_field,"Tracking Area Update Accept")
        nas_msg_type_TrackAreaUpdComp_value = translations_cfg.get(nas_msg_type_field,"Tracking Area Update Complete")
        nas_msg_type_IDReq_value = translations_cfg.get(nas_msg_type_field,"Identity Request")
        nas_msg_type_IDResp_value = translations_cfg.get(nas_msg_type_field,"Identity Response")
        nas_msg_type_CPServReq_value = translations_cfg.get(nas_msg_type_field,"Control Plane Service Request")
        nas_msg_type_ExtServReq_value = translations_cfg.get(nas_msg_type_field,"Extended Service Request")
    mcc_field = ltenas_fields.get("MCC_4G_LAI")
    mnc_field = ltenas_fields.get("MNC_4G_LAI")
    lac_field = ltenas_fields.get("LAC_4G")

    for pkt in packets:
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        if version == "3":
            nas_sub_type_field = misc_fields.get("SubTypeV3")
            gsmtap_payload_field = misc_fields.get("PayloadV3")
        else:
            nas_sub_type_field = misc_fields.get("SubType2")
            gsmtap_payload_field = misc_fields.get("Payload")
        if gsmtap_payload_field is not None:
            gsmtap_type_field_values = translations_cfg.get(gsmtap_payload_field,"LTE NAS")
        # 4G NAS filter
        if pkt["fields"].get(gsmtap_payload_field) != gsmtap_type_field_values:
            continue
        # Filter NAS messages carrying user IDs
        if pkt["fields"].get(nas_msg_type_field) not in [nas_msg_type_AttAcpt_value,nas_msg_type_AttComp_value,nas_msg_type_GUTIRealoc_value,nas_msg_type_GUTIRealocComp_value,nas_msg_type_TrackAreaUpdAc_value,nas_msg_type_TrackAreaUpdComp_value,nas_msg_type_AttReq_value,nas_msg_type_IDReq_value,nas_msg_type_IDResp_value,nas_msg_type_CPServReq_value,nas_msg_type_ExtServReq_value,nas_msg_type_TrackAreaUpdReq_value]:
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        payload = pkt["fields"].get(gsmtap_payload_field)
        sub_type = pkt["fields"].get(nas_sub_type_field)
        mcc = pkt["fields"].get(mcc_field)
        mnc = pkt["fields"].get(mnc_field)
        lac = pkt["fields"].get(lac_field)
        message = pkt["fields"].get(nas_msg_type_field)
        mmegroupid = pkt["fields"].get(mmegroupid_field)
        mmecode = pkt["fields"].get(mmecode_field)
        # Special handling for TAU Request which may carry multiple GUTIs in MTMSI
        if message == nas_msg_type_TrackAreaUpdReq_value:
            raw_mtmsi = pkt["fields"].get(mtmsi_field)
            guti_ids = []
            if isinstance(raw_mtmsi, list):
                guti_ids = [str(x).strip() for x in raw_mtmsi if str(x).strip()]
            elif isinstance(raw_mtmsi, str):
                # Support comma, semicolon or whitespace separated values
                candidate = raw_mtmsi.replace(";", ",")
                parts = []
                for chunk in candidate.split(","):
                    parts.extend(chunk.split())
                guti_ids = [p.strip() for p in parts if p.strip()]
            elif raw_mtmsi is not None:
                guti_ids = [str(raw_mtmsi).strip()]
            # Limit to two IDs to match tablebuilder formatting
            if len(guti_ids) > 2:
                guti_ids = guti_ids[:2]
            # Build numbered slots (max 2) for same-row output, aligning MME fields per ID
            id1 = decimal_id_to_hex(guti_ids[0]) if len(guti_ids) >= 1 else None
            id2 = decimal_id_to_hex(guti_ids[1]) if len(guti_ids) >= 2 else None
            idtype1 = mobileid_type_GUTI_value if id1 else None
            idtype2 = mobileid_type_GUTI_value if id2 else None
            # Parse MME fields as lists when multiple
            def _to_list_any(val: Any) -> List[str]:
                """Normalize a value to a list of strings.

                Accepts lists or delimited strings (comma/semicolon/whitespace).
                """
                if val is None:
                    return []
                if isinstance(val, list):
                    return [str(x).strip() for x in val if str(x).strip()]
                s = str(val)
                s = s.replace(";", ",")
                parts: List[str] = []
                for chunk in s.split(","):
                    parts.extend(chunk.split())
                return [p.strip() for p in parts if p.strip()]
            mmegid_list = _to_list_any(mmegroupid)
            mmecode_list = _to_list_any(mmecode)
            mmegid1 = mmegid_list[0] if id1 and len(mmegid_list) >= 1 else (mmegroupid if id1 else None)
            mmegid2 = mmegid_list[1] if id2 and len(mmegid_list) >= 2 else (mmegroupid if id2 and len(mmegid_list)==1 else (mmegroupid if id2 and mmegroupid and not mmegid_list else None))
            mmecode1 = mmecode_list[0] if id1 and len(mmecode_list) >= 1 else (mmecode if id1 else None)
            mmecode2 = mmecode_list[1] if id2 and len(mmecode_list) >= 2 else (mmecode if id2 and len(mmecode_list)==1 else (mmecode if id2 and mmecode and not mmecode_list else None))
            results[id1 or id2 or ""].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": nas_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "LAC": lac,
                "MessageField": nas_msg_type_field,
                "Message": message,
                "ID Type Field": mobileid_type_field,
                "MMEGID 1": mmegid1,
                "MMECODE 1": mmecode1,
                "ID Type 1": idtype1,
                "ID1": id1,
                "MMEGID 2": mmegid2,
                "MMECODE 2": mmecode2,
                "ID Type 2": idtype2,
                "ID2": id2,
            })
            continue
        else:
            if message == nas_msg_type_IDResp_value:
                idtype = pkt["fields"].get(mobileid_type_field_legacy)
            else:
                idtype = pkt["fields"].get(mobileid_type_field)
            if idtype == mobileid_type_GUTI_value:
                id = decimal_id_to_hex(pkt["fields"].get(mtmsi_field))
            elif idtype == mobileid_type_imsi_value:
                # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
                id = ""
            else:
                id = ""

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_payload_field,
            "Payload": payload,
            "SubTypeField": nas_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "LAC": lac,
            "MessageField": nas_msg_type_field,
            "Message": message,
            "ID Type Field": mobileid_type_field,
            "MMEGID 1": mmegroupid,
            "MMECODE 1": mmecode,
            "ID Type 1": idtype,
            "ID1": id,
            "MMEGID 2": None,
            "MMECODE 2": None,
            "ID Type 2": None,
            "ID2": None,
        })
    return results


def extract_5g_rrc_id(
    packets: List[Dict[str, Any]],
    nrrrc_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 5G (NR RRC) IDs around Setup Request/Setup/Setup Complete.

    Maps S‑TMSI/RandomValue and reconstructs Part2 from the nearest
    rrcSetupComplete when available.

    Args:
        packets: List of packet dicts.
        nrrrc_fields: NR RRC field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    gsmtap_pci_field = misc_fields.get("PCIV3")
    rrc_sub_type_field = misc_fields.get("SubTypeV3")
    if rrc_sub_type_field is not None:
        rrc_sub_type_field_verify = rrc_sub_type_field + "_NRRRC"
    gsmtap_type_field = misc_fields.get("PayloadV3")
    gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
    # 5G RRC headers
    mobileid_type_field = nrrrc_fields.get("MobileIDType")
    stmsi_part1_field = nrrrc_fields.get("STMSI_Part1")
    stmsi_part2_field = nrrrc_fields.get("STMSI_Part2")
    randomvalue_field = nrrrc_fields.get("RANDOM_VALUE")
    if mobileid_type_field is not None:
        mobileid_type_STMSI_Part1_value = translations_cfg.get(mobileid_type_field,"ng-5G-S-TMSI-Part1")
        mobileid_type_RandomValue_value = translations_cfg.get(mobileid_type_field,"RandomValue")
    rrc_message_field = nrrrc_fields.get("C1Message")
    if rrc_message_field is not None:
        rrc_message_field_ULCCCH_verify = rrc_message_field + "_UL-CCCH"
        rrc_message_RRCSetReq_value = translations_cfg.get(rrc_message_field_ULCCCH_verify,"rrcSetupRequest")
        rrc_message_field_DLCCCH_verify = rrc_message_field + "_DL-CCCH"
        rrc_message_RRCSet_value = translations_cfg.get(rrc_message_field_DLCCCH_verify,"rrcSetup")
        rrc_message_field_ULDCCH_verify = rrc_message_field + "_UL-DCCH"
        rrc_message_RRCSetComp_value = translations_cfg.get(rrc_message_field_ULDCCH_verify,"rrcSetupComplete")
    if rrc_sub_type_field is not None:
        rrc_sub_type_RRCULCCCH_value = translations_cfg.get(rrc_sub_type_field_verify,"NR RRC UL CCCH")
        rrc_sub_type_RRCULDCCH_value = translations_cfg.get(rrc_sub_type_field_verify,"NR RRC UL DCCH")
        rrc_sub_type_RRCDLCCCH_value = translations_cfg.get(rrc_sub_type_field_verify,"NR RRC DL CCCH")

    # Create per-frame index for efficient lookup
    sorted_packets = sorted(packets, key=lambda pkt: int(pkt["fields"].get(frame_field, 0)))

    # Scan RRCConnectionRequests
    for pkt in packets:
        version = pkt["fields"].get(gsmtap_version_field_v3)
        if gsmtap_type_field is not None:
            gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field,"NR RRC")
        # 5G RRC filter
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        if pkt["fields"].get(rrc_sub_type_field) not in [rrc_sub_type_RRCULCCCH_value,rrc_sub_type_RRCULDCCH_value,rrc_sub_type_RRCDLCCCH_value]:
            continue
        # RRC Setup Request/Setup/Setup Complete filter
        if pkt["fields"].get(rrc_message_field) not in [rrc_message_RRCSetReq_value,rrc_message_RRCSet_value,rrc_message_RRCSetComp_value]:
            continue
        if pkt["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCDLCCCH_value:
            messagefield = rrc_message_field_DLCCCH_verify
        elif pkt["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCULCCCH_value:
            messagefield = rrc_message_field_ULCCCH_verify
        elif pkt["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCULDCCH_value:
            messagefield = rrc_message_field_ULDCCH_verify
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(rrc_sub_type_field)
        message = pkt["fields"].get(rrc_message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        pci = pkt["fields"].get(gsmtap_pci_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        if idtype == mobileid_type_STMSI_Part1_value:
            id = decimal_id_to_hex(pkt["fields"].get(stmsi_part1_field))
        elif idtype == mobileid_type_RandomValue_value:
            id = decimal_id_to_hex(pkt["fields"].get(randomvalue_field))
        else:
            id = ""

        # Find nearest RRCSetupComplete
        closest_ref = None
        closest_distance = None
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if rrc_message_RRCSetComp_value in ref["fields"].get(rrc_message_field) and ref["fields"].get(rrc_sub_type_field) == rrc_sub_type_RRCULDCCH_value:
                distance = abs(ref_frame - frame)
                if closest_distance is None or distance < closest_distance:
                    closest_distance = distance
                    closest_ref = ref
        if closest_ref:
            id_part2 = closest_ref["fields"].get(stmsi_part2_field)

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": rrc_sub_type_field,
            "SubType": sub_type,
            "MessageField": messagefield,
            "Message": message,
            "ARFCN": arfcn,
            "PCI": pci,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID Part 1": id,
            "ID Part 2": id_part2,
        })
    return results

def extract_5g_nas_id(
    packets: List[Dict[str, Any]],
    nrnas_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract 5G (NR NAS) IDs from Registration and Identity messages.

    Supports Registration Request/Accept/Complete, Identity Request/Response,
    and Service Request/Accept. Handles multiple 5G-GUTIs in a single message
    (two-slot layout) and the 5G S-TMSI single-ID path. IMSI is never exposed.

    Args:
        packets: List of packet dicts.
        nrnas_fields: 5G NAS field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID → list of extracted records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    nas_sub_type_field = misc_fields.get("SubTypeV3")
    gsmtap_payload_field = misc_fields.get("PayloadV3")
    gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
    # 5G NAS headers
    mobileid_type_field = nrnas_fields.get("MobileIDType")
    if mobileid_type_field is not None:
        mobileid_type_GUTI_value = translations_cfg.get(mobileid_type_field,"5G-GUTI")
        mobileid_type_5G_STMSI_value = translations_cfg.get(mobileid_type_field,"5G-S-TMSI")
    tmsi5g_field = nrnas_fields.get("5G_TMSI")
    nas_msg_type_field = nrnas_fields.get("NASMsgType")
    if nas_msg_type_field is not None:
        nas_msg_type_RegReq_value = translations_cfg.get(nas_msg_type_field,"Registration request")
        nas_msg_type_RegAcpt_value = translations_cfg.get(nas_msg_type_field,"Registration accept")
        nas_msg_type_RegComp_value = translations_cfg.get(nas_msg_type_field,"Registration complete")
        nas_msg_type_ServReq_value = translations_cfg.get(nas_msg_type_field,"Service request")
        nas_msg_type_ServAcpt_value = translations_cfg.get(nas_msg_type_field,"Service accept")
        nas_msg_type_IDReq_value = translations_cfg.get(nas_msg_type_field,"Identity request")
        nas_msg_type_IDResp_value = translations_cfg.get(nas_msg_type_field,"Identity response")
    mcc_field = nrnas_fields.get("MCC_5G_GUAMI")
    mnc_field = nrnas_fields.get("MNC_5G_GUAMI")
    lac_field = nrnas_fields.get("LAC_5G_GUAMI")
    amf_region_id_field = nrnas_fields.get("AMF_REGION_ID")
    amf_set_id_field = nrnas_fields.get("AMF_SET_ID")
    amf_pointer_field = nrnas_fields.get("AMF_POINTER")

    for pkt in packets:
        if gsmtap_payload_field is not None:
            gsmtap_type_field_values = translations_cfg.get(gsmtap_payload_field,"NR NAS")
        # 5G NAS filter
        if pkt["fields"].get(gsmtap_payload_field) != gsmtap_type_field_values:
            continue
        # NAS Registration Request filter
        if pkt["fields"].get(nas_msg_type_field) not in [nas_msg_type_RegReq_value,nas_msg_type_RegAcpt_value,nas_msg_type_RegComp_value,nas_msg_type_ServReq_value,nas_msg_type_ServAcpt_value,nas_msg_type_IDReq_value,nas_msg_type_IDResp_value]:
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field_v3)
        payload = pkt["fields"].get(gsmtap_payload_field)
        sub_type = pkt["fields"].get(nas_sub_type_field)
        mcc = pkt["fields"].get(mcc_field)
        mnc = pkt["fields"].get(mnc_field)
        lac = pkt["fields"].get(lac_field)
        message = pkt["fields"].get(nas_msg_type_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        amf_region_id = pkt["fields"].get(amf_region_id_field)
        amf_set_id = pkt["fields"].get(amf_set_id_field)
        amf_pointer = pkt["fields"].get(amf_pointer_field)
        idtype = pkt["fields"].get(mobileid_type_field)

        # If 5G-GUTI, there may be multiple IDs in one message
        if idtype and (mobileid_type_GUTI_value in idtype):
            raw_tmsi5g = pkt["fields"].get(tmsi5g_field)
            guti_ids: List[str] = []
            if isinstance(raw_tmsi5g, list):
                guti_ids = [str(x).strip() for x in raw_tmsi5g if str(x).strip()]
            elif isinstance(raw_tmsi5g, str):
                candidate = raw_tmsi5g.replace(";", ",")
                parts: List[str] = []
                for chunk in candidate.split(","):
                    parts.extend(chunk.split())
                guti_ids = [p.strip() for p in parts if p.strip()]
            elif raw_tmsi5g is not None:
                guti_ids = [str(raw_tmsi5g).strip()]
            # Limit to two IDs
            if len(guti_ids) > 2:
                guti_ids = guti_ids[:2]
            id1 = decimal_id_to_hex(guti_ids[0]) if len(guti_ids) >= 1 else None
            id2 = decimal_id_to_hex(guti_ids[1]) if len(guti_ids) >= 2 else None
            # Align AMF fields per ID when multiple values are present
            def _to_list_any(val: Any) -> List[str]:
                """Normalize a value to a list of strings.

                Accepts lists or delimited strings (comma/semicolon/whitespace).
                """
                if val is None:
                    return []
                if isinstance(val, list):
                    return [str(x).strip() for x in val if str(x).strip()]
                s = str(val)
                s = s.replace(";", ",")
                parts: List[str] = []
                for chunk in s.split(","):
                    parts.extend(chunk.split())
                return [p.strip() for p in parts if p.strip()]
            amf_region_list = _to_list_any(amf_region_id)
            amf_set_list = _to_list_any(amf_set_id)
            amf_pointer_list = _to_list_any(amf_pointer)
            idtype_list = _to_list_any(idtype)
            idtype_1 = idtype_list[0] if id1 and len(idtype_list) >= 1 else (idtype if id1 else None)
            idtype_2 = idtype_list[1] if id2 and len(idtype_list) >= 2 else (idtype if id2 and len(idtype_list)==1 else (idtype if id2 and idtype and not idtype_list else None))
            amf_region_1 = amf_region_list[0] if id1 and len(amf_region_list) >= 1 else (amf_region_id if id1 else None)
            amf_region_2 = amf_region_list[1] if id2 and len(amf_region_list) >= 2 else (amf_region_id if id2 and len(amf_region_list)==1 else (amf_region_id if id2 and amf_region_id and not amf_region_list else None))
            amf_set_1 = amf_set_list[0] if id1 and len(amf_set_list) >= 1 else (amf_set_id if id1 else None)
            amf_set_2 = amf_set_list[1] if id2 and len(amf_set_list) >= 2 else (amf_set_id if id2 and len(amf_set_list)==1 else (amf_set_id if id2 and amf_set_id and not amf_set_list else None))
            amf_pointer_1 = amf_pointer_list[0] if id1 and len(amf_pointer_list) >= 1 else (amf_pointer if id1 else None)
            amf_pointer_2 = amf_pointer_list[1] if id2 and len(amf_pointer_list) >= 2 else (amf_pointer if id2 and len(amf_pointer_list)==1 else (amf_pointer if id2 and amf_pointer and not amf_pointer_list else None))

            results[id1 or id2 or ""].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": nas_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "LAC": lac,
                "MessageField": nas_msg_type_field,
                "Message": message,
                "ARFCN": arfcn,
                "ID Type Field": mobileid_type_field,
                "ID Type 1": idtype_1,
                "AMF Region ID 1": amf_region_1,
                "AMF Set ID 1": amf_set_1,
                "AMF Pointer 1": amf_pointer_1,
                "ID1": id1,
                "ID Type 2": idtype_2,
                "AMF Region ID 2": amf_region_2,
                "AMF Set ID 2": amf_set_2,
                "AMF Pointer 2": amf_pointer_2,
                "ID2": id2,
            })
            continue

        # 5G S-TMSI (single id path)
        elif idtype == mobileid_type_5G_STMSI_value:
            id_val = decimal_id_to_hex(pkt["fields"].get(tmsi5g_field))
            results[id_val].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": nas_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "LAC": lac,
                "MessageField": nas_msg_type_field,
                "Message": message,
                "ARFCN": arfcn,
                "ID Type Field": mobileid_type_field,
                "ID Type 1": idtype,
                "AMF Region ID 1": amf_region_id,
                "AMF Set ID 1": amf_set_id,
                "AMF Pointer 1": amf_pointer,
                "ID1": id_val,
                "ID Type 2": None,
                "AMF Region ID 2": None,
                "AMF Set ID 2": None,
                "AMF Pointer 2": None,
                "ID2": None,
            })
            continue
        else:
            id_val = ""
            results[id_val].append({
                "Timestamp": ts,
                "Frame": frame,
                "Version": version,
                "PayloadField": gsmtap_payload_field,
                "Payload": payload,
                "SubTypeField": nas_sub_type_field,
                "SubType": sub_type,
                "MCC": mcc,
                "MNC": mnc,
                "LAC": lac,
                "MessageField": nas_msg_type_field,
                "Message": message,
                "ARFCN": arfcn,
                "ID Type Field": mobileid_type_field,
                "ID Type 1": idtype,
                "AMF Region ID 1": amf_region_id,
                "AMF Set ID 1": amf_set_id,
                "AMF Pointer 1": amf_pointer,
                "ID1": id_val,
                "ID Type 2": None,
                "AMF Region ID 2": None,
                "AMF Set ID 2": None,
                "AMF Pointer 2": None,
                "ID2": None,
            })
    return results


# Paging

def extract_2g_paging(
    packets: List[Dict[str, Any]],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, str]]]:
    """
    Extract GSM paging requests (Type 1/2/3) from provided packets.

    Builds ID slots using TMSI from Paging and optional IMSI digits field. IMSI is
    not exposed (empty string) for privacy. Associates the closest SIT6 to enrich
    with LAC/MCC/MNC and ARFCN.

    Args:
        packets: List of packet dicts.
        gsm_fields: GSM field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, str]]]: Map of ID (or first present ID) → list of records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType2")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # GSM headers
    mcc_field = gsm_fields.get("MCC_2G")
    mnc_field = gsm_fields.get("MNC_2G")
    lac_field = gsm_fields.get("LAC_2G")
    cell_field = gsm_fields.get("CellID_2G")
    msg_rr_type_field = gsm_fields.get("DTAPRRType")
    if msg_rr_type_field is not None:
        msg_rr_type_PagingReqType1value = translations_cfg.get(msg_rr_type_field, "Paging Request Type 1")
        msg_rr_type_PagingReqType2value = translations_cfg.get(msg_rr_type_field, "Paging Request Type 2")
        msg_rr_type_PagingReqType3value = translations_cfg.get(msg_rr_type_field, "Paging Request Type 3")
        msg_rr_type_SIT6value = translations_cfg.get(msg_rr_type_field, "System Information Type 6")
    mobileid_type_field = gsm_fields.get("MobileIDTypeLegacy")
    if mobileid_type_field is not None:
        mobileid_type_imsi_value = translations_cfg.get(mobileid_type_field,"IMSI")
        mobileid_type_tmsi_value = translations_cfg.get(mobileid_type_field,"TMSI")
    if gsmtap_type_field is not None:
        gsmtap_type_field_values = [translations_cfg.get(gsmtap_type_field,"GSM Um"),translations_cfg.get(gsmtap_type_field,"GSM Abis")]
    imsi_field = gsm_fields.get("IMSI")
    tmsi_field = gsm_fields.get("TMSI")
    paging_tmsi_field = gsm_fields.get("PagingTMSI")

    # Search for Paging Request data
    # Create per-frame index for efficient lookup
    sorted_packets = sorted(packets, key=lambda x: int(x["fields"].get(frame_field, 0)))
    for pkt in packets:
        # GSM filter
        if pkt["fields"].get(gsmtap_type_field) not in gsmtap_type_field_values:
            continue
        # Filter Paging Request Type 1/2/3
        if pkt["fields"].get(msg_rr_type_field) not in [msg_rr_type_PagingReqType1value,msg_rr_type_PagingReqType2value,msg_rr_type_PagingReqType3value]:
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(msg_rr_type_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        if pkt["fields"].get(msg_rr_type_field) == msg_rr_type_PagingReqType1value:

            if idtype == mobileid_type_imsi_value:
                # id1 = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
                id1 = ""
                id2 = None
                id3 = None
                id4 = None
            elif idtype == mobileid_type_tmsi_value:
                id1 = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
                id2 = None
                id3 = None
                id4 = None
            else:
                continue
        elif pkt["fields"].get(msg_rr_type_field) == msg_rr_type_PagingReqType2value:
            raw_ids = pkt["fields"].get(paging_tmsi_field)
            ids = []
            if isinstance(raw_ids, list):
                ids = [str(x).strip() for x in raw_ids if str(x).strip()]
            elif isinstance(raw_ids, str):
                candidate = raw_ids.replace(";", ",")
                parts = []
                for chunk in candidate.split(","):
                    parts.extend(chunk.split())
                ids = [p.strip() for p in parts if p.strip()]
            elif raw_ids is not None:
                ids = [str(raw_ids).strip()]
            # Assign up to two IDs
            id1 = decimal_id_to_hex(ids[0]) if len(ids) > 0 else None
            id2 = decimal_id_to_hex(ids[1]) if len(ids) > 1 else None
            if idtype == mobileid_type_imsi_value:
                # id3 = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
                id3 = ""
                id4 = None
            elif idtype == mobileid_type_tmsi_value:
                id3 = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
                id4 = None
            else:
                id3 = None
                id4 = None
        elif pkt["fields"].get(msg_rr_type_field) == msg_rr_type_PagingReqType3value:
            raw_ids = pkt["fields"].get(paging_tmsi_field)
            ids = []
            if isinstance(raw_ids, list):
                ids = [str(x).strip() for x in raw_ids if str(x).strip()]
            elif isinstance(raw_ids, str):
                candidate = raw_ids.replace(";", ",")
                parts = []
                for chunk in candidate.split(","):
                    parts.extend(chunk.split())
                ids = [p.strip() for p in parts if p.strip()]
            elif raw_ids is not None:
                ids = [str(raw_ids).strip()]
            # Assign up to two IDs
            id1 = decimal_id_to_hex(ids[0]) if len(ids) > 0 else None
            id2 = decimal_id_to_hex(ids[1]) if len(ids) > 1 else None
            id3 = decimal_id_to_hex(ids[2]) if len(ids) > 2 else None
            id4 = decimal_id_to_hex(ids[3]) if len(ids) > 3 else None
         # Initialize variables for cell and location data
        lac = cell = mcc = mnc = ""
        closest_ref = None  # Reference to the closest SIT6 packet
        closest_frame = -1
        next_ref = None
        next_frame = None
        # Find the closest SIT6 packet to retrieve cell and location information
        for ref in sorted_packets:
            ref_frame = int(ref["fields"].get(frame_field, 0))
            if ref["fields"].get(msg_rr_type_field) == msg_rr_type_SIT6value and ref["fields"].get(gsmtap_arfcn_field) == arfcn:
                if ref_frame < frame and ref_frame > closest_frame:
                    closest_frame = ref_frame
                    closest_ref = ref
                elif ref_frame > frame and (next_frame is None or ref_frame < next_frame):
                    next_frame = ref_frame
                    next_ref = ref
        if closest_ref:
            lac  = closest_ref["fields"].get(lac_field, "")
            cell = closest_ref["fields"].get(cell_field, "")
            mcc  = closest_ref["fields"].get(mcc_field, "")
            mnc  = closest_ref["fields"].get(mnc_field, "")
        elif next_ref:
            lac  = next_ref["fields"].get(lac_field, "")
            cell = next_ref["fields"].get(cell_field, "")
            mcc  = next_ref["fields"].get(mcc_field, "")
            mnc  = next_ref["fields"].get(mnc_field, "")
        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MCC": mcc,
            "MNC": mnc,
            "LAC": lac,
            "ARFCN": arfcn,
            "Cell": cell,
            "MessageField": msg_rr_type_field,
            "Message": message,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID1": id1,
            "ID2": id2,
            "ID3": id3,
            "ID4": id4,
        })
    return results

def extract_3g_paging(
    packets: List[Dict[str, Any]],
    umts_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, Any]]]:
    """
    Extract UMTS paging (pagingType1) records from PCCH.

    Filters RRC PCCH/pagingType1, reconstructs IDs (TMSI/PTMSI; IMSI hidden),
    and records paging domain.

    Args:
        packets: List of packet dicts.
        umts_fields: UMTS field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, Any]]]: Map of ID → list of records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_type_field = misc_fields.get("Payload")
    gsmtap_sub_type_field = misc_fields.get("SubType")
    gsmtap_arfcn_field = misc_fields.get("ARFCN")
    # UMTS headers
    if gsmtap_type_field is not None:
        gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field,"UMTS RRC")
    mobileid_type_field = umts_fields.get("MobileIDTypePaging")
    paging_domain_field = umts_fields.get("PagingDomain")
    paging_record_field = umts_fields.get("PagingRecord")
    if mobileid_type_field is not None:
        mobileid_type_imsi_value = translations_cfg.get(mobileid_type_field,"IMSI")
        mobileid_type_tmsi_value = translations_cfg.get(mobileid_type_field,"TMSI")
        mobileid_type_ptmsi_value = translations_cfg.get(mobileid_type_field,"PTMSI")
    imsi_field = umts_fields.get("IMSI_MAP")
    tmsi_field = umts_fields.get("TMSI_MAP")
    ptmsi_field = umts_fields.get("PTMSI_MAP")
    rrc_message_field = umts_fields.get("RRCMsgType")
    if rrc_message_field is not None:
        rrc_message_field_verify = rrc_message_field + "_PCCH"
        rrc_message_pagingType1_value = translations_cfg.get(rrc_message_field_verify,"pagingType1")
    rrc_sub_type_field = misc_fields.get("SubType")
    if rrc_sub_type_field is not None:
        rrc_sub_type_RRCPCCH_value = translations_cfg.get(rrc_sub_type_field,"RRC PCCH")
    for pkt in packets:
      # UMTS RRC filter
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        # Filter pagingType1
        if pkt["fields"].get(rrc_message_field) != rrc_message_pagingType1_value or pkt["fields"].get(rrc_sub_type_field) != rrc_sub_type_RRCPCCH_value:
            continue
        if pkt["fields"].get(paging_record_field) != "0":
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        version = pkt["fields"].get(gsmtap_version_field)
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(gsmtap_sub_type_field)
        message = pkt["fields"].get(rrc_message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        paging_domain = pkt["fields"].get(paging_domain_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        if idtype == mobileid_type_imsi_value:
            # id = pkt["fields"].get(imsi_field) # Avoid exposing IMSI unnecessarily
            id = ""
        elif idtype == mobileid_type_tmsi_value:
            id = decimal_id_to_hex(pkt["fields"].get(tmsi_field))
        elif idtype == mobileid_type_ptmsi_value:
            id = decimal_id_to_hex(pkt["fields"].get(ptmsi_field))
        else:
            id = None
            continue

        results[id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": gsmtap_sub_type_field,
            "SubType": sub_type,
            "MessageField": rrc_message_field_verify,
            "Message": message,
            "ARFCN": arfcn,
            "Domain": paging_domain,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": id,
        })
    return results

def extract_4g_paging(
    packets: List[Dict[str, Any]],
    lterrc_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, Any]]]:
    """
    Extract LTE RRC (PCCH) paging records.

    Accepts either C1 message 'paging' or the presence of pagingRecordList.
    Builds up to five aligned slots per row (Domain, ID Type, MMEC, ID),
    normalizing IDs (S-TMSI as hex) and hiding IMSI.

    Args:
        packets: List of packet dicts.
        lterrc_fields: LTE RRC field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, Any]]]: Map of primary ID → list of records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field = misc_fields.get("Version")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    # 4G RRC headers
    mobileid_type_field = lterrc_fields.get("MobileIDType")
    mmec_field = lterrc_fields.get("MMEC")
    mtmsi_field = lterrc_fields.get("MTMSI")
    imsi_field = lterrc_fields.get("PagingIMSI_digit")
    paging_domain_field = lterrc_fields.get("PagingDomain")
    paging_record_field = lterrc_fields.get("PagingRecord")
    if mobileid_type_field is not None:
        mobileid_type_field_verify = mobileid_type_field + "_paging"
        mobileid_type_STMSI_value = translations_cfg.get(mobileid_type_field_verify,"s-TMSI")
        mobileid_type_IMSI_value = translations_cfg.get(mobileid_type_field_verify,"imsi")
    rrc_message_field = lterrc_fields.get("C1Message")
    if rrc_message_field is not None:
        rrc_message_field_verify = rrc_message_field + "_PCCH"
        rrc_message_paging_value = translations_cfg.get(rrc_message_field_verify,"paging")
    rrc_sub_type_field = lterrc_fields.get("SubType")
    if rrc_sub_type_field is not None:
        rrc_sub_type_field_verify = rrc_sub_type_field + "_LTERRC"

    def _to_list(val: Any) -> List[str]:
        """Convert an arbitrary value to a list of stripped strings.

        Handles lists and strings with comma/semicolon/space separators.
        """
        if val is None:
            return []
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        s = str(val)
        s = s.replace(";", ",")
        parts: List[str] = []
        for chunk in s.split(","):
            parts.extend(chunk.split())
        return [p for p in parts if p]

    def _digit_str(x: Any) -> str:
        """Convert an IMSI digit element to a single decimal digit string.

        Handles forms like 0x7, 0x2, integers, or already-decimal strings.
        """
        if isinstance(x, int):
            return str(x)
        s = str(x).strip()
        if s.lower().startswith("0x"):
            try:
                return str(int(s, 16))
            except Exception:
                return s
        return s

    for pkt in packets:
        version = pkt["fields"].get(gsmtap_version_field) or pkt["fields"].get(gsmtap_version_field_v3)
        # Resolve per-version fields
        if version == "3":
            rrc_sub_type_field = misc_fields.get("SubTypeV3")
            gsmtap_type_field = misc_fields.get("PayloadV3")
            gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
            rrc_sub_type_field_verify = (rrc_sub_type_field + "_LTERRC") if rrc_sub_type_field else None
        elif version == "2":
            rrc_sub_type_field = misc_fields.get("SubType2")
            gsmtap_type_field = misc_fields.get("Payload")
            gsmtap_arfcn_field = misc_fields.get("ARFCN")
            rrc_sub_type_field_verify = rrc_sub_type_field if rrc_sub_type_field else None
        else:
            rrc_sub_type_field = None
            gsmtap_type_field = None
            gsmtap_arfcn_field = None
            rrc_sub_type_field_verify = None

        # Translate payload and subtype values
        gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field, "LTE RRC") if gsmtap_type_field else None
        rrc_sub_type_PCCH_value_local = translations_cfg.get(rrc_sub_type_field_verify, "RRC PCCH") if rrc_sub_type_field_verify else None

        if gsmtap_type_field_values is None or pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        if rrc_sub_type_PCCH_value_local is None or pkt["fields"].get(rrc_sub_type_field) != rrc_sub_type_PCCH_value_local:
            continue
        # Accept either: c1 message == 'paging' OR pagingRecordList present
        c1_is_paging = (pkt["fields"].get(rrc_message_field) == rrc_message_paging_value)
        has_paging_record = (paging_record_field is not None and pkt["fields"].get(paging_record_field) is not None)
        if not (c1_is_paging or has_paging_record):
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        payload = pkt["fields"].get(gsmtap_type_field)
        sub_type = pkt["fields"].get(rrc_sub_type_field)
        message = pkt["fields"].get(rrc_message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        paging_record = pkt["fields"].get(paging_record_field)
        # Build per-record arrays (agnostic to count)
        domains = _to_list(pkt["fields"].get(paging_domain_field))
        # Keep raw ID types; translation happens in table builder using ID Type Field
        idtypes = _to_list(pkt["fields"].get(mobileid_type_field))
        mtmsis = _to_list(pkt["fields"].get(mtmsi_field))
        # Optional MMEC per record, if available in fields (not mandatory)
        mmecs = _to_list(pkt["fields"].get(mmec_field)) if mmec_field else []
        # IMSI reconstruction: ALWAYS from digits list (PagingIMSI_digit) to avoid tokens like '0x7, 0x2'
        imsi_slots_idx = [i for i, t in enumerate(idtypes) if t == mobileid_type_IMSI_value]
        imsi_ids: List[str] = []
        imsi_digits_val = pkt["fields"].get(imsi_field)
        if isinstance(imsi_digits_val, list):
            imsi_digits_list = [_digit_str(d) for d in imsi_digits_val]
            if len(imsi_slots_idx) > 0 and len(imsi_digits_list) >= 15 * len(imsi_slots_idx):
                for j in range(len(imsi_slots_idx)):
                    start = j * 15
                    imsi_ids.append("".join(imsi_digits_list[start:start+15]))
            else:
                joined = "".join(imsi_digits_list)
                if joined:
                    imsi_ids = [joined] * max(1, len(imsi_slots_idx))
        else:
            # Handle delimited string like '0x7, 0x2 ...' -> ['7','2',...] -> '72...'
            if imsi_digits_val:
                s = str(imsi_digits_val).replace(";", ",")
                tokens: List[str] = []
                for part in s.split(","):
                    tokens.extend(part.split())
                conv = [_digit_str(tok) for tok in tokens if tok.strip()]
                digits_only = [d for d in conv if d.isdigit()]
                joined = "".join(digits_only)
            else:
                joined = ""
            if joined:
                imsi_ids = [joined] * max(1, len(imsi_slots_idx))

        max_len = max(len(domains), len(idtypes), len(mtmsis), len(mmecs) if mmecs else 0, 1)
        # Prepare up to 5 slots to align with table columns
        slot_domains: List[Optional[str]] = []
        slot_idtypes: List[Optional[str]] = []
        slot_ids: List[Optional[str]] = []
        slot_mmecs: List[Optional[str]] = []
        imsi_idx = 0
        for i in range(max_len):
            dom = domains[i] if i < len(domains) else None
            idt = idtypes[i] if i < len(idtypes) else None
            # Decide ID by type
            mt = mtmsis[i] if i < len(mtmsis) else None
            mm = mmecs[i] if i < len(mmecs) else None
            if idt == mobileid_type_IMSI_value or (not mt and imsi_ids):
                # Use IMSI if explicitly marked, or when MTMSI missing but IMSI digits exist
                ident = imsi_ids[imsi_idx] if imsi_idx < len(imsi_ids) else (imsi_ids[-1] if imsi_ids else None)
                imsi_idx += 1
                if idt != mobileid_type_IMSI_value:
                    idt = mobileid_type_IMSI_value
            else:
                ident = mt
            slot_domains.append(dom)
            slot_idtypes.append(idt)
            # Ensure mm is defined for IMSI branch as well
            if idt == mobileid_type_IMSI_value:
                mm = mmecs[i] if i < len(mmecs) else None
                # slot_ids.append(ident) # Avoid exposing IMSI unnecessarily
                slot_ids.append("")
            else:
                slot_ids.append(decimal_id_to_hex(ident))
            slot_mmecs.append(mm)

        # Trim/pad to 5 positions
        while len(slot_domains) < 5:
            slot_domains.append(None)
            slot_idtypes.append(None)
            slot_ids.append(None)
            slot_mmecs.append(None)
        slot_domains = slot_domains[:5]
        slot_idtypes = slot_idtypes[:5]
        slot_ids = slot_ids[:5]
        slot_mmecs = slot_mmecs[:5]

        # Use first present ID as grouping key
        group_id = next((x for x in slot_ids if x), None)
        if group_id is None:
            continue

        results[group_id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": rrc_sub_type_field,
            "SubType": sub_type,
            "MessageField": rrc_message_field_verify,
            "Message": message,
            "ARFCN": arfcn,
            "ID Type Field": mobileid_type_field_verify,
            "Paging Record": paging_record,
            "Domain 1": slot_domains[0],
            "ID Type 1": slot_idtypes[0],
            "MMEC 1": slot_mmecs[0],
            "ID1": slot_ids[0],
            "Domain 2": slot_domains[1],
            "ID Type 2": slot_idtypes[1],
            "MMEC 2": slot_mmecs[1],
            "ID2": slot_ids[1],
            "Domain 3": slot_domains[2],
            "ID Type 3": slot_idtypes[2],
            "MMEC 3": slot_mmecs[2],
            "ID3": slot_ids[2],
            "Domain 4": slot_domains[3],
            "ID Type 4": slot_idtypes[3],
            "MMEC 4": slot_mmecs[3],
            "ID4": slot_ids[3],
            "Domain 5": slot_domains[4],
            "ID Type 5": slot_idtypes[4],
            "MMEC 5": slot_mmecs[4],
            "ID5": slot_ids[4],
        })
    return results

def extract_5g_paging(
    packets: List[Dict[str, Any]],
    nrrrc_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> DefaultDict[str, List[Dict[str, Any]]]:
    """
    Extract NR RRC (PCCH) paging records.

    Filters NR RRC PCCH/paging and builds a mapping of NG-5G-S-TMSI to paging
    records with timestamp, ARFCN, and subtype details.

    Args:
        packets: List of packet dicts.
        nrrrc_fields: NR RRC field mapping.
        misc_fields: Miscellaneous field mapping.
        translations_cfg: Translations for field values.

    Returns:
        DefaultDict[str, List[Dict[str, Any]]]: Map of NG-5G-S-TMSI → list of records.
    """
    results = defaultdict(list)
    # MISC headers
    ts_field = misc_fields.get("Timestamp")
    frame_field = misc_fields.get("Frame")
    gsmtap_version_field_v3 = misc_fields.get("VersionV3")
    gsmtap_pci_field = misc_fields.get("PCIV3")
    rrc_sub_type_field = misc_fields.get("SubTypeV3")
    if rrc_sub_type_field is not None:
        rrc_sub_type_field_verify = rrc_sub_type_field + "_NRRRC"
    gsmtap_type_field = misc_fields.get("PayloadV3")
    gsmtap_arfcn_field = misc_fields.get("ARFCNV3")
    gsmtap_type_field_values = translations_cfg.get(gsmtap_type_field,"NR RRC")
    # 5G RRC headers
    mobileid_type_field = nrrrc_fields.get("MobileIDType")
    ng_5G_S_TMSI_paging = nrrrc_fields.get("ng_5G_S_TMSI_paging")
    rrc_message_field = nrrrc_fields.get("C1Message")
    if rrc_message_field is not None:
        rrc_message_field_PCCH_verify = rrc_message_field + "_PCCH"
        rrc_message_paging_value = translations_cfg.get(rrc_message_field_PCCH_verify,"paging")
    if rrc_sub_type_field is not None:
        rrc_sub_type_PCCH_value = translations_cfg.get(rrc_sub_type_field_verify,"NR RRC PCCH")
    for pkt in packets:
        if pkt["fields"].get(gsmtap_type_field) != gsmtap_type_field_values:
            continue
        if pkt["fields"].get(rrc_sub_type_field) != rrc_sub_type_PCCH_value or pkt["fields"].get(rrc_message_field) != rrc_message_paging_value:
            continue
        ts = pkt["fields"].get(ts_field)
        frame = int(pkt["fields"].get(frame_field))
        payload = pkt["fields"].get(gsmtap_type_field)
        version = pkt["fields"].get(gsmtap_version_field_v3)
        sub_type = pkt["fields"].get(rrc_sub_type_field)
        message = pkt["fields"].get(rrc_message_field)
        arfcn = pkt["fields"].get(gsmtap_arfcn_field)
        pci = pkt["fields"].get(gsmtap_pci_field)
        idtype = pkt["fields"].get(mobileid_type_field)
        ng_5g_id = pkt["fields"].get(ng_5G_S_TMSI_paging)
        results[ng_5g_id].append({
            "Timestamp": ts,
            "Frame": frame,
            "Version": version,
            "PayloadField": gsmtap_type_field,
            "Payload": payload,
            "SubTypeField": rrc_sub_type_field,
            "SubType": sub_type,
            "MessageField": rrc_message_field_PCCH_verify,
            "Message": message,
            "ARFCN": arfcn,
            "PCI": pci,
            "ID Type Field": mobileid_type_field,
            "ID Type": idtype,
            "ID": ng_5g_id,
        })
    return results
