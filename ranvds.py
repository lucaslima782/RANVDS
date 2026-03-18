# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
RANVDS.py - RAN Vulnerability Detection System Main Module.

Purpose:
  - Process PCAP files or live traffic (via SCAT recording PCAP + tshark)
  - Extract 2G/3G/4G/5G algorithms and MCC/MNC network identifiers
  - Map MCC/MNC to Country and Operator using mcc-mnc.csv database
  - Generate ODS spreadsheet with comprehensive network analysis

Usage:
  # Analyze PCAP file
  python3 RANVDS.py -p capture.pcap -o output.ods

  # Live capture via SCAT
  python3 RANVDS.py -l [IP]

  # Generate security report from existing ODS
  python3 RANVDS.py -s network.ods

  # Parse modem dump files
  python3 RANVDS.py -d dump1.bin dump2.bin
"""

import argparse
import configparser
import csv
import datetime
import logging
import multiprocessing as mp
import subprocess
import sys
import time
import shutil
import os
import signal
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import json as _json
from collections import defaultdict as _defaultdict
from selection_profile import SelectionProfile
from table_builder import build_ods_table
from security_evaluator import (
    extract_sequences_from_ods,
    extract_ids_from_ods,
    extract_paging_from_ods,
    extract_suci_stats_from_ods,
    extract_vops_from_ods,
    extract_ue_cap_security_from_ods,
    extract_sip_ipsec_from_ods,
    write_crypto_checker_ods,
)
from pcap_analyzer import (
    extract_2g_voice_enc_info, extract_2g_data_enc_info, extract_3g_enc_info,
    extract_4g_rrc_enc_info, extract_4g_nas_enc_info, extract_5g_rrc_enc_info,
    extract_5g_nas_enc_info, extract_2g_voice_id, extract_2g_data_id, extract_3g_rrc_id,
    extract_3g_nas_id, extract_4g_rrc_id, extract_4g_nas_id, extract_5g_rrc_id,
    extract_5g_nas_id, extract_2g_paging, extract_3g_paging, extract_4g_paging,
    extract_5g_paging, extract_5g_nas_suci, extract_4g_nas_vops, extract_5g_nas_vops,
    extract_4g_ue_cap_security_msgs, extract_5g_ue_cap_security_msgs,
    extract_sip_packets,
)


# Configure logging for console output
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# -----------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -----------------------------------------------------------------------------
def get_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments provided by the user.

    Supported modes (mutually exclusive):
    - -p / --pcap <file.pcap>: Analyze a PCAP file and generate an ODS report.
    - -l / --live [IP]: Live capture via SCAT; generates PCAP and exits (no ODS).
        Optional IP parameter is currently ignored.
    - -d / --dump <file(s)>: Read modem dump(s) via SCAT and generate PCAP (no ODS).
    - -s / --security <file.ods>: Generate Security ODS from existing ODS.
        Default output: <stem>_Security.ods.

    Additional parameters:
    - Live mode: -t, -m, -i, -a/--usb, --start-magic, --live-outdir, --live-pcap.
    - Dump mode: --dump-type, --dump-model, --dump-outdir, --dump-pcap.
    - Security mode: --security-outdir (output directory), --security-name (custom filename).
    - PCAP mode (-p only): -o / --output defines ODS name; ignored with --live, --dump, --security.
      Without -o, a dynamic name (YYYYMMDD_HHMMSS_<Operator>.ods) is generated in current directory.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    # Create the CLI argument parser
    parser = argparse.ArgumentParser(
        description=(
            "RANVDS v2.0.0 — RAN Vulnerability Detection System. "
            "Analyzes cellular traffic (2G–5G) for security vulnerabilities: weak cipher detection, "
            "TMSI/GUTI randomness, IMSI exposure, paging leaks, IMS VoPS support (4G/5G), and 5G SUCI analysis. "
            "Four modes: PCAP analysis (generates multi-tab ODS), live capture (SCAT→PCAP), "
            "modem dump (SCAT→PCAP), or security evaluation (ODS→Security ODS) "
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pcap", help="Path to the PCAP file to analyze and generate an ODS")
    group.add_argument("-l", "--live", nargs="?", const="127.0.0.1",
                       help="Live capture via SCAT; generates a PCAP and exits (no ODS). The optional IP parameter is currently ignored.")
    group.add_argument("-d", "--dump", nargs="+",
                       help="Parse modem dump file(s) via SCAT and write a PCAP, then exit (no ODS).")
    group.add_argument("-s", "--security", help="Generate a security report from an existing ODS (e.g., -s table.ods). Evaluates cipher strength, TMSI randomness, IMSI paging exposure, 5G SUCI, and VoPS support (per-quintuplet MCC/MNC/TAC/PCI/ARFCN). Default output is <stem>_Security.ods; use --security-outdir to choose the folder and --security-name to set a custom filename.")
    parser.add_argument(
        "--profile-json", dest="profile_json", default=None,
        help=(
            "JSON-encoded SelectionProfile dict to control which analysis modules run. "
            "Keys include per-generation encryption (enc_2g_cs, enc_4g_rrc, …), "
            "identity (id_4g_nas, …), paging (paging_2g, …), "
            "VoPS (vops_4g, vops_5g), SUCI (suci_5g), and UE Capability (ue_capability). "
            "All keys default to true. Only meaningful with --pcap or --security."
        ),
    )
    # Additional parameters for Live mode (SCAT)
    parser.add_argument(
        "-t", dest="scat_type", choices=["sec", "qc"], default="sec",
        help="Chipset type for SCAT (-t): 'sec' (Samsung) or 'qc' (Qualcomm). Only with --live."
    )
    parser.add_argument(
        "-m", dest="scat_model", default=None,
        help="Model for SCAT (-m), e.g., e5123 (optional). Only with --live."
    )
    parser.add_argument(
        "-i", dest="scat_iface", default="4",
        help="Interface for SCAT (-i), e.g., 4. Only with --live."
    )
    parser.add_argument(
        "-a", "--usb", dest="usb_addr", default=None,
        help="Force USB address in BUS:DEVICE format (e.g., 001:004); overrides auto-detection. Only with --live."
    )
    parser.add_argument(
        "--start-magic", dest="start_magic", default="0x34dc12fe",
        help="Start magic for SCAT (optional), e.g., 0xffffffff. Only with --live."
    )
    parser.add_argument(
        "--live-outdir", dest="live_outdir", default=None,
        help="Output folder for the live capture PCAP (default: ./PCAPs). Only with --live."
    )
    parser.add_argument(
        "--live-pcap", dest="live_pcap", default=None,
        help="Output PCAP filename for live mode (optional). Only with --live."
    )
    # Additional parameters for Dump mode (SCAT dump analyzer)
    parser.add_argument(
        "--dump-type", dest="dump_type", choices=["sec", "qc"], default="sec",
        help="Chipset type for dump analysis: 'sec' (Samsung) or 'qc' (Qualcomm). Only with --dump."
    )
    parser.add_argument(
        "--dump-model", dest="dump_model", default=None,
        help="Model for Samsung dump analysis (optional), e.g., e5123. Only with --dump."
    )
    parser.add_argument(
        "--dump-outdir", dest="dump_outdir", default=None,
        help="Output folder for the generated PCAP (default: ./PCAPs). Only with --dump."
    )
    parser.add_argument(
        "--dump-pcap", dest="dump_pcap", default=None,
        help="Output PCAP filename for dump mode (optional). Only with --dump."
    )
    # Additional parameter for Security mode output
    parser.add_argument(
        "--security-outdir", dest="security_outdir", default=None,
        help="Output folder for the Security ODS (default: same directory as the input ODS). Only with --security."
    )
    parser.add_argument(
        "--security-name", dest="security_name", default=None,
        help="Custom filename for the Security ODS (.ods optional). Only with --security."
    )
    parser.add_argument(
        "-o", "--output", default="algorithms_table.ods",
        help=(
            "Output ODS filename (PCAP mode only). Ignored with --live, --dump and --security. If omitted, uses a dynamic name like YYYYMMDD_HHMMSS_<Operator>.ods in the current directory."
        ),
    )
    return parser.parse_args()


def detect_cell(scat_type: str) -> Tuple[str, str]:
    """
    Auto-detect USB connection of a cellular device.

    Executes the `lsusb` command and searches for a line containing the appropriate
    manufacturer keyword based on SCAT chipset type:
      - 'sec'  -> searches for 'Samsung'
      - 'qc'   -> searches for 'Qualcomm'
    From that line, extracts bus and port fields needed for SCAT execution
    with correct device identification.

    Args:
        scat_type: Chipset type ('sec' for Samsung, 'qc' for Qualcomm)

    Returns:
        Tuple[str, str]: (bus, port) if found; ('', '') if device not detected
                         or if command execution fails.
    """
    try:
        lsusb_out = subprocess.check_output(["lsusb"], text=True)
    except subprocess.CalledProcessError as e:
        logging.error("lsusb failed: %s", e)
        return "", ""

    keyword = "samsung" if scat_type == "sec" else "qualcomm"
    for line in lsusb_out.splitlines():
        if keyword in line.lower():
            parts = line.split()
            if len(parts) >= 4:  # Ensure we have enough parts
                bus = parts[1]
                port = parts[3].rstrip(":")
                logging.info(
                    "USB detected for %s: bus=%s port=%s",
                    "Samsung" if scat_type == "sec" else "Qualcomm",
                    bus,
                    port,
                )
                return bus, port

    logging.error("Device %s not found in lsusb", "Samsung" if scat_type == "sec" else "Qualcomm")
    return "", ""


def load_fields(cfg_path: Path) -> Tuple[
    Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str],
    Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str],
    Dict[str, str], Dict[str, str]
]:
    """
    Load field configuration from an CFG file (fields.cfg).

    Args:
        cfg_path (Path): Path to the configuration file (fields.cfg).

    Returns:
        Tuple[Dict[str, str], ...]: Tuple of dictionaries for each technology and group:
            - AlgorithmFields: Algorithm support indicators
            - UsedAlgorithmFields: Algorithm usage indicators
            - 2GFields (GSM), 3GFields (UMTS)
            - 4GRRCFields, 4GNASFields (LTE)
            - 5GRRCFields, 5GNASFields (NR)
            - MISCFields: Generic fields (timestamp, frame, ARFCN, etc.)
    """
    cfg = configparser.ConfigParser()
    cfg.optionxform = str  # type: ignore[assignment]
    cfg.read(cfg_path)
    alg = dict(cfg["AlgorithmFields"])
    used = dict(cfg["UsedAlgorithmFields"])
    misc = dict(cfg["MISCFields"])
    gsm = dict(cfg["2GFields"])
    umts = dict(cfg["3GFields"])
    lteRcc = dict(cfg["4GRRCFields"])
    lteNas = dict(cfg["4GNASFields"])
    nrRrc = dict(cfg["5GRRCFields"])
    nrNas = dict(cfg["5GNASFields"])
    sip = dict(cfg["SIPFields"]) if cfg.has_section("SIPFields") else {}
    return alg, used, gsm, umts, lteRcc, lteNas, nrRrc, nrNas, misc, sip


def load_translations(cfg_path: Path) -> configparser.ConfigParser:
    """
    Load translation mappings from an CFG file (translations.cfg).

    Args:
        cfg_path (Path): Path to the translations configuration file.

    Returns:
        configparser.ConfigParser: Loaded configuration parser with value translations.
    """
    cfg = configparser.ConfigParser()
    cfg.optionxform = str  # type: ignore[assignment]
    cfg.read(cfg_path)
    return cfg


def prepare_tshark_cmd(
    pcap: Optional[str] = None,
    live_ip: Optional[str] = None,
    total_fields: Optional[List[str]] = None
) -> List[str]:
    """
    Build the `tshark` command needed to extract desired fields from the capture.

    Operates in two modes:
    - Offline mode (with PCAP file): analyze a local file (no UDP 4729 filter needed).
    - Live mode: listen on the appropriate interface with filter for UDP traffic
                 on port 4729 (used by SCAT).

    Args:
        pcap (str): Path to the PCAP file (offline mode).
        live_ip (str): Target IP for the live capture filter.
        total_fields (List[str] | None): Tshark field names to extract (-e arguments).

    Returns:
        List[str]: Argument list comprising the full tshark command.
    """
    cmd = ["tshark"]
    if pcap:
        # Offline mode: read PCAP directly; no UDP 4729 filter required
        # because SCAT-generated PCAPs with -F do not use UDP encapsulation.
        cmd += ["-r", pcap]
    else:
        iface = "lo" if live_ip == "127.0.0.1" else "any"
        # Note: do NOT quote the filter here; subprocess will not use a shell.
        cmd += [
            "-i", iface, "-f",
            f"udp port 4729 and host {live_ip}"
        ]
    cmd += ["-T", "fields", "-E", "separator=/t"]
    if total_fields:
        cmd += sum([["-e", field] for field in total_fields], [])
    return cmd



def _scat_entry(argv: List[str]) -> None:
    """Entry point for running SCAT inside this binary in a child process.

    Exits the process with the same code SCAT would use.
    """
    import sys as _sys
    import os as _os
    try:
        # Import locally to avoid polluting parent globals
        import scat.main as _scat_main
    except Exception:
        # If import fails, exit non-zero so caller can detect
        _os._exit(2)
    # Simulate CLI argv for scat
    _sys.argv = argv
    try:
        _scat_main.scat_main()
        code = 0
    except SystemExit as e:
        try:
            code = int(getattr(e, 'code', 0) or 0)
        except Exception:
            code = 1
    except Exception:
        code = 1
    # Ensure child process exits with SCAT's code
    _os._exit(code)


class _ProcAdapter:
    """Adapter to present a subprocess-like interface for a multiprocessing.Process."""

    def __init__(self, proc: mp.Process):
        self._p = proc

    def wait(self) -> Optional[int]:
        self._p.join()
        return self.returncode

    @property
    def returncode(self) -> Optional[int]:
        return self._p.exitcode

    @property
    def pid(self) -> Optional[int]:
        """PID of the child process, if started."""
        try:
            return self._p.pid
        except Exception:
            return None

    def is_alive(self) -> bool:
        """Whether the child process is still running."""
        try:
            return self._p.is_alive()
        except Exception:
            return False

    def send_sigint(self) -> bool:
        """Send SIGINT to the child process to request a graceful stop.

        Returns True if the signal was sent, False otherwise.
        """
        pid = self.pid
        if not pid:
            return False
        try:
            os.kill(pid, signal.SIGINT)
            return True
        except Exception as e:
            try:
                logging.error("Failed to send SIGINT to SCAT (pid=%s): %s", pid, e)
            except Exception:
                pass
            return False


def launch_scat(
    bus: str,
    port: str,
    scat_type: str,
    scat_iface: str,
    scat_model: Optional[str] = None,
    start_magic: Optional[str] = None,
    pcap_path: Optional[Path] = None,
) -> Any:
    """
    Execute embedded SCAT in a child process via multiprocessing.

    Runs the SCAT entry point inside this binary (Nuitka) in a separate process
    to isolate argv/exit handling. If pcap_path is provided, SCAT writes directly
    to that file using its '-F' option.

    Returns:
        A subprocess-like adapter object providing wait() and returncode.
    """
    # Build SCAT argv from parameters
    # First element must be a dummy program name; argparse ignores argv[0]
    scat_argv: List[str] = [
        "scat", "-t", scat_type, "-3", "-u", "-a", f"{bus}:{port}", "-i", str(scat_iface)
    ]
    if scat_model:
        scat_argv += ["-m", str(scat_model)]
    if start_magic:
        scat_argv += ["--start-magic", str(start_magic)]
    if pcap_path:
        # pcap_path is already a full filename; pass it directly to SCAT
        scat_argv += ["-F", str(pcap_path)]
    logging.info("Starting embedded SCAT (in-binary)")
    try:
        logging.info("SCAT argv: %s", " ".join(scat_argv))
        if pcap_path:
            logging.info("PCAP path: %s", pcap_path)
    except Exception:
        pass
    # Run SCAT in a child process to isolate argv/exit and avoid impacting the parent
    p = mp.Process(target=_scat_entry, args=(scat_argv,), daemon=False)
    p.start()
    return _ProcAdapter(p)


def start_live_capture_nonblocking(
    bus: str,
    port: str,
    scat_type: str,
    scat_iface: str,
    scat_model: Optional[str] = None,
    start_magic: Optional[str] = None,
    pcap_dir: Optional[str] = None,
    pcap_filename: Optional[str] = None,
) -> Tuple[Any, Path]:
    """Start SCAT live capture in a child process and return immediately.

    Returns a tuple of (process_adapter, pcap_path).

    If pcap_dir is provided, the PCAP file will be created under that directory.
    If pcap_filename is also provided, it will be used; otherwise a timestamped
    name like 'live_capture_YYYYmmdd_HHMMSS.pcap' is chosen.
    """
    # Prepare PCAP output path; SCAT will write it directly (-F)
    out_dir = Path(pcap_dir) if pcap_dir else (Path.cwd() / "PCAPs")
    out_dir.mkdir(parents=True, exist_ok=True)
    if pcap_filename:
        pcap_path = out_dir / pcap_filename
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = out_dir / f"live_capture_{ts}.pcap"
    proc = launch_scat(
        bus, port, scat_type, scat_iface, scat_model, start_magic, pcap_path
    )
    try:
        logging.info("SCAT started (pid=%s), PCAP: %s", getattr(proc, "pid", None), pcap_path)
    except Exception:
        pass
    return proc, pcap_path


def launch_scat_dump(
    scat_type: str,
    dump_files: Any,
    scat_model: Optional[str] = None,
    pcap_path: Optional[Path] = None,
) -> Any:
    """
    Launch SCAT in a child process to parse modem dump file(s) and write PCAP directly.

    Arguments:
        scat_type: 'sec' or 'qc'.
        dump_files: Single path or list of paths to dump files (.sdm, .qmdl, .lpd, etc.).
        scat_model: Optional model override for Samsung ('sec').
        pcap_path: Optional full PCAP output path to write via '-F'.

    Returns a subprocess-like adapter with wait() and returncode properties.
    """
    # Normalize dump files into a list of strings
    files: List[str]
    try:
        if isinstance(dump_files, (list, tuple)):
            files = [str(p) for p in dump_files]
        else:
            files = [str(dump_files)]
    except Exception:
        files = [str(dump_files)]

    # Build SCAT argv
    scat_argv: List[str] = [
        "scat", "-t", scat_type, "-3", "-d",
    ] + files
    if scat_model and scat_type == "sec":
        scat_argv += ["-m", str(scat_model)]
    if pcap_path:
        scat_argv += ["-F", str(pcap_path)]
    logging.info("Starting embedded SCAT dump analysis (in-binary)")
    try:
        logging.info("SCAT argv: %s", " ".join(scat_argv))
        if pcap_path:
            logging.info("PCAP path: %s", pcap_path)
    except Exception:
        pass
    p = mp.Process(target=_scat_entry, args=(scat_argv,), daemon=False)
    p.start()
    return _ProcAdapter(p)


def start_dump_analyzer_nonblocking(
    scat_type: str,
    dump_files: Any,
    scat_model: Optional[str] = None,
    pcap_dir: Optional[str] = None,
    pcap_filename: Optional[str] = None,
) -> Tuple[Any, Path]:
    """Start SCAT dump analysis in a child process and return immediately.

    Returns a tuple of (process_adapter, pcap_path).

    If pcap_dir is provided, the PCAP file will be created under that directory.
    If pcap_filename is also provided, it will be used; otherwise a timestamped
    name like 'dump_capture_YYYYmmdd_HHMMSS.pcap' is chosen.
    """
    out_dir = Path(pcap_dir) if pcap_dir else (Path.cwd() / "PCAPs")
    out_dir.mkdir(parents=True, exist_ok=True)
    if pcap_filename:
        pcap_path = out_dir / pcap_filename
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = out_dir / f"dump_capture_{ts}.pcap"
    proc = launch_scat_dump(
        scat_type=scat_type,
        dump_files=dump_files,
        scat_model=scat_model,
        pcap_path=pcap_path,
    )
    try:
        logging.info("SCAT dump started (pid=%s), PCAP: %s", getattr(proc, "pid", None), pcap_path)
    except Exception:
        pass
    return proc, pcap_path


def _security_entry(ods_path_str: str, output_dir_str: str, retransmit_window_seconds: float = 10.0, tmsi_thresholds: Dict[str, float] | None = None, profile_dict: Dict[str, bool] | None = None) -> None:
    """Child-process entry: generate Security ODS from an existing ODS file.

    Reads algorithm sequences, identities and paging stats from the input ODS
    and writes a consolidated Security ODS into the given output directory.
    Exits the process with code 0 on success, non-zero on failure.
    """
    import os as _os
    try:
        ods_in = Path(ods_path_str)
        out_dir = Path(output_dir_str)
        if not ods_in.exists():
            try:
                logging.error("ODS file not found: %s", ods_in)
            except Exception:
                pass
            _os._exit(1)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            try:
                logging.error("Failed to create output dir: %s", out_dir)
            except Exception:
                pass
            _os._exit(2)

        try:
            logging.info("Reading ODS for security: %s", ods_in)
        except Exception:
            pass

        profile = SelectionProfile.from_dict(profile_dict) if profile_dict else SelectionProfile()
        sequences = extract_sequences_from_ods(ods_in)
        sequences = profile.filter_sequences(sequences)
        _raw_ids = extract_ids_from_ods(ods_in) if profile.any_id_enabled() else []
        identities = profile.filter_identity_records(_raw_ids) if _raw_ids else None
        _raw_paging = extract_paging_from_ods(ods_in) if profile.any_paging_enabled() else {}
        paging_stats = profile.filter_paging_stats(_raw_paging) if _raw_paging else None
        suci_stats = extract_suci_stats_from_ods(ods_in) if profile.suci_5g else None
        vops_stats = extract_vops_from_ods(ods_in) if (profile.vops_4g or profile.vops_5g) else None
        ue_cap_security_stats = None
        if profile.ue_cap_security_4g or profile.ue_cap_security_5g:
            ue_cap_security_stats = extract_ue_cap_security_from_ods(ods_in)
            if not profile.ue_cap_security_4g:
                ue_cap_security_stats.before_4g = 0
                ue_cap_security_stats.after_4g = 0
                ue_cap_security_stats.unknown_4g = 0
            if not profile.ue_cap_security_5g:
                ue_cap_security_stats.before_5g = 0
                ue_cap_security_stats.after_5g = 0
                ue_cap_security_stats.unknown_5g = 0
        sip_ipsec_stats = extract_sip_ipsec_from_ods(ods_in) if profile.sip_ipsec else None

        prefix = ods_in.stem
        out_path = write_crypto_checker_ods(
            out_dir,
            prefix,
            sequences,
            identities=identities or None,
            paging_stats=paging_stats or None,
            ts_margin_seconds=float(retransmit_window_seconds or 0.0),
            tmsi_thresholds=tmsi_thresholds,
            suci_stats=suci_stats,
            vops_stats=vops_stats,
            ue_cap_security_stats=ue_cap_security_stats,
            sip_ipsec_stats=sip_ipsec_stats,
        )
        try:
            logging.info("Security report generated: %s", out_path)
            # Emit a simple marker that UIs may parse if running in-process
            print(f"SECURITY_CREATED {out_path}")
        except Exception:
            pass
        _os._exit(0)
    except SystemExit as e:
        try:
            code = int(getattr(e, 'code', 1) or 1)
        except Exception:
            code = 1
        _os._exit(code)
    except Exception:
        try:
            import traceback as _tb
            logging.error("Security generation error:\n%s", _tb.format_exc())
        except Exception:
            pass
        _os._exit(1)


def start_security_report_nonblocking(
    ods_path: Any,
    output_dir: Optional[str] = None,
    retransmit_window_seconds: float = 10.0,
    tmsi_thresholds: Dict[str, float] | None = None,
    profile_dict: Dict[str, bool] | None = None,
) -> Any:
    """Launch Security report generation in a child process and return immediately.

    Arguments:
        ods_path: Path to the input ODS file with per-technology tabs.
        output_dir: Folder where the Security ODS will be written. If None, uses CWD.

    Returns:
        A subprocess-like adapter object with wait(), returncode, pid, is_alive().
    """
    out_dir = Path(output_dir) if output_dir else Path.cwd()
    p = mp.Process(
        target=_security_entry,
        args=(str(ods_path), str(out_dir), float(retransmit_window_seconds or 0.0), tmsi_thresholds, profile_dict),
        daemon=False,
    )
    p.start()
    return _ProcAdapter(p)


def run_live_capture(
    live_ip: str,
    bus: str,
    port: str,
    scat_type: str,
    scat_iface: str,
    scat_model: Optional[str] = None,
    start_magic: Optional[str] = None,
    pcap_dir: Optional[str] = None,
    pcap_filename: Optional[str] = None,
) -> Path:
    """
    Execute a live capture using SCAT to generate a PCAP directly (-F).

    Launches SCAT in a child process, waits for it to finish, and validates
    that the output PCAP exists and is non-empty.

    Args:
        live_ip: Target IP for filter (currently unused in SCAT -F mode)
        bus: USB bus identifier
        port: USB device identifier
        scat_type: 'sec' (Samsung) or 'qc' (Qualcomm)
        scat_iface: SCAT interface number (e.g., '4')
        scat_model: Optional device model (Samsung)
        start_magic: Optional SCAT start magic value
        pcap_dir: Output directory for PCAP (default ./PCAPs)
        pcap_filename: Optional custom filename

    Returns:
        Path: Path to the generated PCAP.
    """
    # Prepare PCAP path; SCAT will write it directly (-F)
    out_dir = Path(pcap_dir) if pcap_dir else (Path.cwd() / "PCAPs")
    out_dir.mkdir(parents=True, exist_ok=True)
    if pcap_filename:
        pcap_path = out_dir / pcap_filename
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = out_dir / f"live_capture_{ts}.pcap"

    scat_proc = launch_scat(
        bus, port, scat_type, scat_iface, scat_model, start_magic, pcap_path=pcap_path
    )
    # Wait for the SCAT session to finish
    scat_proc.wait()
    try:
        logging.info("SCAT exited with code: %s", getattr(scat_proc, "returncode", None))
    except Exception:
        pass

    # Validate that the PCAP was created and is not empty
    try:
        # Wait briefly for file write/flush in case SCAT exits and the OS delays writing
        for _ in range(10):
            if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                break
            time.sleep(0.3)

        if not pcap_path.exists() or pcap_path.stat().st_size < 24:
            logging.error(
                "PCAP not found or empty: %s. Check permissions/access and whether any traffic was captured.",
                pcap_path,
            )
            # Exit with error so the GUI can report failure clearly
            sys.exit(1)
    except Exception as e:
        logging.error("Failed to verify PCAP: %s", e)
        sys.exit(1)
    return pcap_path


def run_dump_analysis(
    dump_files: Any,
    scat_type: str,
    scat_model: Optional[str] = None,
    pcap_dir: Optional[str] = None,
    pcap_filename: Optional[str] = None,
) -> Path:
    """
    Parse modem dump file(s) using embedded SCAT and write a PCAP, then exit.

    Returns:
        Path: Path to the generated PCAP file.
    """
    # Prepare PCAP output path using the non-blocking starter helper
    proc, pcap_path = start_dump_analyzer_nonblocking(
        scat_type=scat_type,
        dump_files=dump_files,
        scat_model=scat_model,
        pcap_dir=pcap_dir,
        pcap_filename=pcap_filename,
    )
    # Wait for SCAT to finish processing the dump
    proc.wait()
    try:
        logging.info("Dump analyzer exited with code: %s", getattr(proc, "returncode", None))
    except Exception:
        pass

    # Validate PCAP creation
    try:
        for _ in range(10):
            if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                break
            time.sleep(0.3)
        if not pcap_path.exists() or pcap_path.stat().st_size < 24:
            logging.error(
                "PCAP not found or empty: %s. Check if the dump file(s) are supported and accessible.",
                pcap_path,
            )
            sys.exit(1)
    except Exception as e:
        logging.error("Failed to verify PCAP from dump: %s", e)
        sys.exit(1)
    return pcap_path


def parse_tshark_lines(
    lines: List[str],
    total_fields: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Convert tab-separated tshark output lines into structured packet dicts.

    Each line corresponds to one packet. Field values are mapped to the
    names provided in total_fields (in the same order they were passed to tshark).

    Args:
        lines: Raw lines from tshark stdout (tab-separated values).
        total_fields: Names of fields extracted with '-e'; determines mapping.

    Returns:
        List[Dict[str, Any]]: List of packets as dicts with a 'fields' mapping.
    """
    packets = []
    for line in lines:
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        if total_fields is not None:
            cols += [""] * (len(total_fields) - len(cols))
            pkt = {
                "fields": dict(zip(total_fields, cols)),
            }
        packets.append(pkt)
    return packets


def choose_final_values_generic(
    packets: List[Dict[str, Any]], mapping: Dict[str, str]
) -> Dict[str, Dict[str, Any]]:
    """
    Select a final value for each field in `mapping` to display in the spreadsheet.

    Selection rules:
    - If packets with EMM type 0x41 (Attach Accept) exist, prioritize those values.
    - Otherwise, use the latest value observed (by frame number).
    - Supports comma-separated multi-values within a single field.

    Args:
        packets: List of processed packets from parse_tshark_lines().
        mapping: Logical field name -> tshark field name.

    Returns:
        Dict[str, Dict[str, Any]]: For each field:
            - 'chosen_value': selected value (str)
            - 'packets_different': set of frame numbers with differing values
    """
    result = {}
    for name, tshark_field in mapping.items():
        values = []
        packets_different = set()
        all_values: List[str] = []
        for pkt in packets:
            val = pkt["fields"].get(tshark_field)
            if val not in (None, ""):
                # Handle comma-separated multi-values in a single field (e.g., "0,0")
                for v in str(val).split(","):
                    v = v.strip()
                    if v != "":
                        values.append(v)
                        packets_different.add(pkt["fields"].get("frame.number", "?"))
                        if v not in all_values:
                            all_values.append(v)
        if values:
            # Find the last value based on frame ordering
            last_value = None
            last_frame = -1
            for pkt in packets:
                frame_str = pkt["fields"].get("frame.number", "")
                try:
                    frame = int(frame_str)
                except Exception:
                    continue
                val = pkt["fields"].get(tshark_field)
                if val not in (None, ""):
                    for v in str(val).split(","):
                        v = v.strip()
                        if v != "":
                            if frame > last_frame:
                                last_value = v
                                last_frame = frame
            chosen_value = last_value if last_value is not None else values[-1]
            diffs = set()
            for pkt in packets:
                val = pkt["fields"].get(tshark_field)
                if val not in (None, ""):
                    for v in str(val).split(","):
                        v = v.strip()
                        if v != "" and v != chosen_value:
                            diffs.add(pkt["fields"].get("frame.number", "?"))
        else:
            chosen_value = ""
            diffs = set()
            all_values = []
        result[name] = {
            "chosen_value": chosen_value,
            "packets_different": diffs,
            "all_values": all_values,
        }
    return result


def get_best_mcc_mnc_from_results(*sources: Dict[str, List[Dict[str, Any]]], n_priority: int = 8) -> Tuple[str, str]:
    """Select the best MCC/MNC pair from any number of extraction result dicts.

    Uses a two-tier strategy:
    1. High-priority sources (first ``n_priority`` args, default 8 = 5G+4G enc/int):
       if they yield any MCC or MNC, their result is returned immediately.
    2. Fallback: count across all remaining sources.

    Within each tier, the most-frequent value wins; ties are broken by first-seen order.

    Args:
        *sources: Result dicts keyed by algorithm name or frame number; each
                  value is a list of record dicts that may contain "MCC"/"MNC".
        n_priority: Number of leading sources treated as high-priority tier.

    Returns:
        Tuple[str, str]: The (MCC, MNC) selected as best estimates.
    """

    def _normalize(v: Any) -> str:
        s = str(v).strip()
        if s.isdigit():
            s = s.lstrip("0") or "0"
        return s

    def _pick_best(counts: Dict[str, int], first_seen: Dict[str, int]) -> str:
        if not counts:
            return ""
        max_count = max(counts.values())
        candidates = [v for v, c in counts.items() if c == max_count]
        if len(candidates) == 1:
            return candidates[0]
        return min(candidates, key=lambda v: first_seen.get(v, float("inf")))

    def _extract(srcs) -> Tuple[str, str]:
        mcc_counts: Dict[str, int] = {}
        mnc_counts: Dict[str, int] = {}
        mcc_first_seen: Dict[str, int] = {}
        mnc_first_seen: Dict[str, int] = {}
        order_idx = 0
        for src in srcs:
            for alg in src.values():
                for entry in alg:
                    mcc_v = entry.get("MCC")
                    if mcc_v not in (None, ""):
                        mcc_s = _normalize(mcc_v)
                        mcc_counts[mcc_s] = mcc_counts.get(mcc_s, 0) + 1
                        if mcc_s not in mcc_first_seen:
                            mcc_first_seen[mcc_s] = order_idx
                    mnc_v = entry.get("MNC")
                    if mnc_v not in (None, ""):
                        mnc_s = _normalize(mnc_v)
                        mnc_counts[mnc_s] = mnc_counts.get(mnc_s, 0) + 1
                        if mnc_s not in mnc_first_seen:
                            mnc_first_seen[mnc_s] = order_idx
                    order_idx += 1
        return _pick_best(mcc_counts, mcc_first_seen), _pick_best(mnc_counts, mnc_first_seen)

    mcc, mnc = _extract(sources[:n_priority])
    if mcc or mnc:
        return mcc, mnc
    return _extract(sources[n_priority:])


def lookup_operator(
    mcc: str,
    mnc: str,
    csv_filename: str = "mcc-mnc.csv"
) -> Tuple[str, str]:
    """
    Map an MCC/MNC pair to Country and Operator using a CSV database.

    Expected CSV columns:
        - col 0: MCC (Mobile Country Code)
        - col 1: MNC (Mobile Network Code)
        - col 4: Country name
        - col 7: Operator name

    Rules:
    - Remove leading zeros from MCC/MNC before comparing.
    - Auto-detect CSV delimiter ("," or ";").
    - Ignore rows with fewer than 8 columns.

    Args:
        mcc: Mobile Country Code
        mnc: Mobile Network Code
        csv_filename: CSV filename (default: "mcc-mnc.csv").

    Returns:
        Tuple[str, str]: (country, operator) if found; otherwise ('', '').
    """
    mcc_n, mnc_n = mcc.lstrip("0"), mnc.lstrip("0")
    candidates: List[Path] = []
    # Preferred system location
    candidates.append(Path("/usr/local/etc/ranvds") / csv_filename)
    # Environment override
    try:
        data_dir = os.environ.get("RANVDS_DATA_DIR")
        if data_dir:
            candidates.append(Path(data_dir) / csv_filename)
    except Exception:
        pass
    # Current working directory
    candidates.append(Path.cwd() / csv_filename)
    # Module directory
    try:
        candidates.append(Path(__file__).resolve().parent / csv_filename)
    except Exception:
        pass
    # argv[0] directory
    try:
        argv0_dir = Path(sys.argv[0]).resolve().parent
        candidates.append(argv0_dir / csv_filename)
    except Exception:
        pass
    # De-duplicate while preserving order
    _seen: set[Path] = set()
    _dedup: List[Path] = []
    for p in candidates:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        if rp in _seen:
            continue
        _seen.add(rp)
        _dedup.append(p)
    candidates = _dedup

    for path in candidates:
        try:
            with path.open(newline="", encoding="utf-8") as f:
                sample = f.read(2048)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.reader(f, dialect)
                for row in reader:
                    if len(row) < 8:
                        continue
                    row0 = row[0].strip().lstrip("0")
                    row1 = row[1].strip().lstrip("0")
                    if not (row0.isdigit() and row1.isdigit()):
                        continue
                    if row0 == mcc_n and row1 == mnc_n:
                        country = row[4].strip()
                        operator = row[7].strip()
                        logging.info("MCC/MNC CSV matched at: %s", path)
                        return country, operator
        except FileNotFoundError:
            continue
        except csv.Error as e:
            logging.error("CSV error (%s): %s", path, e)
        except Exception as e:
            logging.error("Unexpected error reading %s: %s", path, e)

    logging.error("MCC/MNC CSV not found at: %s", ", ".join(str(p) for p in candidates))
    return "", ""


# ---------------------------------------------------------------------
# 3) Main workflow
# ---------------------------------------------------------------------

def main() -> None:
    """
    Coordinate the end-to-end workflow.

    Steps:
    1) Parse CLI arguments (mutually exclusive modes)
    2) Load configuration files (fields.cfg, translations.cfg)
    3) Branch by mode:
       - Security (-s): generate Security ODS from an existing ODS
       - Dump (-d): parse modem dump(s) to PCAP only
       - Live (-l): capture to PCAP only using embedded SCAT
       - PCAP (-p): analyze PCAP and generate comprehensive ODS
    4) In PCAP mode: run tshark, parse outputs, extract algorithms/IDs/paging,
       determine MCC/MNC and operator, then build the ODS report.
    """
    args: Any = get_arguments()
    translations_cfg_file: Path = Path("/usr/local/etc/ranvds/translations.cfg")
    TRANSLATIONS: configparser.ConfigParser = load_translations(translations_cfg_file)
    translations_dict: Dict[str, Any] = dict(TRANSLATIONS.items())
    fields_cfg_file: Path = Path("/usr/local/etc/ranvds/fields.cfg")
    (
        ALGORITHM_FIELDS,
        USED_ALGORITHM_FIELDS,
        GSM_FIELDS,
        UMTS_FIELDS,
        LTE_RRC_FIELDS,
        LTE_NAS_FIELDS,
        NR_RRC_FIELDS,
        NR_NAS_FIELDS,
        MISC_FIELDS,
        SIP_FIELDS,
    ) = load_fields(fields_cfg_file)
    ORDER: List[str] = list(ALGORITHM_FIELDS.keys())
    USED_ORDER: List[str] = list(USED_ALGORITHM_FIELDS.keys())
    TSHARK_FIELDS: List[str] = (
        list(ALGORITHM_FIELDS.values()) +
        list(USED_ALGORITHM_FIELDS.values()) +
        list(MISC_FIELDS.values()) +
        list(GSM_FIELDS.values()) +
        list(UMTS_FIELDS.values()) +
        list(LTE_RRC_FIELDS.values()) +
        list(LTE_NAS_FIELDS.values()) +
        list(NR_RRC_FIELDS.values()) +
        list(NR_NAS_FIELDS.values()) +
        list(SIP_FIELDS.values())
    )
    # Security-only mode (-s): read existing ODS and generate <stem>_Security.ods
    if getattr(args, "security", None):
        ods_in = Path(args.security)
        if not ods_in.exists():
            logging.error("ODS file not found: %s", ods_in)
            return
        logging.info("Reading ODS for security: %s", ods_in)
        sequences = extract_sequences_from_ods(ods_in, exclude_tabs=["UE Capability"])  # skip capability summary
        _sec_profile_json = getattr(args, "profile_json", None)
        _sec_profile = SelectionProfile.from_dict(_json.loads(_sec_profile_json)) if _sec_profile_json else SelectionProfile()
        sequences = _sec_profile.filter_sequences(sequences)
        _raw_ids = extract_ids_from_ods(ods_in) if _sec_profile.any_id_enabled() else []
        identities = _sec_profile.filter_identity_records(_raw_ids) if _raw_ids else None
        _raw_paging = extract_paging_from_ods(ods_in) if _sec_profile.any_paging_enabled() else {}
        paging_stats = _sec_profile.filter_paging_stats(_raw_paging) if _raw_paging else None
        suci_stats = extract_suci_stats_from_ods(ods_in) if _sec_profile.suci_5g else None
        vops_stats = extract_vops_from_ods(ods_in) if _sec_profile.any_vops_enabled() else None
        if vops_stats is not None and not _sec_profile.vops_4g:
            vops_stats.supported_4g = 0
            vops_stats.not_supported_4g = 0
            vops_stats.quintuplets = [q for q in vops_stats.quintuplets if q.generation != "4G"]
        if vops_stats is not None and not _sec_profile.vops_5g:
            vops_stats.supported_5g = 0
            vops_stats.not_supported_5g = 0
            vops_stats.quintuplets = [q for q in vops_stats.quintuplets if q.generation != "5G"]
        ue_cap_security_stats = None
        if _sec_profile.ue_cap_security_4g or _sec_profile.ue_cap_security_5g:
            ue_cap_security_stats = extract_ue_cap_security_from_ods(ods_in)
            if not _sec_profile.ue_cap_security_4g:
                ue_cap_security_stats.before_4g = 0
                ue_cap_security_stats.after_4g = 0
                ue_cap_security_stats.unknown_4g = 0
            if not _sec_profile.ue_cap_security_5g:
                ue_cap_security_stats.before_5g = 0
                ue_cap_security_stats.after_5g = 0
                ue_cap_security_stats.unknown_5g = 0
        # Prefix: use exactly the stem of the analyzed file
        prefix = ods_in.stem
        out_dir = Path(getattr(args, "security_outdir", "")) if getattr(args, "security_outdir", None) else ods_in.parent
        sip_ipsec_stats = extract_sip_ipsec_from_ods(ods_in) if _sec_profile.sip_ipsec else None
        out = write_crypto_checker_ods(out_dir, prefix, sequences, identities=identities or None, paging_stats=paging_stats or None, suci_stats=suci_stats, vops_stats=vops_stats, ue_cap_security_stats=ue_cap_security_stats, sip_ipsec_stats=sip_ipsec_stats)
        # Optional rename to custom filename
        desired_name = (getattr(args, "security_name", None) or "").strip()
        if desired_name:
            name = desired_name
            if not name.lower().endswith('.ods'):
                name += '.ods'
            dest = (out_dir / Path(name).name)
            try:
                if dest.resolve() != out.resolve():
                    base = dest.stem
                    ext = dest.suffix
                    parent = dest.parent
                    candidate = dest
                    i = 1
                    while candidate.exists():
                        candidate = parent / f"{base} ({i}){ext}"
                        i += 1
                    try:
                        out.rename(candidate)
                        out = candidate
                    except Exception as _e:
                        logging.warning("Failed to rename Security ODS to desired name; keeping default.")
            except Exception:
                pass
        logging.info("Security report generated: %s", out)
        return

    # Dump mode (-d): analyze modem dump(s) and generate only a PCAP
    if getattr(args, "dump", None):
        logging.info("Dump mode: files=%s", args.dump)
        pcap_path = run_dump_analysis(
            dump_files=args.dump,
            scat_type=getattr(args, "dump_type", "sec"),
            scat_model=getattr(args, "dump_model", None),
            pcap_dir=getattr(args, "dump_outdir", None),
            pcap_filename=getattr(args, "dump_pcap", None),
        )
        logging.info("Dump PCAP saved: %s", pcap_path)
        try:
            print(f"PCAP_CREATED {pcap_path}")
        except Exception:
            pass
        return

    if args.pcap:
        logging.info("PCAP mode: %s", args.pcap)
        pcap_path = Path(args.pcap)
        if not pcap_path.exists() or not pcap_path.is_file():
            logging.error("PCAP file not found: %s", pcap_path)
            sys.exit(1)
        # Ensure tshark is available before attempting to run it
        if shutil.which("tshark") is None:
            logging.error("'tshark' not found. Please install it (e.g., sudo apt-get install tshark) and try again.")
            sys.exit(1)
        cmd = prepare_tshark_cmd(pcap=args.pcap, total_fields=TSHARK_FIELDS)
        #try:
        #    logging.info("tshark cmd: %s", " ".join(cmd))
        #except Exception:
        #    pass
        try:
            # Capture raw bytes to avoid any implicit decoding errors; decode manually with replacement
            # Use user's normal Wireshark/tshark environment
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_txt = (result.stdout or b'').decode('utf-8', errors='replace')
            stderr_txt = (result.stderr or b'').decode('utf-8', errors='replace')
            if result.returncode != 0:
                logging.warning("tshark exited with code %s. stderr: %s", result.returncode, stderr_txt.strip())
            lines = stdout_txt.splitlines()
            if not lines:
                logging.error("No output from tshark. Ensure the PCAP is valid and fields configuration matches your tshark version.")
                sys.exit(1)
        except FileNotFoundError:
            logging.error("'tshark' executable not found in PATH. Install tshark and retry.")
            sys.exit(1)
        except Exception as e:
            logging.error("Failed to run tshark: %s", e)
            sys.exit(1)
    else:
        logging.info("Live mode: %s", args.live)
        # Resolve USB address (override > auto-detect)
        if getattr(args, "usb_addr", None):
            try:
                bus, port = args.usb_addr.split(":", 1)
                bus = bus.strip()
                port = port.strip()
                logging.info("USB forced: bus=%s port=%s", bus, port)
            except Exception:
                logging.error("Invalid format for --usb. Use BUS:DEVICE, e.g., 001:004")
                sys.exit(1)
        else:
            bus, port = detect_cell(args.scat_type)
            if not bus:
                sys.exit(1)
        pcap_path = run_live_capture(
            args.live,
            bus,
            port,
            args.scat_type,
            args.scat_iface,
            args.scat_model,
            args.start_magic,
            getattr(args, "live_outdir", None),
            getattr(args, "live_pcap", None),
        )
        logging.info("Live PCAP saved: %s", pcap_path)
        # Emit a simple marker for UIs to parse if needed
        try:
            print(f"PCAP_CREATED {pcap_path}")
        except Exception:
            pass
        return

    packets = parse_tshark_lines(lines, TSHARK_FIELDS)

    # Parse selection profile (controls which modules run)
    _profile_json = getattr(args, "profile_json", None)
    _pcap_profile = SelectionProfile.from_dict(_json.loads(_profile_json)) if _profile_json else SelectionProfile()
    _e = _defaultdict(list)  # empty placeholder for disabled modules

    # Summary of supported and used algorithms
    alg_res = choose_final_values_generic(packets, ALGORITHM_FIELDS)
    used_res = choose_final_values_generic(packets, USED_ALGORITHM_FIELDS)

    # Per-generation extractions
    # Encryption and integrity algorithms
    r2g_voz_enc = extract_2g_voice_enc_info(
        packets, USED_ALGORITHM_FIELDS, GSM_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.enc_2g_cs else _e
    r2g_dados_enc = extract_2g_data_enc_info(
        packets, USED_ALGORITHM_FIELDS, GSM_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.enc_2g_ps else _e
    _r3g_enc_raw, _r3g_int_raw = extract_3g_enc_info(
        packets, USED_ALGORITHM_FIELDS, UMTS_FIELDS, MISC_FIELDS
    ) if (_pcap_profile.enc_3g or _pcap_profile.int_3g) else (_e, _e)
    r3g_enc = _r3g_enc_raw if _pcap_profile.enc_3g else _e
    r3g_int = _r3g_int_raw if _pcap_profile.int_3g else _e
    _r4g_rrc_enc_raw, _r4g_rrc_int_raw = extract_4g_rrc_enc_info(
        packets, USED_ALGORITHM_FIELDS, LTE_RRC_FIELDS, MISC_FIELDS
    ) if (_pcap_profile.enc_4g_rrc or _pcap_profile.int_4g_rrc) else (_e, _e)
    r4g_rrc_enc = _r4g_rrc_enc_raw if _pcap_profile.enc_4g_rrc else _e
    r4g_rrc_int = _r4g_rrc_int_raw if _pcap_profile.int_4g_rrc else _e
    _r4g_nas_enc_raw, _r4g_nas_int_raw = extract_4g_nas_enc_info(
        packets, USED_ALGORITHM_FIELDS, LTE_NAS_FIELDS, MISC_FIELDS
    ) if (_pcap_profile.enc_4g_nas or _pcap_profile.int_4g_nas) else (_e, _e)
    r4g_nas_enc = _r4g_nas_enc_raw if _pcap_profile.enc_4g_nas else _e
    r4g_nas_int = _r4g_nas_int_raw if _pcap_profile.int_4g_nas else _e
    _r5g_rrc_enc_raw, _r5g_rrc_int_raw = extract_5g_rrc_enc_info(
        packets, USED_ALGORITHM_FIELDS, NR_RRC_FIELDS, MISC_FIELDS
    ) if (_pcap_profile.enc_5g_rrc or _pcap_profile.int_5g_rrc) else (_e, _e)
    r5g_rrc_enc = _r5g_rrc_enc_raw if _pcap_profile.enc_5g_rrc else _e
    r5g_rrc_int = _r5g_rrc_int_raw if _pcap_profile.int_5g_rrc else _e
    _r5g_nas_enc_raw, _r5g_nas_int_raw = extract_5g_nas_enc_info(
        packets, USED_ALGORITHM_FIELDS, NR_NAS_FIELDS, MISC_FIELDS
    ) if (_pcap_profile.enc_5g_nas or _pcap_profile.int_5g_nas) else (_e, _e)
    r5g_nas_enc = _r5g_nas_enc_raw if _pcap_profile.enc_5g_nas else _e
    r5g_nas_int = _r5g_nas_int_raw if _pcap_profile.int_5g_nas else _e

    # User identifiers
    r2g_voz_id = extract_2g_voice_id(
        packets, GSM_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_2g_voice else _e
    r2g_dados_id = extract_2g_data_id(
        packets, GSM_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_2g_data else _e
    r3g_rrc_id = extract_3g_rrc_id(
        packets, UMTS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_3g_rrc else _e
    r3g_nas_id = extract_3g_nas_id(
        packets, UMTS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_3g_nas else _e
    r4g_rrc_id = extract_4g_rrc_id(
        packets, LTE_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_4g_rrc else _e
    r4g_nas_id = extract_4g_nas_id(
        packets, LTE_NAS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_4g_nas else _e
    r5g_rrc_id = extract_5g_rrc_id(
        packets, NR_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_5g_rrc else _e
    r5g_nas_id = extract_5g_nas_id(
        packets, NR_NAS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.id_5g_nas else _e

    # Paging identifiers
    r2g_paging = extract_2g_paging(
        packets, GSM_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.paging_2g else _e
    r3g_paging = extract_3g_paging(
        packets, UMTS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.paging_3g else _e
    r4g_paging = extract_4g_paging(
        packets, LTE_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.paging_4g else _e
    r5g_paging = extract_5g_paging(
        packets, NR_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.paging_5g else _e

    # SUCI Schema
    r5g_sucischema = extract_5g_nas_suci(
        packets, NR_NAS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.suci_5g else _e

    # VoPS
    r4g_vops = extract_4g_nas_vops(
        packets, LTE_NAS_FIELDS, LTE_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.vops_4g else _e
    r5g_vops = extract_5g_nas_vops(
        packets, NR_NAS_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.vops_5g else _e

    # SIP
    r_sip = extract_sip_packets(
        packets, SIP_FIELDS, MISC_FIELDS
    ) if _pcap_profile.sip_ipsec else _e

    # UE Capability Security check
    r4g_ue_cap_sec = extract_4g_ue_cap_security_msgs(
        packets, LTE_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.ue_cap_security_4g else []
    r5g_ue_cap_sec = extract_5g_ue_cap_security_msgs(
        packets, NR_RRC_FIELDS, MISC_FIELDS, TRANSLATIONS
    ) if _pcap_profile.ue_cap_security_5g else []

    # Network identifiers
    mcc, mnc = get_best_mcc_mnc_from_results(
        r5g_nas_enc, r5g_nas_int, r5g_rrc_enc, r5g_rrc_int,
        r4g_nas_enc, r4g_nas_int, r4g_rrc_enc, r4g_rrc_int,
        r3g_enc, r3g_int,
        r2g_voz_enc, r2g_dados_enc,
        r5g_vops, r4g_vops,
        r5g_nas_id, r4g_nas_id,
        r5g_sucischema,
        r3g_nas_id, r3g_rrc_id,
        r2g_voz_id, r2g_dados_id,
        r2g_paging, r3g_paging, r4g_paging, r5g_paging,
        r5g_rrc_id, r4g_rrc_id,
    )
    country, operator = lookup_operator(mcc, mnc)

    if not operator:
        operator = "Unknown_Operator"
        logging.warning("Operator not identified for MCC/MNC: %s/%s", mcc, mnc)

    if args.output == "algorithms_table.ods":
        base = f"{datetime.datetime.now():%Y%m%d_%H%M%S}_{''.join(c for c in operator if c.isalnum())}"
        out_fn = Path.cwd() / f"{base}.ods"
        idx = 1
        while out_fn.exists():
            out_fn = Path.cwd() / f"{base}_{idx}.ods"
            idx += 1
    else:
        out_fn = Path(args.output)
        if not out_fn.is_absolute():
            out_fn = Path.cwd() / out_fn

    build_ods_table(
        alg_res=alg_res,
        used_res=used_res,
        order=ORDER,
        used_order=USED_ORDER,
        resultados_2g_voz_enc=r2g_voz_enc,
        resultados_2g_dados_enc=r2g_dados_enc,
        resultados_3g_enc=r3g_enc,
        resultados_3g_int=r3g_int,
        resultados_4g_rrc_enc=r4g_rrc_enc,
        resultados_4g_rrc_int=r4g_rrc_int,
        resultados_4g_nas_enc=r4g_nas_enc,
        resultados_4g_nas_int=r4g_nas_int,
        resultados_5g_rrc_enc=r5g_rrc_enc,
        resultados_5g_rrc_int=r5g_rrc_int,
        resultados_5g_nas_enc=r5g_nas_enc,
        resultados_5g_nas_int=r5g_nas_int,
        resultados_2g_voz_id=r2g_voz_id,
        resultados_2g_dados_id=r2g_dados_id,
        resultados_3g_rrc_id=r3g_rrc_id,
        resultados_3g_nas_id=r3g_nas_id,
        resultados_4g_rrc_id=r4g_rrc_id,
        resultados_4g_nas_id=r4g_nas_id,
        resultados_5g_rrc_id=r5g_rrc_id,
        resultados_5g_nas_id=r5g_nas_id,
        resultados_2g_paging=r2g_paging,
        resultados_3g_paging=r3g_paging,
        resultados_4g_paging=r4g_paging,
        resultados_5g_paging=r5g_paging,
        resultados_5g_sucischema=r5g_sucischema,
        resultados_4g_vops=r4g_vops,
        resultados_5g_vops=r5g_vops,
        resultados_4g_ue_cap_security=r4g_ue_cap_sec,
        resultados_5g_ue_cap_security=r5g_ue_cap_sec,
        resultados_sip=r_sip,
        country=country,
        operator=operator,
        translations_cfg=translations_dict,
        out_fn=str(out_fn),
        include_ue_capability=_pcap_profile.ue_capability,
    )
    logging.info("ODS generated: %s", out_fn)

    # --- Rename the .pcap file if MCC/MNC were identified ---
    if not args.pcap:
        # The generated .pcap lives in PCAPs/live_capture_TIMESTAMP.pcap.
        # The .ods name is in out_fn.
        # Only rename when MCC and MNC are not empty.
        if mcc and mnc:
            # Find the most recent .pcap under PCAPs.
            pcap_dir = Path.cwd() / "PCAPs"
            pcap_files = sorted(
                pcap_dir.glob("live_capture_*.pcap"),
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )
            if pcap_files:
                latest_pcap = pcap_files[0]
                new_pcap_name = Path(out_fn).with_suffix('.pcap').name
                new_pcap_path = pcap_dir / new_pcap_name
                try:
                    latest_pcap.rename(new_pcap_path)
                    logging.info(
                        f"PCAP file renamed to: {new_pcap_path}"
                    )
                except Exception as e:
                    logging.error(f"Error renaming PCAP: {e}")
            else:
                logging.warning("No .pcap file found to rename.")
        else:
            logging.info(
                "MCC/MNC not identified, keeping the original .pcap filename."
            )


if __name__ == "__main__":
    main()
