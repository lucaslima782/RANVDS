# RANVDS API Documentation

Comprehensive API reference for RANVDS modules. For architecture details, refer to the master's thesis.

## Module Overview

| Module | Purpose | Lines |
|--------|---------|-------|
| **pcap_analyzer** | Extract protocol data from packets | ~2,600 |
| **security_evaluator** | Security analysis & randomness testing | ~1,500 |
| **table_builder** | ODS report generation | ~1,000 |
| **ranvds** | CLI orchestration & workflow | ~1,350 |
| **ranvds_gui** | GUI orchestration & workflow | ~1,450 |
---

## pcap_analyzer

Extract and correlate cellular network protocol information from packet captures.

### Utility Functions

```python
def decimal_id_to_hex(
    id_str: str,
    prefix: bool = True,
    even_length: bool = True,
    min_nibbles: Optional[int] = None
) -> str
```
Convert identifier strings to normalized hexadecimal format.

### Encryption Extraction (2G-5G)

Extract algorithm usage from signaling messages:

```python
# 2G
extract_2g_voice_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]
extract_2g_data_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]

# 3G
extract_3g_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]

# 4G
extract_4g_rrc_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]
extract_4g_nas_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]

# 5G
extract_5g_rrc_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]
extract_5g_nas_enc_info(packets, fields, ...) -> Dict[str, List[Dict]]
```

**Returns:** Dictionary mapping algorithm names to usage records with timestamp, frame, LAC, CellID, MCC/MNC.

### Identity Extraction (2G-5G)

Extract mobile identifiers (IMSI, TMSI, GUTI):

```python
# 2G
extract_2g_voice_id(packets, fields, ...) -> List[Dict]
extract_2g_data_id(packets, fields, ...) -> List[Dict]

# 3G
extract_3g_rrc_id(packets, fields, ...) -> List[Dict]
extract_3g_nas_id(packets, fields, ...) -> List[Dict]

# 4G
extract_4g_rrc_id(packets, fields, ...) -> List[Dict]
extract_4g_nas_id(packets, fields, ...) -> List[Dict]

# 5G
extract_5g_rrc_id(packets, fields, ...) -> List[Dict]
extract_5g_nas_id(packets, fields, ...) -> List[Dict]
```

**Returns:** List of identity records with timestamp, message, ID type, ID value.

### Paging Extraction (2G-5G)

Extract paging messages for privacy analysis:

```python
extract_2g_paging(packets, fields, ...) -> List[Dict]
extract_3g_paging(packets, fields, ...) -> List[Dict]
extract_4g_paging(packets, fields, ...) -> List[Dict]
extract_5g_paging(packets, fields, ...) -> List[Dict]
```

---

## security_evaluator

Security analysis, weak cipher detection, and TMSI randomness testing.

### Constants

```python
WEAK_2G_VOICE = {"A5/0", "A5/1", "A5/2"}
WEAK_2G_DATA = {"GEA0", "GEA1", "GEA2"}
WEAK_3G = {"UEA0", "UIA0"}
WEAK_4G = {"EEA0", "EIA0"}
WEAK_5G = {"NEA0", "NIA0"}
```

### Data Classes

```python
@dataclass
class GenerationSummary:
    name: str
    changes: int
    counts: Dict[str, int]
    weak_in_use: bool = False

@dataclass
class IdentityRecord:
    sheet: str
    timestamp: str
    message: str
    id_type: str
    id_value: str
    domain: str = ""
```

### Core Functions

```python
def extract_sequences_from_ods(
    ods_path: Path,
    exclude_tabs: Optional[List[str]] = None
) -> Dict[str, List[str]]
```
Extract algorithm sequences from network ODS for security analysis.

```python
def extract_ids_from_ods(ods_path: Path) -> List[IdentityRecord]
```
Extract identity records from network ODS. Applies pairing logic for 2G CS and 3G NAS CS (Location Updating Request/Accept).

```python
def extract_paging_from_ods(ods_path: Path) -> Dict[str, Dict[str, int]]
```
Extract paging statistics: `{"2G": {"total_paging": 150, "imsi_ids": 45}, ...}`

```python
def write_crypto_checker_ods(
    input_ods_path: Path,
    output_ods_path: Path,
    ts_margin_seconds: float = 0.0,
    tmsi_thresholds: Optional[Dict[str, float]] = None
) -> Path
```
Generate comprehensive security ODS with:
- **Crypto Summary** - Algorithm usage, weak cipher detection
- **IDs Messages** - Identity exposure tracking
- **Randomness Summary** - TMSI/GUTI statistical analysis
- **Paging Summary** - Paging counts by generation

**Thresholds:**
```python
{
    "collision_max": 0.01,
    "h_norm_min": 0.99,
    "succ_hamm_p_min": 0.01,
    "chi2_p_min": 0.01
}
```

### Statistical Functions

```python
_shannon_entropy(counts: Dict) -> float
_miller_madow_correction(counts: Dict) -> float
_min_entropy(counts: Dict) -> float
_norm_entropy(h_bits: float, num_bins: int) -> float
_chi2_sf_wh(x: float, k: int) -> float
```

Implement randomness tests: Shannon entropy, Miller-Madow correction, min-entropy, chi-square.

---

## table_builder

ODS spreadsheet generation and value interpretation.

### Value Interpretation

```python
def interpret_value(name: str, raw: str) -> str
```
Convert algorithm support values: "True"/"False" → "YES"/"NO"/"NOT FOUND"

```python
def interpret_used_value(name: str, raw: str) -> str
```
Convert raw algorithm values to names:
- 2G CS: 0→A5/1, 1→A5/2, 2→A5/3, 3→A5/4
- 2G PS: 0→GEA0, 1→GEA1, 2→GEA2, 3→GEA3
- 3G C: 0→UEA0, 1→UEA1, 2→UEA2
- 3G I: 0→UIA1, 1→UIA2
- 4G/5G: Similar mappings for EEA/EIA/NEA/NIA

### Generation-Specific Interpreters

```python
interpret_2g_voz(algo: str) -> str
interpret_2g_dados(algo: str) -> str
interpret_3g_enc(algo: str) -> str
interpret_3g_int(algo: str) -> str
interpret_4g_rrc_enc(algo: str) -> str
interpret_4g_rrc_int(algo: str) -> str
interpret_4g_nas_enc(algo: str) -> str
interpret_4g_nas_int(algo: str) -> str
interpret_5g_rrc_enc(algo: str) -> str
interpret_5g_rrc_int(algo: str) -> str
interpret_5g_nas_enc(algo: str) -> str
interpret_5g_nas_int(algo: str) -> str
```

### Helper Functions

```python
get_interpret_func_for_tab(title: str) -> Callable
interpret_version(version: str) -> str
interpret_payload(payloadfield: str, payload: str, ...) -> str
interpret_subtype(version: str, payload: str, ...) -> str
interpret_domain(domain: str, ...) -> str
interpret_message(message_field: str, message: str, ...) -> str
```

### ODS Building

```python
def build_ods_table(
    output_path: Path,
    algorithm_fields: Dict,
    used_algorithm_fields: Dict,
    packets: List[Dict],
    # ... field mappings ...
    enc_2g_voice: Dict,
    enc_2g_data: Dict,
    # ... encryption data ...
    id_2g_voice: List[Dict],
    # ... identity data ...
    paging_2g: List[Dict],
    # ... paging data ...
) -> Path
```
Main function to generate network analysis ODS from all extracted data.

---

## ranvds (Main Module)

CLI orchestration and workflow management.

### Argument Parsing

```python
def get_arguments() -> argparse.Namespace
```
Parse CLI arguments for four modes:
- `-p/--pcap` - Analyze PCAP → ODS
- `-l/--live` - Live capture → PCAP
- `-d/--dump` - Modem dump → PCAP
- `-s/--security` - ODS → Security ODS

### Utility Functions

```python
def detect_cell(scat_type: str) -> Tuple[str, str]
```
Auto-detect USB device (Samsung/Qualcomm). Returns (bus, port).

```python
def load_fields(cfg_path: Path) -> Tuple[Dict, ...]
```
Load field mappings from fields.cfg (9 dictionaries).

```python
def load_translations(cfg_path: Path) -> configparser.ConfigParser
```
Load value translations from translations.cfg.

```python
def prepare_tshark_cmd(
    pcap: Optional[str],
    live_ip: Optional[str],
    total_fields: Optional[List[str]]
) -> List[str]
```
Build tshark command for packet extraction.

---

## Data Structures

### Packet Dictionary
```python
{
    "fields": {
        "frame.number": "1234",
        "frame.time": "2025-11-20 14:30:45.123",
        "gsm_a.lac": "0x1234",
        "gsm_a.imsi": "724050123456789",
        # ...
    }
}
```

### Algorithm Usage Record
```python
{
    "Timestamp": "2025-11-20 14:30:45.123",
    "Frame": "1234",
    "Algorithm": "A5/3",
    "Message": "Ciphering Mode Command",
    "LAC": "0x1234",
    "CellID": "0x5678",
    "MCC": "724",
    "MNC": "05"
}
```

### Identity Record
```python
{
    "Timestamp": "2025-11-20 14:30:45.123",
    "Frame": "1234",
    "Message": "Location Updating Request",
    "ID Type": "IMSI",
    "ID Value": "0x724050123456789",
    "Domain": "CS"
}
```

---

## Configuration Files

### fields.cfg
INI file defining tshark field names:
- `[AlgorithmFields]` - Algorithm support indicators
- `[UsedAlgorithmFields]` - Algorithm usage indicators
- `[2GFields]`, `[3GFields]`, `[4GRRCFields]`, etc.
- `[MISCFields]` - Timestamp, frame, ARFCN

### translations.cfg
INI file mapping protocol values to human-readable names.

### mcc-mnc.csv
Mobile Country Code / Mobile Network Code database for operator identification.

---

## Usage Examples

### Analyze PCAP Programmatically

```python
from pathlib import Path
from RANVDS import load_fields, load_translations, prepare_tshark_cmd
from pcapanalyzer import extract_2g_voice_enc_info
from tablebuilder import build_ods_table
import subprocess
import json

# Load configuration
fields = load_fields(Path("fields.cfg"))
translations = load_translations(Path("translations.cfg"))

# Extract packets with tshark
cmd = prepare_tshark_cmd(pcap="capture.pcap", total_fields=["frame.number", "gsm_a.lac"])
result = subprocess.run(cmd, capture_output=True, text=True)
packets = [{"fields": json.loads(line)} for line in result.stdout.splitlines()]

# Extract encryption info
enc_2g = extract_2g_voice_enc_info(packets, fields[1], fields[2], fields[8], translations)

# Generate ODS
build_ods_table(Path("output.ods"), *fields, packets, enc_2g, ...)
```

### Generate Security Report

```python
from pathlib import Path
from securityevaluator import write_crypto_checker_ods

write_crypto_checker_ods(
    input_ods_path=Path("network.ods"),
    output_ods_path=Path("security.ods"),
    tmsi_thresholds={
        "collision_max": 0.01,
        "h_norm_min": 0.99,
        "succ_hamm_p_min": 0.01,
        "chi2_p_min": 0.01
    }
)
```

### Custom Randomness Analysis

```python
from securityevaluator import extract_ids_from_ods, _shannon_entropy, _chi2_sf_wh
from collections import Counter

# Extract TMSIs
ids = extract_ids_from_ods(Path("network.ods"))
tmsis = [r.id_value for r in ids if r.id_type == "TMSI"]

# Calculate entropy
counts = Counter(tmsis)
entropy = _shannon_entropy(counts)
print(f"TMSI Entropy: {entropy:.2f} bits")

# Chi-square test on nibbles
nibbles = [c for tmsi in tmsis for c in tmsi.replace("0x", "")]
nibble_counts = Counter(nibbles)
observed = list(nibble_counts.values())
expected = sum(observed) / 16
chi2 = sum((o - expected)**2 / expected for o in observed)
p_value = _chi2_sf_wh(chi2, 15)
print(f"Chi-square p-value: {p_value:.4f}")
```

---

## Error Handling

All modules use Python's logging module:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Common exceptions:
- `FileNotFoundError` - Missing PCAP/ODS/config files
- `KeyError` - Missing expected fields in packets/ODS
- `ValueError` - Invalid algorithm values or malformed data
- `subprocess.CalledProcessError` - tshark/SCAT execution failures

---

## Type Hints

All public functions use type hints. Import from `typing`:

```python
from typing import List, Dict, Tuple, Optional, Any, Callable, Set, Iterable
```

---

## Testing

Currently no automated tests. Manual testing recommended:

```bash
# Test PCAP analysis
python3 ranvds.py -p test.pcap -o test.ods

# Test security report
python3 ranvds.py -s test.ods

# Verify ODS opens in LibreOffice
libreoffice test.ods
```

---

## Performance Notes

- **Large PCAPs** (>1GB): May require 10-30 minutes for tshark extraction
- **Memory Usage**: ~500MB-2GB depending on packet count
- **Optimization**: Use tshark filters to reduce packet count before analysis

---

## Further Reading

- **Master's Thesis** - Architecture and algorithm details
- **README.md** - User guide and installation
- **CONTRIBUTING.md** - Development guidelines
- **RUNTIME_REQUIREMENTS.md** - System dependencies

---

**Last Updated:** November 2025  
**Version:** Development (pre-release)
