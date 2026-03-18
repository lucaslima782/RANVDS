# RANVDS - RAN Vulnerability Detection System

[![Version 2.0.0](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/lucaslima782/RANVDS/releases)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**RANVDS** (RAN Vulnerability Detection System) is a security analysis tool for cellular networks that identifies cryptographic weaknesses, identity exposure, paging leaks, VoPS support issues, SUCI-related privacy indicators, and capability-message ordering risks across 2G, 3G, 4G, and 5G mobile networks.

> 🎓 **Academic Research Project**  
> This tool was developed as part of a Master's thesis research project. RANVDS helps researchers, operators, and subscribers inspect the security posture of operational cellular networks through automated PCAP analysis, modem-dump parsing, and live capture workflows.

---

## ✨ Key Features

### 🔒 Cipher Security Analysis
- **Weak Cipher Detection** - Identifies use of deprecated or null algorithms:
  - 2G: A5/0, A5/1, A5/2, GEA0, GEA1, GEA2
  - 3G: UEA0, UIA0
  - 4G: EEA0, EIA0
  - 5G: NEA0, NIA0
- **Algorithm Usage Tracking** - Records negotiated encryption and integrity algorithms per generation and layer
- **Cryptographic Downgrade Visibility** - Highlights insecure or weak protection choices in the resulting reports

### 🎲 Privacy & Randomness Analysis
- **TMSI/GUTI Randomness Testing** - Statistical analysis of temporary identifier allocation:
  - Reuse rate analysis
  - Shannon entropy
  - Successive Hamming distance testing
  - Chi-square goodness-of-fit on nibble distributions
- **Configurable Thresholds** - Customizable pass/fail criteria for randomness metrics in the Security workflow

### 🆔 Identity Exposure Tracking
- **Multi-Generation ID Monitoring** - Tracks identity exposure across:
  - 2G: IMSI, TMSI (CS and PS domains)
  - 3G: IMSI, TMSI, P-TMSI (RRC and NAS layers)
  - 4G: IMSI, GUTI, M-TMSI (RRC and NAS layers)
  - 5G: 5G-GUTI, SUCI and related NAS/RRC identifiers
- **Paging Analysis** - Monitors paging messages for IMSI or temporary-ID exposure across 2G to 5G

### 📞 VoPS (Voice over Packet Switched) Analysis
- **4G IMS VoPS** - Extracts the LTE NAS Attach Accept IMS VoPS indicator
- **5G VoPS** - Extracts the NR NAS Registration Accept VoPS 3GPP indicator
- **Per-Quintuplet Security Evaluation** - Flags **Fail** for any `(MCC, MNC, TAC, PCI, ARFCN)` combination where VoPS is not supported

### 🪪 5G SUCI Analysis
- **SUCI Protection Scheme Extraction** - Parses 5G NAS registration signaling and reports the SUCI protection scheme used
- **Security Summary Integration** - Includes dedicated 5G SUCI statistics in the Security ODS

### 🧩 UE Capability Message Security
- **4G and 5G Capability Ordering Checks** - Tracks `UECapabilityInformation` relative to `SecurityModeComplete`
- **Dedicated Reporting** - Produces explicit UE capability security sheets in the Network Analysis ODS and summary statistics in the Security ODS

### 📡 Protocol Support
- **2G (GSM/GPRS/EDGE)** - Circuit-Switched (CS) and Packet-Switched (PS) domains
- **3G (UMTS)** - RRC and NAS layers, CS and PS domains
- **4G (LTE)** - RRC and NAS security contexts
- **5G (NR)** - RRC and NAS security contexts

### 📊 Comprehensive Reporting
- **ODS Spreadsheet Output** - Detailed multi-tab reports covering:
  - Encryption and integrity algorithm observations
  - Identity messages with timestamps
  - Paging summaries
  - 5G SUCI observations
  - 4G/5G VoPS observations
  - UE capability message security checks
  - Security evaluation with pass/fail indicators
  - Randomness analysis with statistical metrics
- **Conditional Tab Creation** - Tabs are generated only when the corresponding module is enabled and data exists
- **Network Information Mapping** - Automatic MCC/MNC to country and operator mapping

### 🖥️ Multiple Interfaces
- **Command-Line Interface** - Scriptable batch processing
- **Graphical User Interface** - Kivy-based desktop application with four tabs: **Live Capture**, **Modem Log**, **PCAP→ODS**, and **Security**
- **Standalone Binary** - Nuitka-compiled executable for Linux deployments
- **Selectable Analysis Modules** - Per-generation toggles via GUI dialogs or `--profile-json`
- **Copyable Execution Log** - GUI log area uses a selectable text widget for copy/paste

### 📱 Live Capture Support
- **Real-Time Analysis Pipeline** - Direct modem integration via SCAT
- **Hardware Support**:
  - Samsung Exynos chipsets (via SCAT `-t sec`)
  - Qualcomm chipsets (via SCAT `-t qc`)
- **Modem Dump Parsing** - Converts existing modem dumps to PCAP for later analysis

---

## 🚀 Quick Start

### Prerequisites

**System Requirements:**
- Linux (Debian/Ubuntu/Fedora tested)
- Python 3.8+ (for source installation)
- Wireshark/tshark (for PCAP dissection)

**For Live Capture:**
- USB-connected Samsung or Qualcomm device
- USB access permissions (see [Runtime Requirements](RUNTIME_REQUIREMENTS.md))

### Installation Options

#### Option 1: Binary Distribution

1. **Download the latest release:**
   ```bash
   wget https://github.com/lucaslima782/RANVDS/releases/latest/download/ranvds
   chmod +x ranvds
   ```

2. **Install system dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y wireshark-common tshark usbutils libusb-1.0-0      libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libgl1

   # Fedora/RHEL
   sudo dnf install -y wireshark-cli usbutils libusbx      SDL2 SDL2_image SDL2_ttf mesa-libGL
   ```

3. **Install configuration files:**
   ```bash
   sudo install -d /usr/local/etc/ranvds
   sudo install -m 0644 config/fields.cfg config/translations.cfg config/mcc-mnc.csv /usr/local/etc/ranvds/
   ```

4. **Run:**
   ```bash
   ./ranvds --help
   ```

#### Option 2: From Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/lucaslima782/RANVDS.git
   cd RANVDS
   ```

2. **Install system dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y wireshark-common tshark usbutils libusb-1.0-0      libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libgl1

   # Fedora/RHEL
   sudo dnf install -y wireshark-cli usbutils libusbx      SDL2 SDL2_image SDL2_ttf mesa-libGL
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt

   # Optional: development tooling
   pip install -r requirements-dev.txt
   ```

   **Required Python packages:**
   - `odfpy` - ODS file handling
   - `scipy` - Statistical tests used by the Security evaluator
   - `kivy` - GUI framework
   - `kivy-garden` - GUI support components
   - `libscrc` - Optional, for faster CRC calculations in SCAT-related workflows

4. **Verify installation:**
   ```bash
   python3 -c "import pcap_analyzer, security_evaluator, table_builder, selection_profile"
   python3 ranvds.py --help
   ```

5. **Run RANVDS:**
   ```bash
   # CLI mode
   python3 ranvds.py --help

   # GUI mode
   python3 ranvds_gui.py
   ```

### Basic Usage Examples

#### 1. Analyze a PCAP File
```bash
python3 ranvds.py -p capture.pcap -o network_analysis.ods
```

#### 2. Generate a Security Report from an Existing ODS
```bash
python3 ranvds.py -s network_analysis.ods
```

#### 3. Run PCAP Analysis with a Custom Selection Profile
```bash
python3 ranvds.py -p capture.pcap -o filtered.ods   --profile-json '{"enc_2g_cs": true, "enc_2g_ps": false, "vops_4g": true, "vops_5g": true, "ue_capability": true}'
```

#### 4. Live Capture (Samsung Device)
```bash
python3 ranvds.py -l -t sec -i 4 --live-outdir ./captures
```

#### 5. Analyze Modem Dump Files
```bash
python3 ranvds.py -d dump1.bin dump2.bin --dump-type sec --dump-outdir ./pcaps
python3 ranvds.py -p ./pcaps/output.pcap -o analysis.ods
```

#### 6. GUI Mode
```bash
python3 ranvds_gui.py
```

---

## 📖 Documentation

### Command-Line Reference

```text
usage: ranvds.py [-h] (-p PCAP | -l [LIVE] | -d DUMP [DUMP ...] | -s SECURITY)
                 [--profile-json PROFILE_JSON] [-t {sec,qc}] [-m SCAT_MODEL]
                 [-i SCAT_IFACE] [-a USB_ADDR] [--start-magic START_MAGIC]
                 [--live-outdir LIVE_OUTDIR] [--live-pcap LIVE_PCAP]
                 [--dump-type {sec,qc}] [--dump-model DUMP_MODEL]
                 [--dump-outdir DUMP_OUTDIR] [--dump-pcap DUMP_PCAP]
                 [--security-outdir SECURITY_OUTDIR]
                 [--security-name SECURITY_NAME] [-o OUTPUT]

RANVDS v2.0.0 — RAN Vulnerability Detection System. Analyzes cellular traffic
(2G–5G) for security vulnerabilities: weak cipher detection, TMSI/GUTI
randomness, IMSI exposure, paging leaks, IMS VoPS support (4G/5G), and 5G SUCI
analysis. Four modes: PCAP analysis (generates multi-tab ODS), live capture
(SCAT→PCAP), modem dump (SCAT→PCAP), or security evaluation (ODS→Security ODS)

options:
  -h, --help            show this help message and exit
  -p, --pcap PCAP       Path to the PCAP file to analyze and generate an ODS
  -l, --live [LIVE]     Live capture via SCAT; generates a PCAP and exits (no
                        ODS). The optional IP parameter is currently ignored.
  -d, --dump DUMP [DUMP ...]
                        Parse modem dump file(s) via SCAT and write a PCAP,
                        then exit (no ODS).
  -s, --security SECURITY
                        Generate a security report from an existing ODS.
                        Evaluates cipher strength, TMSI randomness, IMSI paging
                        exposure, 5G SUCI, and VoPS support per quintuplet
                        MCC/MNC/TAC/PCI/ARFCN.
  --profile-json PROFILE_JSON
                        JSON-encoded SelectionProfile dict to control which
                        analysis modules run. Includes encryption, integrity,
                        identity, paging, SUCI, VoPS, UE capability summary,
                        and 4G/5G capability-message security checks.
  -t {sec,qc}           Chipset type for SCAT live capture: 'sec' (Samsung) or
                        'qc' (Qualcomm)
  -m SCAT_MODEL         Model for SCAT live capture (optional)
  -i SCAT_IFACE         Interface for SCAT live capture
  -a, --usb USB_ADDR    Force USB address in BUS:DEVICE format
  --start-magic START_MAGIC
                        Start magic for SCAT (optional)
  --live-outdir LIVE_OUTDIR
                        Output folder for live capture PCAPs
  --live-pcap LIVE_PCAP
                        Output PCAP filename for live mode (optional)
  --dump-type {sec,qc}  Chipset type for dump parsing
  --dump-model DUMP_MODEL
                        Samsung dump model (optional)
  --dump-outdir DUMP_OUTDIR
                        Output folder for dump-generated PCAPs
  --dump-pcap DUMP_PCAP
                        Output PCAP filename for dump mode (optional)
  --security-outdir SECURITY_OUTDIR
                        Output folder for the Security ODS
  --security-name SECURITY_NAME
                        Custom filename for the Security ODS
  -o, --output OUTPUT   Output ODS filename for PCAP mode
```

### Selection Profile Keys

All profile keys default to `true`.

- **2G**: `enc_2g_cs`, `enc_2g_ps`, `id_2g_voice`, `id_2g_data`, `paging_2g`
- **3G**: `enc_3g`, `int_3g`, `id_3g_rrc`, `id_3g_nas`, `paging_3g`
- **4G**: `enc_4g_rrc`, `int_4g_rrc`, `enc_4g_nas`, `int_4g_nas`, `id_4g_rrc`, `id_4g_nas`, `paging_4g`, `vops_4g`, `ue_cap_security_4g`
- **5G**: `enc_5g_rrc`, `int_5g_rrc`, `enc_5g_nas`, `int_5g_nas`, `id_5g_rrc`, `id_5g_nas`, `paging_5g`, `suci_5g`, `vops_5g`, `ue_cap_security_5g`
- **General**: `ue_capability`

### Output Format

#### Network Analysis ODS (from `-p` mode)
Depending on the enabled modules and the available data, RANVDS can create the following sheets:

- **UE Crypto Capabilities**
- **2G CS**, **2G PS**
- **3G ENC**, **3G INT**
- **4G RRC ENC**, **4G RRC INT**, **4G NAS ENC**, **4G NAS INT**
- **5G RRC ENC**, **5G RRC INT**, **5G NAS ENC**, **5G NAS INT**
- **2G CS ID**, **2G PS ID**, **3G RRC ID**, **3G NAS ID**, **4G RRC ID**, **4G NAS ID**, **5G RRC ID**, **5G NAS ID**
- **2G Paging**, **3G Paging**, **4G Paging**, **5G Paging**
- **5G SUCI**
- **4G VoPS**, **5G VoPS**
- **4G UE Cap Security**, **5G UE Cap Security**

Disabled or empty modules do not generate sheets.

#### Security ODS (from `-s` mode)
The Security report can include:

- **Crypto Summary**
- **IDs Messages**
- **Randomness Summary**
- **Paging Summary**
- **5G SUCI Stats**
- **VoPS Stats**
- **UE Cap Security Stats**
- **Summary**

### Configuration Files

- **`config/fields.cfg`** - Defines tshark fields extracted from each protocol layer
- **`config/translations.cfg`** - Maps field values to human-readable names
- **`config/mcc-mnc.csv`** - Mobile Country Code / Mobile Network Code database

For the standalone binary, these files must be installed under `/usr/local/etc/ranvds/`.

---

## 🛠️ Advanced Usage

### Custom Security Thresholds

The GUI allows configuring randomness thresholds used by the Security evaluator:
- **Reuse Rate** - Maximum acceptable reuse rate (default: `0.01`)
- **Entropy Threshold** - Minimum normalized entropy (default: `0.99`)
- **Hamming Distance p-value** - Minimum p-value for the successive Hamming test (default: `0.01`)
- **Chi-square p-value** - Minimum p-value for the nibble distribution test (default: `0.01`)

### Building from Source

```bash
./scripts/build_nuitka.sh
```

Expected output:
```text
dist/nuitka/ranvds
```

### USB Device Detection

```bash
lsusb

# Example:
# Bus 001 Device 004: ID 04e8:xxxx Samsung Electronics Co., Ltd

python3 ranvds.py -l -t sec -a 001:004
```

---

## 🔬 Technical Details

### Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                         RANVDS                              │
├─────────────────────────────────────────────────────────────┤
│      CLI (ranvds.py)      │      GUI (ranvds_gui.py)        │
├─────────────────────────────────────────────────────────────┤
│                    Core Analysis Modules                    │
│  ┌──────────────────┐ ┌────────────────────┐ ┌────────────┐ │
│  │ pcap_analyzer.py │ │ security_evaluator │ │ table_buil │ │
│  │                  │ │ .py                │ │ der.py     │ │
│  └──────────────────┘ └────────────────────┘ └────────────┘ │
│  ┌────────────────────┐                                      │
│  │ selection_profile  │                                      │
│  │ .py                │                                      │
│  └────────────────────┘                                      │
├─────────────────────────────────────────────────────────────┤
│                    Data Acquisition                         │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │   tshark      │  │     SCAT      │  │  Config Files    │ │
│  │  (Wireshark)  │  │  (embedded)   │  │  config/*.cfg    │ │
│  └───────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Analysis Pipeline

1. **Packet Extraction** - `tshark` dissects the PCAP and extracts configured fields
2. **Protocol Parsing** - `pcap_analyzer.py` correlates messages across layers and generations
3. **Security Evaluation** - `security_evaluator.py` applies randomness tests and security rules
4. **Report Generation** - `table_builder.py` creates the final ODS outputs
5. **Module Gating** - `selection_profile.py` controls which extractors and evaluators run

### Statistical Methods

**Randomness Testing** employs multiple complementary tests:
- **Reuse Rate** - Detects duplicate identifiers
- **Shannon Entropy** - Measures information content (`H(X) = -Σ p(x) log₂ p(x)`)
- **Successive Hamming Distance** - Tests bit-level independence between consecutive IDs
- **Chi-Square Test** - Tests uniformity of nibble distribution

---

## 🤝 Contributing

Contributions are welcome.

### How to Contribute
- **Report Bugs** - Open an issue with clear reproduction steps
- **Suggest Features** - Describe the use case and expected behavior
- **Submit Pull Requests** - Follow the existing code style and project structure
- **Improve Documentation** - Help keep usage and architecture documentation aligned with the codebase

### Development Setup
```bash
git clone https://github.com/lucaslima782/RANVDS.git
cd RANVDS
pip install -r requirements.txt
pip install -r requirements-dev.txt
python3 ranvds.py --help
```

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

### What this means
- ✅ **Freedom to use** - Use RANVDS for any purpose
- ✅ **Freedom to study** - Access and modify the source code
- ✅ **Freedom to share** - Distribute copies to help others
- ✅ **Freedom to improve** - Distribute modified versions
- ⚠️ **Copyleft** - Derivative works must also be licensed under GPL v3
- ⚠️ **No Warranty** - Provided "as-is" without warranty of any kind

---

## 🎓 Academic Use & Citation

If you use RANVDS in your research, please cite:

```bibtex
@article{ranvds2026ojcoms,
  author = {da Rocha, Lucas L. and Carneiro, Vitor G. A. and Pinto, Ernesto L.},
  journal = {IEEE Open Journal of the Communications Society}, 
  title = {RANVDS: Client-Side Detection of Insecure RAN Configurations in Operational 2G–5G Networks}, 
  year = {2026},
  volume = {7},
  number = {},
  pages = {2504-2527},
  doi = {10.1109/OJCOMS.2026.3673071}
}
```
or
```bibtex
@mastersthesis{lima2025ranvds,
  author = {Lucas Lima da Rocha},
  title = {RANVDS: Uma Ferramenta para Detecção de Configurações Inseguras em Redes de Acesso à Telefonia Móvel},
  school = {Instituto Militar de Engenharia},
  year = {2025},
  type = {Master's Thesis},
  url = {https://github.com/lucaslima782/RANVDS}
}
```

---

## 🙏 Acknowledgments

- **SCAT (Signaling Collection and Analysis Tool)** - Embedded modem log parser
- **Wireshark/tshark** - Protocol dissection engine
- **Kivy** - Cross-platform GUI framework
- **odfpy** - ODS generation library
- **Nuitka** - Python-to-C++ compiler used for standalone builds
- **SciPy** - Statistical computing library used by the Security evaluator

---

## 📧 Contact & Support

- **Author:** Lucas Lima
- **GitHub:** [@lucaslima782](https://github.com/lucaslima782)
- **Repository:** [RANVDS](https://github.com/lucaslima782/RANVDS)
- **Issues:** [Report a bug or request a feature](https://github.com/lucaslima782/RANVDS/issues)

---

## 🔐 Security & Privacy Notice

**RANVDS processes sensitive cellular network data including:**
- International Mobile Subscriber Identity (IMSI)
- Temporary Mobile Subscriber Identity values (TMSI/GUTI and related variants)
- Network identifiers such as MCC/MNC, TAC, ARFCN, and PCI

**Important:**
- ⚠️ **Do not share PCAP files or ODS reports** containing real subscriber data
- ⚠️ **Anonymize data** before publishing, archiving, or sharing results
- ⚠️ **Comply with local regulations** regarding network monitoring and privacy
- ⚠️ **Use only on networks you own or are authorized to analyze**

RANVDS is intended for **security research, network testing, and educational purposes only**.

---

## 📚 Additional Resources

- [CHANGELOG.md](CHANGELOG.md) - Version history
- [RUNTIME_REQUIREMENTS.md](RUNTIME_REQUIREMENTS.md) - System dependencies for binary execution
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution workflow
- [SECURITY.md](SECURITY.md) - Vulnerability disclosure process
- [API.md](API.md) - Programmatic/API notes
- [config/](config/) - Field definitions and translations
- [scripts/](scripts/) - Build and packaging helpers
- [examples/](examples/) - Sample captures and sample results

---

**Version:** 2.0.0  
**Last Updated:** March 2026  
**Status:** Active Development 🚧
