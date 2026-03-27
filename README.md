# RANVDS - RAN Vulnerability Detection System

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**RANVDS** (RAN Vulnerability Detection System) is a comprehensive security analysis tool for cellular networks that identifies cryptographic vulnerabilities, weak cipher usage, identity exposure, and privacy leaks across 2G, 3G, 4G, and 5G mobile networks.

> 🎓 **Academic Research Project**  
> This tool was developed as part of a Master's thesis research project. RANVDS provides security researchers, network subscribers, and academics with insights into cellular network security posture through automated PCAP analysis and real-time monitoring.

---

## ✨ Key Features

### 🔒 Cipher Security Analysis
- **Weak Cipher Detection** - Identifies use of deprecated/weak algorithms:
  - 2G: A5/0, A5/1, A5/2, GEA0, GEA1, GEA2
  - 3G: UEA0, UIA0
  - 4G: EEA0, EIA0
  - 5G: NEA0, NIA0
- **Algorithm Change Tracking** - Monitors cipher transitions during sessions
- **Cryptographic Downgrade Detection** - Flags security downgrades

### 🎲 Privacy & Randomness Analysis
- **TMSI/GUTI Randomness Testing** - Statistical analysis of temporary identifier allocation:
  - Reuse rate analysis
  - Shannon entropy
  - Successive Hamming distance testing
  - Chi-square goodness-of-fit for nibbles tests
- **Configurable Thresholds** - Customizable pass/fail criteria for randomness metrics

### 🆔 Identity Exposure Tracking
- **Multi-Generation ID Monitoring** - Tracks identity exposure across:
  - 2G: IMSI, TMSI (CS and PS domains)
  - 3G: IMSI, TMSI, P-TMSI (RRC and NAS layers)
  - 4G: IMSI, GUTI, M-TMSI (RRC and NAS layers)
  - 5G: SUPI, SUCI, 5G-GUTI (RRC and NAS layers)
- **Paging Analysis** - Monitors paging messages for IMSI leaks

### 📡 Protocol Support
- **2G (GSM/GPRS/EDGE)** - Circuit-Switched (CS) and Packet-Switched (PS) domains
- **3G (UMTS)** - RRC and NAS layers, CS and PS domains
- **4G (LTE)** - RRC and NAS security contexts
- **5G (NR)** - RRC and NAS security contexts

### 📊 Comprehensive Reporting
- **ODS Spreadsheet Output** - Detailed multi-tab reports including:
  - Algorithm support matrices
  - Encryption/integrity algorithm usage
  - Identity messages with timestamps
  - Paging summaries
  - Security evaluation with pass/fail statussu
  - Randomness analysis with statistical metrics
- **Network Information** - Automatic MCC/MNC to Country/Operator mapping

### 🖥️ Multiple Interfaces
- **Command-Line Interface** - Scriptable batch processing
- **Graphical User Interface** - Kivy-based desktop application
- **Standalone Binary** - Nuitka-compiled executable (no Python required)

### 📱 Live Capture Support
- **Real-Time Analysis** - Direct modem integration via SCAT
- **Hardware Support**:
  - Samsung Exynos chipsets (via SCAT `-t sec`)
  - Qualcomm chipsets (via SCAT `-t qc`)
- **Modem Log Analysis** - Parse existing modem dumps

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

#### Option 1: Binary Distribution (Recommended)

1. **Download the latest release:**
   ```bash
   # Download from GitHub Releases (coming soon)
   wget https://github.com/lucaslima782/RANVDS/releases/latest/download/ranvds
   chmod +x ranvds
   ```

2. **Install system dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y wireshark-common tshark usbutils libusb-1.0-0 \
     libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libgl1

   # Fedora/RHEL
   sudo dnf install -y wireshark-cli usbutils libusbx \
     SDL2 SDL2_image SDL2_ttf mesa-libGL
   ```

3. **Install configuration files:**
   ```bash
   sudo install -d /usr/local/etc/ranvds
   sudo install -m 0644 fields.cfg translations.cfg mcc-mnc.csv /usr/local/etc/ranvds/
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
   sudo apt-get install -y wireshark-common tshark usbutils libusb-1.0-0 \
     libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libgl1

   # Fedora/RHEL
   sudo dnf install -y wireshark-cli usbutils libusbx \
     SDL2 SDL2_image SDL2_ttf mesa-libGL
   ```

3. **Install Python dependencies:**
   ```bash
   # Install core dependencies
   pip install -r requirements.txt
   
   # Optional: Install development tools
   pip install -r requirements-dev.txt
   ```
   
   **Required Python packages:**
   - `odfpy` - ODS file handling
   - `kivy` - GUI framework
   - `libscrc` - Optional, for faster CRC calculations

4. **Verify installation:**
   ```bash
   # Test imports
   python3 -c "import pcap_analyzer; import security_evaluator; import table_builder"
   
   # Check CLI works
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
# Generate algorithm analysis report
python3 ranvds.py -p capture.pcap -o network_analysis.ods

# Output: network_analysis.ods with algorithm support and usage data
```

#### 2. Generate Security Report
```bash
# Create comprehensive security evaluation from existing ODS
python3 ranvds.py -s network_analysis.ods

# Output: network_analysis_Security.ods with vulnerability assessment
```

#### 3. Live Capture (Samsung Device)
```bash
# Capture live traffic to PCAP (no ODS generation)
python3 ranvds.py -l -t sec -i 4 --live-outdir ./captures

# -l: live mode
# -t sec: Samsung chipset
# -i 4: interface number (use lsusb to identify)
```

#### 4. Analyze Modem Dump
```bash
# Parse Samsung modem dump file(s) to PCAP
python3 ranvds.py -d dump1.bin dump2.bin --dump-type sec --dump-outdir ./pcaps

# Then analyze the generated PCAP
python3 ranvds.py -p ./pcaps/output.pcap -o analysis.ods
```

#### 5. GUI Mode
```bash
# Launch graphical interface
python3 ranvds_gui.py
```

---

## 📖 Documentation

### Command-Line Reference

```
usage: ranvds.py [-h] (-p PCAP | -l [LIVE] | -d DUMP [DUMP ...] | -s SECURITY)
                 [-t {sec,qc}] [-m SCAT_MODEL] [-i SCAT_IFACE] [-a USB_ADDR]
                 [--start-magic START_MAGIC] [--live-outdir LIVE_OUTDIR]
                 [--live-pcap LIVE_PCAP] [--dump-type {sec,qc}]
                 [--dump-model DUMP_MODEL] [--dump-outdir DUMP_OUTDIR]
                 [--dump-pcap DUMP_PCAP] [--security-outdir SECURITY_OUTDIR]
                 [--security-name SECURITY_NAME] [-o OUTPUT]

Analyze cellular network traffic for security vulnerabilities

Modes (mutually exclusive):
  -p, --pcap PCAP          Analyze PCAP file and generate ODS report
  -l, --live [IP]          Live capture via SCAT (generates PCAP only)
  -d, --dump FILES         Parse modem dump(s) to PCAP
  -s, --security ODS       Generate security report from existing ODS

PCAP Analysis Options:
  -o, --output FILE        Output ODS filename (default: YYYYMMDD_HHMMSS_Operator.ods)

Live Capture Options:
  -t {sec,qc}              Chipset type: 'sec' (Samsung) or 'qc' (Qualcomm)
  -m MODEL                 Device model (e.g., e5123 for Samsung)
  -i INTERFACE             Interface number (default: 4)
  -a, --usb BUS:DEVICE     Force USB address (e.g., 001:004)
  --start-magic HEX        SCAT start magic (default: 0x34dc12fe)
  --live-outdir DIR        Output directory for PCAP (default: ./PCAPs)
  --live-pcap FILENAME     Custom PCAP filename

Dump Analysis Options:
  --dump-type {sec,qc}     Chipset type for dump parsing
  --dump-model MODEL       Device model (Samsung only)
  --dump-outdir DIR        Output directory for PCAP (default: ./PCAPs)
  --dump-pcap FILENAME     Custom PCAP filename

Security Report Options:
  --security-outdir DIR    Output directory (default: same as input ODS)
  --security-name FILE     Custom output filename (default: <input>_Security.ods)
```

### Output Format

#### Network Analysis ODS (from `-p` mode)
- **2G CS / 2G PS** - Algorithm support and usage for GSM/GPRS
- **3G ENC / 3G INT** - UMTS encryption and integrity algorithms
- **4G RRC ENC/INT** - LTE RRC layer security
- **4G NAS ENC/INT** - LTE NAS layer security
- **5G RRC ENC/INT** - NR RRC layer security
- **5G NAS ENC/INT** - NR NAS layer security
- **Network Info** - MCC/MNC, Country, Operator

#### Security ODS (from `-s` mode)
- **Crypto Summary** - Algorithm usage statistics and weak cipher detection
- **IDs Messages** - Identity exposure tracking with timestamps
- **Randomness Summary** - Statistical analysis of TMSI/GUTI allocation
- **Paging Summary** - Paging message counts by generation

### Configuration Files

**fields.cfg** - Defines tshark fields to extract for each protocol layer  
**translations.cfg** - Maps protocol values to human-readable names  
**mcc-mnc.csv** - Mobile Country Code / Mobile Network Code database

---

## 🛠️ Advanced Usage

### Custom Security Thresholds

The GUI allows configuring randomness test thresholds:
- **Reuse Rate** - Maximum acceptable reuse rate (default: 0.01)
- **Entropy Threshold** - Minimum normalized entropy (default: 0.99)
- **Hamming Distance p-value** - Minimum p-value for successive Hamming test (default: 0.01)
- **Chi-square p-value** - Minimum p-value for nibble distribution (default: 0.01)

### Building from Source

```bash
# Build standalone binary with Nuitka
./scripts/build_nuitka.sh

# Output: dist/nuitka/ranvds
```

### USB Device Detection

```bash
# List connected USB devices
lsusb

# Example output:
# Bus 001 Device 004: ID 04e8:xxxx Samsung Electronics Co., Ltd

# Use bus and device numbers with -a flag:
python3 ranvds.py -l -t sec -a 001:004
```

---

## 🔬 Technical Details

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         RANVDS                              │
├─────────────────────────────────────────────────────────────┤
│      CLI (ranvds.py)      │      GUI (ranvds_gui.py)        │
├─────────────────────────────────────────────────────────────┤
│                    Core Analysis Modules                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐    │
│  │ pcap_analyzer │  │ security_eva  │  │ table_builder │    │
│  │   .py         │  │  luator.py    │  │    .py        │    │
│  └───────────────┘  └───────────────┘  └───────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    Data Acquisition                         │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐    │
│  │   tshark      │  │     SCAT      │  │  Config Files │    │
│  │  (Wireshark)  │  │  (embedded)   │  │   (.cfg)      │    │
│  └───────────────┘  └───────────────┘  └───────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Analysis Pipeline

1. **Packet Extraction** - tshark dissects PCAP and extracts configured fields
2. **Protocol Parsing** - pcapanalyzer correlates messages across layers
3. **Security Analysis** - securityevaluator applies detection rules and statistics
4. **Report Generation** - tablebuilder creates structured ODS output

### Statistical Methods

**Randomness Testing** employs multiple complementary tests:
- **Reuse Rate** - Detects duplicate identifiers
- **Shannon Entropy** - Measures information content (H(X) = -Σ p(x) log₂ p(x))
- **Successive Hamming Distance** - Tests bit-level independence between consecutive IDs
- **Chi-Square Test** - Tests uniformity of nibble distribution (χ² goodness-of-fit)

---

## 🤝 Contributing

Contributions are welcome! This project is in active development as part of academic research.

### How to Contribute
- **Report Bugs** - Open an issue with detailed reproduction steps
- **Suggest Features** - Describe your use case and proposed solution
- **Submit Pull Requests** - Follow the existing code style
- **Improve Documentation** - Help make RANVDS more accessible

### Development Setup
```bash
git clone https://github.com/lucaslima782/RANVDS.git
cd RANVDS
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run from source
python3 ranvds.py --help
```

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

### What this means:
- ✅ **Freedom to use** - Use RANVDS for any purpose
- ✅ **Freedom to study** - Access and modify the source code
- ✅ **Freedom to share** - Distribute copies to help others
- ✅ **Freedom to improve** - Distribute modified versions
- ⚠️ **Copyleft** - Derivative works must also be licensed under GPL v3
- ⚠️ **No Warranty** - Provided "as-is" without warranty of any kind

This ensures RANVDS and its derivatives remain free and open-source software.

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

- **SCAT (Signaling Collection and Analysis Tool)** - Embedded modem log parser (https://github.com/fgsect/scat)
- **Wireshark/tshark** - Protocol dissection engine (https://www.wireshark.org/)
- **Kivy** - Cross-platform GUI framework (https://kivy.org/)
- **odfpy** - ODS file generation (https://github.com/odfpy/odfpy)
- **Nuitka** - Python to C++ compiler (https://nuitka.net/)
- **Scipy** - Scientific computing library (https://www.scipy.org/)

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
- Temporary Mobile Subscriber Identity (TMSI/GUTI)
- Network identifiers (MCC/MNC)

**Important:**
- ⚠️ **Do not share PCAP files or ODS reports** containing real subscriber data
- ⚠️ **Anonymize data** before publishing or sharing
- ⚠️ **Comply with local regulations** regarding network monitoring and data privacy
- ⚠️ **Use only on networks you own or have explicit permission to test**

RANVDS is intended for **security research, network testing, and educational purposes only**.

---

## 📚 Additional Resources

- [Runtime Requirements](RUNTIME_REQUIREMENTS.md) - System dependencies for binary distribution
- [Configuration Guide](config/) - Field definitions and translations
- [Build Scripts](scripts/) - Nuitka compilation and system installation

---

**Version:** Development (pre-release)  
**Last Updated:** November 2025  
**Status:** Active Development 🚧
