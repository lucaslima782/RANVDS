# Changelog

All notable changes to RANVDS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-06

### Added
- **5G SUCI extraction** — `extract_5g_nas_suci` now extracts SUCI-related information from 5G NAS Registration messages, including scheme type and MCC/MNC fallbacks.
- **4G VoPS extraction** — `extract_4g_nas_vops` parses IMS VoPS support from LTE NAS Attach Accept messages.
- **5G VoPS extraction** — `extract_5g_nas_vops` parses VoPS 3GPP support from NR NAS Registration Accept messages.
- **4G UE Capability security extraction** — `extract_4g_ue_cap_security_msgs` collects 4G UE Capability / Security Mode message ordering data.
- **5G UE Capability security extraction** — `extract_5g_ue_cap_security_msgs` collects 5G UE Capability / Security Mode message ordering data.
- **Selection profile support** — new `selection_profile.py` module introduces a `SelectionProfile` dataclass to enable/disable analysis modules across PCAP analysis and security evaluation.
- **`--profile-json` CLI argument** — PCAP (`-p`) and Security (`-s`) modes now accept a JSON-encoded `SelectionProfile` to control which modules run.
- **VoPS security evaluation** — security processing now computes VoPS statistics and evaluates per-quintuplet `(Generation, MCC, MNC, TAC, PCI, ARFCN)` status.
- **SUCI security statistics** — security processing now counts completed 5G registrations and summarizes SUCI ID/scheme usage.
- **UE Capability security statistics** — security processing now summarizes whether UE Capability messages appeared before or after security activation in 4G and 5G.
- **VoPS Stats security sheet** — Security ODS output now includes a `VoPS Stats` tab when VoPS data is available.
- **UE Cap Security Stats security sheet** — Security ODS output now includes a `UE Cap Security Stats` tab when UE capability ordering data is available.
- **4G UE Cap Security analysis sheet** — Network Analysis ODS can now include a `4G UE Cap Security` tab.
- **5G UE Cap Security analysis sheet** — Network Analysis ODS can now include a `5G UE Cap Security` tab.
- **Config mappings for new fields** — `config/fields.cfg` now includes mappings for `IMS_VOPS`, 5G SUCI MCC/MNC, 5G TAI MCC/MNC/TAC, and `VOPS_3GPP`.
- **LTE UL-DCCH translation mapping** — `config/translations.cfg` now includes `lte-rrc.c1_UL-DCCH`, enabling identification of `ueCapabilityInformation` and related messages.
- **Repository `.gitignore`** — a root `.gitignore` file was added.

### Changed
- **GUI layout redesigned** — `ranvds_gui.py` was reworked into a tabbed interface separating Live Capture, Modem Log, PCAP→ODS, and Security workflows.
- **GUI log widget changed** — the log area now uses a selectable `TextInput`, allowing copy/paste of logs.
- **Module selection integrated end-to-end** — both PCAP analysis and Security evaluation now filter outputs according to the selected profile instead of always running all modules.
- **Conditional ODS generation** — analysis sheets are now only created when the corresponding module is enabled and data exists, avoiding empty tabs for disabled/unused modules.
- **UE Capability sheet made optional** — the `UE Crypto Capabilities` summary sheet is now controlled by the selection profile.
- **Security pipeline expanded** — security report generation now accepts and propagates optional SUCI, VoPS, and UE capability security datasets.
- **MCC/MNC selection logic improved** — `get_best_mcc_mnc_from_results` now derives the best MCC/MNC pair across multiple extraction result sources.
- **README and CLI help updated** — documentation/help text was updated to describe v2.0.0 functionality, new modules, and new output tabs.

### Fixed
- **4G VoPS radio context enrichment** — 4G VoPS extraction now backtracks to the nearest preceding `RRCConnectionSetup` to populate PCI and ARFCN for VoPS records when possible.
- **Security/analysis consistency for disabled modules** — when a module is disabled through the selection profile, related sheets and summary counters are now suppressed instead of being emitted as empty or irrelevant output.

### Removed
- None.

---

## [1.0.0] - 2025

### Added
- 2G (GSM/GPRS/EDGE) security analysis
  - Weak cipher detection (A5/0, A5/1, A5/2, GEA0, GEA1, GEA2)
  - TMSI randomness testing (CS and PS domains)
  - Identity exposure tracking (IMSI, TMSI)
  - Paging analysis

- 3G (UMTS) security analysis
  - Weak cipher detection (UEA0, UIA0)
  - P-TMSI randomness testing
  - Identity exposure tracking (IMSI, TMSI, P-TMSI)
  - RRC and NAS layer analysis

- 4G (LTE) security analysis
  - Weak cipher detection (EEA0, EIA0)
  - GUTI/M-TMSI randomness testing
  - Identity exposure tracking (IMSI, GUTI, M-TMSI)
  - RRC and NAS layer analysis

- 5G (NR) security analysis
  - Weak cipher detection (NEA0, NIA0)
  - 5G-GUTI randomness testing
  - Identity exposure tracking (SUPI, SUCI, 5G-GUTI)
  - RRC and NAS layer analysis

- Statistical randomness testing
  - Reuse rate analysis
  - Shannon entropy calculation
  - Successive Hamming distance testing
  - Chi-square goodness-of-fit tests
  - Configurable thresholds

- Live capture support
  - Samsung Exynos chipsets (via SCAT)
  - Qualcomm chipsets (via SCAT)
  - Real-time PCAP generation

- Modem dump analysis
  - Parse Samsung modem dumps
  - Parse Qualcomm modem dumps
  - Convert to PCAP format

- Comprehensive reporting
  - ODS spreadsheet output
  - Multi-tab algorithm analysis
  - Security evaluation with pass/fail status
  - Network information (MCC/MNC to Country/Operator mapping)

- Multiple interfaces
  - Command-line interface (CLI)
  - Graphical user interface (GUI with Kivy)
  - Standalone binary distribution (Nuitka)

- Documentation
  - User guide (README.md)
  - API documentation (API.md)
  - Contributing guidelines (CONTRIBUTING.md)
  - Runtime requirements (RUNTIME_REQUIREMENTS.md)

### Technical Details
- Python 3.8+ support
- Type hints throughout codebase
- Modular architecture (pcap_analyzer, security_evaluator, table_builder)
- Embedded SCAT tool for modem log parsing
- tshark integration for PCAP dissection
- MCC/MNC database for operator identification

---

## Version History Notes

### Pre-Release Development
This tool was developed as part of a Master's thesis research project on cellular network security. The initial development focused on:
- Protocol analysis capabilities (2G-5G)
- Cryptographic vulnerability detection
- Privacy analysis through randomness testing
- Academic research validation

### Release Philosophy
- **Major versions (X.0.0):** Significant new features or breaking changes
- **Minor versions (1.X.0):** New features, backward compatible
- **Patch versions (1.0.X):** Bug fixes, security updates

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
