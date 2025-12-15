# Changelog

All notable changes to RANVDS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source release preparation
- Comprehensive documentation (README, CONTRIBUTING, API)
- requirements.txt for Python dependencies
- .gitignore for repository hygiene
- CHANGELOG.md for version tracking
- SECURITY.md for vulnerability reporting
- GitHub issue and PR templates
- CI/CD pipeline with GitHub Actions

### Changed
- N/A

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- N/A

## [1.0.0] - TBD

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
