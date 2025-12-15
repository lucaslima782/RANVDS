# Contributing to RANVDS

Thank you for your interest in contributing to RANVDS (RAN Vulnerability Detection System)! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Community](#community)

---

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

**Key Principles:**
- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility and apologize for mistakes

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Before submitting a bug report:
1. **Check existing issues** - Your bug may already be reported
2. **Use the latest version** - Verify the bug exists in the current release
3. **Collect information** - Gather logs, screenshots, and reproduction steps

**When reporting a bug, include:**
- **Clear title** - Describe the issue concisely
- **Environment details** - OS, Python version, installation method (binary/source)
- **Steps to reproduce** - Exact sequence to trigger the bug
- **Expected behavior** - What should happen
- **Actual behavior** - What actually happens
- **Logs/screenshots** - Any relevant output or error messages
- **PCAP details** (if applicable) - Network type (2G/3G/4G/5G), capture method

**Example:**
```markdown
**Title:** Security report generation fails on 5G-only PCAPs

**Environment:**
- OS: Ubuntu 22.04
- Python: 3.10.12
- Installation: Source (git main branch)

**Steps to reproduce:**
1. Capture 5G NR traffic with Samsung device
2. Generate ODS: `python3 ranvds.py -p 5g_capture.pcap -o output.ods`
3. Generate security report: `python3 ranvds.py -s output.ods`

**Expected:** Security ODS created successfully
**Actual:** KeyError: '5G RRC ENC' 

**Logs:**
[Paste error traceback here]
```

### 💡 Suggesting Features

Feature requests are welcome! Before suggesting:
1. **Check existing issues** - Feature may already be proposed
2. **Consider scope** - Does it align with RANVDS goals?
3. **Provide context** - Explain the use case and benefits

**When suggesting a feature, include:**
- **Problem statement** - What problem does this solve?
- **Proposed solution** - How should it work?
- **Alternatives considered** - Other approaches you've thought about
- **Use cases** - Who benefits and how?
- **Implementation hints** (optional) - Technical suggestions

### 📝 Improving Documentation

Documentation improvements are highly valued:
- Fix typos or unclear explanations
- Add examples or tutorials
- Improve code comments
- Translate documentation (currently English/Portuguese)
- Create diagrams or visualizations

### 🔧 Contributing Code

Code contributions should:
- Fix bugs or implement approved features
- Include tests (when testing framework is established)
- Follow coding standards (see below)
- Update documentation as needed

---

## Getting Started

### Prerequisites

**System Requirements:**
- Linux (Debian/Ubuntu/Fedora recommended)
- Python 3.8 or higher
- Git
- tshark (Wireshark CLI)

**For Live Capture Development:**
- USB-connected Samsung or Qualcomm device
- USB access permissions

### Setting Up Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/RANVDS.git
   cd RANVDS
   ```

3. **Add upstream remote:**
   ```bash
   git remote add upstream https://github.com/lucaslima782/RANVDS.git
   ```

4. **Install system dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -y wireshark-common tshark usbutils libusb-1.0-0 \
     libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libgl1

   # Fedora
   sudo dnf install -y wireshark-cli usbutils libusbx \
     SDL2 SDL2_image SDL2_ttf mesa-libGL
   ```

5. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

6. **Verify installation:**
   ```bash
   python3 ranvds.py --help
   ```

7. **Install development tools (optional):**
   ```bash
   pip install pylint black mypy
   ```

---

## Development Workflow

### Branching Strategy

- **main** - Stable release branch
- **develop** - Integration branch for features (if created)
- **feature/*** - New features
- **bugfix/*** - Bug fixes
- **docs/*** - Documentation updates

### Creating a Feature Branch

```bash
# Update your fork
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and commit
git add .
git commit -m "feat: add your feature description"

# Push to your fork
git push origin feature/your-feature-name
```

### Keeping Your Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge upstream main into your branch
git checkout main
git merge upstream/main

# Rebase your feature branch (if needed)
git checkout feature/your-feature-name
git rebase main
```

---

## Coding Standards

### Python Style Guide

RANVDS follows **PEP 8** with some project-specific conventions:

**General Rules:**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters (flexible for readability)
- Use descriptive variable names
- Prefer explicit over implicit

**Naming Conventions:**
```python
# Functions and variables: snake_case
def extract_encryption_info(packets: List[Dict]) -> Dict:
    algorithm_count = 0
    
# Classes: PascalCase
class SecurityAnalyzer:
    pass

# Constants: UPPER_SNAKE_CASE
WEAK_2G_CIPHERS = {"A5/0", "A5/1", "A5/2"}

# Private methods/variables: _leading_underscore
def _internal_helper():
    pass
```

**Type Hints:**
- Use type hints for function signatures
- Import from `typing` module
```python
from typing import List, Dict, Tuple, Optional, Any

def analyze_pcap(
    pcap_path: str,
    output_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """Analyze PCAP file and generate report."""
    pass
```

**Docstrings:**
- Use docstrings for all public functions/classes
- Follow Google or NumPy style
- Include parameters, return values, and examples

```python
def extract_2g_voice_enc_info(
    packets: List[Dict[str, Any]],
    used_algorithms_fields: Dict[str, str],
    gsm_fields: Dict[str, str],
    misc_fields: Dict[str, str],
    translations_cfg: configparser.ConfigParser
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract 2G voice encryption algorithm information from packets.

    Args:
        packets: List of packet dictionaries from tshark
        used_algorithms_fields: Mapping of algorithm field names
        gsm_fields: GSM-specific field mappings
        misc_fields: Miscellaneous field mappings (timestamp, frame)
        translations_cfg: Configuration for value translations

    Returns:
        Dictionary mapping algorithm names to lists of usage records,
        each containing timestamp, frame number, and algorithm details.

    Example:
        >>> packets = [{"gsm_a.dtap.msg_rr_type": "0x05", ...}]
        >>> result = extract_2g_voice_enc_info(packets, fields, ...)
        >>> print(result.keys())
        dict_keys(['A5/1', 'A5/3'])
    """
    pass
```

**Imports:**
- Group imports: standard library, third-party, local
- Sort alphabetically within groups
- Avoid wildcard imports (`from module import *`)

```python
# Standard library
import argparse
import logging
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Third-party
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow

# Local
from pcapanalyzer import extract_2g_voice_enc_info
from tablebuilder import build_ods_table
```

**Error Handling:**
- Use specific exception types
- Provide helpful error messages
- Log errors appropriately

```python
try:
    with open(pcap_path, 'rb') as f:
        data = f.read()
except FileNotFoundError:
    logging.error(f"PCAP file not found: {pcap_path}")
    raise
except PermissionError:
    logging.error(f"Permission denied reading: {pcap_path}")
    raise
```

### Code Formatting

**Recommended: Use Black**
```bash
# Format a file
black your_file.py

# Format entire project
black .
```

**Alternative: Manual formatting**
- Follow PEP 8 guidelines
- Use consistent spacing and indentation

### Linting

**Run pylint before committing:**
```bash
pylint RANVDS.py pcapanalyzer.py securityevaluator.py tablebuilder.py GUI.py
```

**Common issues to avoid:**
- Unused imports or variables
- Too many local variables (refactor into smaller functions)
- Lines too long (break into multiple lines)
- Missing docstrings

---

## Commit Guidelines

### Commit Message Format

Use **Conventional Commits** format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring (no feature/bug change)
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system or dependency changes
- `ci`: CI/CD configuration changes
- `chore`: Other changes (maintenance, etc.)

**Examples:**

```bash
# Feature
git commit -m "feat(pcapanalyzer): add 5G SA NAS decryption support"

# Bug fix
git commit -m "fix(security): correct TMSI entropy calculation for edge cases"

# Documentation
git commit -m "docs(readme): add troubleshooting section for USB permissions"

# Refactoring
git commit -m "refactor(tablebuilder): extract ODS cell creation into helper function"
```

**Detailed commit with body:**
```
feat(security): add configurable randomness thresholds

Allow users to customize pass/fail thresholds for TMSI randomness
tests via GUI and CLI parameters. Thresholds include:
- Reuse rate maximum
- Entropy minimum
- Chi-square p-value minimum
- Hamming distance p-value minimum

Closes #42
```

### Commit Best Practices

- **Atomic commits** - One logical change per commit
- **Clear messages** - Explain what and why, not how
- **Reference issues** - Use "Closes #123" or "Fixes #456"
- **Sign commits** (optional) - Use GPG signatures for verification

---

## Pull Request Process

### Before Submitting

1. **Update your branch** with latest upstream changes
2. **Test your changes** thoroughly
3. **Run linters** and fix any issues
4. **Update documentation** if needed
5. **Write clear commit messages**

### Submitting a Pull Request

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub:
   - Go to the main repository
   - Click "New Pull Request"
   - Select your fork and branch
   - Fill out the PR template

3. **PR Title Format:**
   ```
   feat(module): brief description of changes
   ```

4. **PR Description Should Include:**
   - **Summary** - What does this PR do?
   - **Motivation** - Why is this change needed?
   - **Changes** - List of modifications
   - **Testing** - How was this tested?
   - **Screenshots** (if UI changes)
   - **Related Issues** - Closes #123

**Example PR Description:**
```markdown
## Summary
Adds support for parsing 5G Standalone (SA) NAS messages in security analysis.

## Motivation
Current implementation only handles 5G NSA mode. SA deployments use different
message structures that were causing parsing failures.

## Changes
- Added SA-specific message type handlers in `pcapanalyzer.py`
- Updated field mappings in `fields.cfg` for 5G SA
- Extended security evaluator to recognize SA cipher suites
- Added test PCAP with 5G SA traffic

## Testing
- Tested with real 5G SA captures from Operator X
- Verified ODS generation includes SA encryption data
- Confirmed security report correctly identifies SA algorithms

## Related Issues
Closes #87
```

### Review Process

1. **Automated checks** run (when CI/CD is set up)
2. **Maintainer review** - May request changes
3. **Address feedback** - Make requested modifications
4. **Approval** - Maintainer approves PR
5. **Merge** - PR is merged into main branch

### After Merge

- **Delete your branch** (optional):
  ```bash
  git branch -d feature/your-feature-name
  git push origin --delete feature/your-feature-name
  ```

- **Update your fork**:
  ```bash
  git checkout main
  git pull upstream main
  ```

---

## Testing Guidelines

### Current State

⚠️ **Note:** RANVDS is currently in the process of establishing a comprehensive test suite. Early contributors can help build this infrastructure!

### Future Testing Requirements

When the test framework is established:

**Unit Tests:**
- Test individual functions in isolation
- Use pytest framework
- Mock external dependencies (tshark, file I/O)
- Aim for 70%+ code coverage

**Integration Tests:**
- Test end-to-end workflows
- Use sample/anonymized PCAP files
- Verify ODS output structure and content

**Test File Naming:**
```
tests/
├── unit/
│   ├── test_pcap_analyzer.py
│   ├── test_security_evaluator.py
│   └── test_table_builder.py
├── integration/
│   ├── test_pcap_to_ods.py
│   └── test_security_report.py
└── fixtures/
    ├── sample_2g.pcap
    └── expected_output.ods
```

**Example Test:**
```python
import pytest
from pcapanalyzer import decimal_id_to_hex

def test_decimal_id_to_hex_conversion():
    """Test decimal to hex conversion."""
    assert decimal_id_to_hex("12345") == "0x3039"
    assert decimal_id_to_hex("0xff") == "0xff"
    assert decimal_id_to_hex("") == ""

def test_decimal_id_to_hex_with_padding():
    """Test hex padding options."""
    assert decimal_id_to_hex("15", even_length=True) == "0x0f"
    assert decimal_id_to_hex("15", even_length=False) == "0xf"
```

### Manual Testing

For now, manually test your changes:

1. **PCAP Analysis:**
   ```bash
   python3 ranvds.py -p test_capture.pcap -o test_output.ods
   ```

2. **Security Report:**
   ```bash
   python3 ranvds.py -s test_output.ods
   ```

3. **GUI:**
   ```bash
   python3 ranvds_gui.py
   ```

4. **Verify:**
   - No Python exceptions
   - ODS files open correctly in LibreOffice
   - Data appears accurate and complete

---

## Documentation

### Code Documentation

- **Docstrings** - All public functions and classes
- **Inline comments** - Complex logic or non-obvious code
- **Type hints** - Function signatures

### User Documentation

When updating features, also update:
- **README.md** - User-facing changes
- **RUNTIME_REQUIREMENTS.md** - New dependencies
- **Configuration files** - New fields or options

### Documentation Style

- **Clear and concise** - Avoid jargon when possible
- **Examples** - Show don't just tell
- **Up-to-date** - Keep in sync with code
- **Bilingual** (optional) - English primary, Portuguese welcome

---

## Community

### Communication Channels

- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - General questions, ideas (when enabled)
- **Pull Requests** - Code review and discussion

### Getting Help

- **Check documentation** - README, RUNTIME_REQUIREMENTS
- **Search issues** - Your question may be answered
- **Ask questions** - Open an issue with "question" label
- **Be patient** - Maintainers are volunteers

### Recognition

Contributors will be:
- Listed in project acknowledgments
- Credited in release notes
- Mentioned in academic citations (for significant contributions)

---

## License

By contributing to RANVDS, you agree that your contributions will be licensed under the **GNU General Public License v3.0**, the same license as the project.

This means:
- Your code becomes part of the GPL v3 codebase
- You retain copyright of your contributions
- You grant others the rights defined in GPL v3

---

## Questions?

If you have questions about contributing:
1. Check this document first
2. Search existing issues
3. Open a new issue with the "question" label
4. Contact the maintainer: [@lucaslima782](https://github.com/lucaslima782)

---

**Thank you for contributing to RANVDS!** 🎉

Your contributions help improve cellular network security research and make the tool more accessible to the community.
