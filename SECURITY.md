# Security Policy

## Reporting a Vulnerability

**IMPORTANT: DO NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in RANVDS, please report it responsibly by emailing:

**Security Contact:** [Your email address here]

### What to Include in Your Report

Please provide the following information:

1. **Description:** Clear description of the vulnerability
2. **Impact:** Potential security impact and affected components
3. **Reproduction:** Step-by-step instructions to reproduce the issue
4. **Proof of Concept:** Code, commands, or screenshots demonstrating the vulnerability
5. **Suggested Fix:** If you have ideas for fixing the issue (optional)
6. **Disclosure Timeline:** Your preferred disclosure timeline

## Security Best Practices for Users

### Data Privacy

RANVDS processes **highly sensitive cellular network data**, including other users broadcasted information:
- **IMSI** (International Mobile Subscriber Identity)
- **TMSI/GUTI** (Temporary Mobile Subscriber Identity)

**⚠️ CRITICAL WARNINGS:**

1. **Never share PCAP files or ODS reports containing real subscriber data**
2. **Anonymize all identifiers before publishing or sharing results**
3. **Use only on networks you own or have explicit written permission to test**
4. **Comply with local data protection regulations** (GDPR, LGPD, CCPA, etc.)
5. **Secure your analysis environment** (encrypted storage, access controls)

### Legal Compliance

**Before using RANVDS:**

- ✅ Comply with telecommunications regulations in your jurisdiction
- ✅ Follow ethical research guidelines (IRB approval if applicable)
- ✅ Respect privacy laws and data protection regulations
- ❌ Do NOT use for unauthorized network monitoring
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT violate terms of service of cellular providers

**Legal Disclaimer:** RANVDS is intended for **security research, network testing, and educational purposes only**. Users are solely responsible for ensuring their use complies with applicable laws and regulations.

## Known Security Considerations

### 1. PCAP File Handling

**Risk:** PCAP files may contain sensitive data beyond cellular protocols (IP addresses, DNS queries, etc.)

**Mitigation:**
- Use tshark filters to extract only cellular signaling
- Review PCAP contents before sharing
- Use Wireshark's anonymization features

### 2. Modem Dumps

**Risk:** Modem dumps may contain device-specific information, keys, or credentials

**Mitigation:**
- Never share raw modem dumps publicly
- Parse dumps in isolated environments
- Delete dumps after PCAP extraction

### 3. Live Capture

**Risk:** Live capture requires USB access and may expose system to device firmware vulnerabilities

**Mitigation:**
- Use dedicated capture devices
- Keep device firmware updated
- Monitor for unexpected USB behavior
- Use USB isolation/filtering if available

### 4. GUI Application

**Risk:** Kivy GUI may have vulnerabilities in file handling or rendering

**Mitigation:**
- Keep Kivy and dependencies updated
- Validate all user inputs
- Run GUI with minimal privileges

### 5. Dependency Vulnerabilities

**Risk:** Third-party libraries (odfpy, Kivy, SCAT) may have security vulnerabilities

**Mitigation:**
- Regularly update dependencies: `pip install -U -r requirements.txt`
- Monitor security advisories for dependencies
- Use tools like `pip-audit` or `safety` to check for known vulnerabilities

```bash
# Check for vulnerable dependencies
pip install pip-audit
pip-audit
```

## Security-Related Configuration

### Secure tshark Usage

By default, tshark requires root privileges for live capture. To run without root:

```bash
# Allow non-root packet capture (Debian/Ubuntu)
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
# Log out and back in
```

**Security Note:** This grants packet capture capabilities to your user account. Only do this on trusted systems.

### USB Device Permissions

RANVDS requires USB access for live capture. Recommended udev rules:

```bash
# /etc/udev/rules.d/99-ranvds-usb.rules
# Samsung devices
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0660", GROUP="plugdev"
# Qualcomm devices
SUBSYSTEM=="usb", ATTR{idVendor}=="05c6", MODE="0660", GROUP="plugdev"
```

**Security Note:** These rules grant USB access to the `plugdev` group. Ensure only trusted users are in this group.

---

## Responsible Disclosure Examples

We appreciate responsible disclosure from the security community. Examples of issues we'd like to know about:

- **Code Execution:** Vulnerabilities allowing arbitrary code execution
- **Data Exposure:** Unintended disclosure of sensitive data
- **Denial of Service:** Crashes or resource exhaustion
- **Path Traversal:** Unauthorized file system access
- **Cryptographic Weaknesses:** Flaws in randomness testing or crypto analysis

---

## Security Resources

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE (Common Weakness Enumeration):** https://cwe.mitre.org/
- **CVE (Common Vulnerabilities and Exposures):** https://cve.mitre.org/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework

---

## Contact

**GitHub:** https://github.com/lucaslima782/RANVDS

---

**Last Updated:** November 2025  
**Version:** 1.0
