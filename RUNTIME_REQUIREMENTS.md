# RANVDS Runtime Requirements (for the Nuitka onefile binary)

This document lists the OS-level packages and setup needed to run the packaged binary `dist/nuitka/ranvds` on a fresh Linux install. Python and pip packages are NOT required to run the binary. For source runs, use `requirements.txt` instead.

## Summary
- The binary bundles Python and all pure-Python libs.
- You must install a few system packages used at runtime:
  - tshark (Wireshark CLI)
  - USB tools/drivers (lsusb, libusb-1.0)
  - Kivy graphics stack (SDL2 + OpenGL/Mesa + optional mtdev)
- Install RANVDS config files to `/usr/local/etc/ranvds/`.
- Adjust user permissions for USB and (optionally) non-root capture with tshark.

## Distro quick-install

### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y \
  wireshark-common tshark usbutils libusb-1.0-0 \
  libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libsdl2-mixer-2.0-0 \
  libgl1 libgles2-mesa libglew2.2 libmtdev1
```
Notes:
- `wireshark-common` triggers a prompt to allow non-root packet capturing; you can also do this later (see "Permissions" below).
- Kivy uses SDL2 + OpenGL. The packages above cover typical desktop systems. If you run Wayland, ensure XWayland is available.

### Fedora/RHEL (adjust names as needed)
```bash
sudo dnf install -y \
  wireshark-cli usbutils libusbx \
  SDL2 SDL2_image SDL2_ttf SDL2_mixer \
  mesa-libGL mesa-libGLES glew mtdev
```
Notes:
- Some Fedora variants use `libusb1` instead of `libusbx`.

## Install configuration files
The app looks for its configuration at fixed paths under `/usr/local/etc/ranvds/`.
Install them once on the target machine:
```bash
sudo install -d /usr/local/etc/ranvds
sudo install -m 0644 fields.cfg translations.cfg mcc-mnc.csv /usr/local/etc/ranvds/
```
Files are sought by:
- `ranvds.py`: `/usr/local/etc/ranvds/translations.cfg` and `/usr/local/etc/ranvds/fields.cfg`
- `ranvds.py` MCC/MNC lookup: `/usr/local/etc/ranvds/mcc-mnc.csv`

Note: The build bundles these files inside the binary too, but the current code first searches the absolute paths above. Installing them system-wide guarantees runtime discovery.

## Permissions and groups
- Serial (if used): add your user to the `dialout` group.
```bash
sudo usermod -aG dialout $USER
```
- USB device access: you may need udev rules for your device(s) or add your user to a group like `plugdev` and define a permissive rule. Example rules:
```bash
# /etc/udev/rules.d/99-ranvds-usb.rules
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0660", GROUP="plugdev"   # Samsung
SUBSYSTEM=="usb", ATTR{idVendor}=="05c6", MODE="0660", GROUP="plugdev"   # Qualcomm
```
Then reload rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```
- Non-root tshark capture (optional):
```bash
sudo dpkg-reconfigure wireshark-common   # allow non-root capture
sudo usermod -aG wireshark $USER
```
Log out and back in for group changes to take effect.

## Environment notes
- ABI: The binary requires glibc >= the version present on the build machine. For broader compatibility, build on an older baseline distro.
- Display: X11 or Wayland with XWayland; OpenGL/Mesa drivers should be available.

## Validation checklist
```bash
# Verify graphics libs are present
ldd ./ranvds | grep -E "SDL2|GL|GLEW"

# Verify external tools
which tshark && tshark -v
which lsusb && lsusb

# Verify config files
ls -l /usr/local/etc/ranvds/
```

## Source-run (not required for the binary)
If you run from source instead of the binary, install Python deps from `requirements.txt`:
```bash
pip install -r requirements.txt
```
Optional performance dependency for CRC: `libscrc`.
