# RANVDS Runtime Requirements (for the Nuitka onefile binary)

This document lists the OS-level packages and setup needed to run the packaged binary `dist/nuitka/ranvds` on a fresh Linux install. Python and pip packages are NOT required to run the binary.

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

## Install via script (recommended)
Use the provided installer to set up the binary, data, and configuration paths:
```bash
# from the repository root
sudo scripts/install_system.sh [--shared] [--bin dist/nuitka/ranvds] [--config Config]
```
Options:
- `--bin`: path to the packaged binary (default: `dist/nuitka/ranvds`).
- `--config` or `--cfg`: path to the config folder containing `fields.cfg`, `translations.cfg`, and `mcc-mnc.csv` (default: `Config`).
- `--shared`: create a `ranvds` group and configure shared-writable directories (`2775`). Add users with `sudo usermod -aG ranvds <username>`.

Example:
```bash
sudo scripts/install_system.sh --bin dist/nuitka/ranvds --config Config --shared
```
After install:
- Binary: `/usr/local/bin/ranvds`
- Data dirs: `/usr/local/share/ranvds/PCAPs`, `/usr/local/share/ranvds/Resultados`
- Config dir: `/usr/local/etc/ranvds/` (`fields.cfg`, `translations.cfg`, `mcc-mnc.csv`)

## Manual install (alternative)
Only if you prefer not to use the script:
```bash
# Install binary
sudo install -Dm755 dist/nuitka/ranvds /usr/local/bin/ranvds

# Create data and config directories
sudo install -d /usr/local/share/ranvds/PCAPs /usr/local/share/ranvds/Resultados /usr/local/etc/ranvds

# Install configuration files
sudo install -m 0644 Config/fields.cfg Config/translations.cfg Config/mcc-mnc.csv /usr/local/etc/ranvds/
```

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
- Shared data/config (optional): if you installed with `--shared`, add users to the `ranvds` group and re-login.
```bash
sudo usermod -aG ranvds $USER
```
Log out and back in for group changes to take effect.

## Environment notes
- ABI: The binary requires glibc >= the version present on the build machine. For broader compatibility, build on an older baseline distro.
- Display: X11 or Wayland with XWayland; OpenGL/Mesa drivers should be available.

## Validation checklist
```bash
# Verify graphics libs are present (if Kivy/SDL2 GUI)
ldd /usr/local/bin/ranvds | grep -E "SDL2|GL|GLEW" || true

# Verify external tools
which tshark && tshark -v
which lsusb && lsusb

# Verify config files and directories
ls -l /usr/local/etc/ranvds/
ls -ld /usr/local/share/ranvds /usr/local/share/ranvds/PCAPs /usr/local/share/ranvds/Resultados

# Launch (should open the application)
ranvds
```

## Uninstall
Use the provided uninstall script:
```bash
sudo scripts/uninstall_system.sh            # keeps data and config
sudo scripts/uninstall_system.sh --purge    # also removes /usr/local/share/ranvds and /usr/local/etc/ranvds
```
If you installed with `--shared`, you may also want to remove the `ranvds` group:
```bash
sudo groupdel ranvds || true
```
Manual fallback (not recommended):
```bash
sudo rm -f /usr/local/bin/ranvds
sudo rm -rf /usr/local/share/ranvds
sudo rm -rf /usr/local/etc/ranvds
```
