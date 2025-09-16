# RANVDS

A packaged Linux application (onefile via Nuitka) for evaluating security configurations of cellular networks using tshark and a config-driven field extraction approach. The app ships as a single binary and relies on a few system-level dependencies for capture and UI.

- Self-contained binary: `dist/nuitka/ranvds`
- Uses system tools/libraries: `tshark`, USB tools, SDL2/OpenGL (for GUI)
- Configuration-driven (2G/3G/4G/5G wireshark dissector fields): see `Config/`

For detailed runtime setup, see: [RUNTIME_REQUIREMENTS.md](./RUNTIME_REQUIREMENTS.md)

This app was developed in the context of a Masters Thesis and only has reasearch goals.

The app uses SCAT (https://github.com/fgsect/scat) to capture the traffic, and therefore has the same dependencies and limitations regarding the devices supported. However, this version also supports RRC and NAS messages for 5G in Samsung e5123 chipset devices. Support for other chipsets is not guaranteed and need to be tested for each case.

## Repository layout

- `Config/`
  - `fields.cfg`, `translations.cfg`, `mcc-mnc.csv` used by the application at runtime
- `scripts/`
  - `install_system.sh` – installs the binary and configuration into system paths
  - `uninstall_system.sh` – removes installed files (optionally purges data/config)
- `dist/nuitka/ranvds`
  - Packaged onefile binary
- `RUNTIME_REQUIREMENTS.md`
  - OS-level dependencies and full runtime setup guide

## Quick start

1) Install OS dependencies (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y \
  wireshark-common tshark usbutils libusb-1.0-0 \
  libsdl2-2.0-0 libsdl2-image-2.0-0 libsdl2-ttf-2.0-0 libsdl2-mixer-2.0-0 \
  libgl1 libgles2-mesa libglew2.2 libmtdev1
```
For Fedora/RHEL and more details, see [RUNTIME_REQUIREMENTS.md](./RUNTIME_REQUIREMENTS.md).

2) Install the app (from the repo root)
```bash
sudo scripts/install_system.sh --bin dist/nuitka/ranvds --config Config [--shared]
```
- Binary is installed to: `/usr/local/bin/ranvds`
- Data folders: `/usr/local/share/ranvds/{PCAPs, Resultados}`
- Config folder: `/usr/local/etc/ranvds/` (copies of the files in `Config/`)

3) Run
```bash
ranvds
```

## Uninstall

```bash
sudo scripts/uninstall_system.sh            # keeps data and config
sudo scripts/uninstall_system.sh --purge    # also removes /usr/local/share/ranvds and /usr/local/etc/ranvds
```
If you installed with `--shared`, you may also want to remove the `ranvds` group:
```bash
sudo groupdel ranvds || true
```

## Configuration

Edit the files in `Config/` to adjust parsing/labels and then reinstall (or copy over):
```bash
# reinstall to refresh /usr/local/etc/ranvds with your updated configs
sudo scripts/install_system.sh --config Config
```
At runtime the app reads from `/usr/local/etc/ranvds/`:
- `fields.cfg`
- `translations.cfg`
- `mcc-mnc.csv`

## Permissions (summary)

- Serial (if used): add your user to `dialout`.
```bash
sudo usermod -aG dialout $USER
```
- Non-root tshark capture (optional, Debian/Ubuntu):
```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```
- Shared installs: if you used `--shared`, add users to `ranvds` group and re-login.
```bash
sudo usermod -aG ranvds $USER
```
- USB access: you may need udev rules (see examples in [RUNTIME_REQUIREMENTS.md](./RUNTIME_REQUIREMENTS.md)).

## Troubleshooting

- Missing GUI libraries: ensure SDL2/OpenGL packages are installed (see Runtime Requirements).
- Permission errors capturing packets: review wireshark/tshark group settings and re-login.
- USB device permissions: add a udev rule for your device vendor IDs, reload rules.
