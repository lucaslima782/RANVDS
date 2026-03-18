# Copyright (C) 2025 Lucas Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Kivy GUI for RANVDS.

Provides a desktop interface to:
  - Capture live traffic via SCAT and write PCAPs
  - Analyze modem dump files and generate PCAPs
  - Convert PCAP files into analysis ODS tables
  - Generate Security ODS reports from existing ODS files

Desktop run (development):
  python3 ranvds_gui.py
"""

from __future__ import annotations

from pathlib import Path
import os
import threading
import traceback
import sys
import io
import importlib, importlib.util
import logging
import time
from contextlib import redirect_stdout, redirect_stderr

from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.properties import BooleanProperty, StringProperty, ObjectProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.gridlayout import GridLayout
from kivy.uix.progressbar import ProgressBar
from kivy.uix.spinner import Spinner
from kivy.uix.image import Image
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.widget import Widget
from kivy.core.window import Window
import json as _gui_json


def _find_app_icon() -> str | None:
    """Locate the RANVDS icon PNG for the GUI window and in-app header.

    Preference order:
      1) RANVDS_ICON environment variable (if set)
      2) System install path /usr/local/share/ranvds/RANVDS.png
      3) RANVDS.png next to this module (development tree)
      4) RANVDS.png inside Nuitka onefile temporary directory (if present)
    """
    candidates: list[Path] = []

    # Explicit override via environment variable
    env_path = os.environ.get("RANVDS_ICON")
    if env_path:
        candidates.append(Path(env_path))

    # System-wide install location used by install_system.sh
    candidates.append(Path("/usr/local/share/ranvds/RANVDS.png"))

    # Development tree: icon alongside this GUI module
    try:
        here = Path(__file__).resolve().parent
        candidates.append(here / "RANVDS.png")
    except Exception:
        pass

    # Nuitka onefile temporary extraction directory (if used)
    try:
        onefile_tmp = os.environ.get("NUITKA_ONEFILE_TEMP")
        if onefile_tmp:
            candidates.append(Path(onefile_tmp) / "RANVDS.png")
    except Exception:
        pass

    for p in candidates:
        try:
            if p.is_file():
                return str(p.resolve())
        except Exception:
            continue
    return None


KV = r"""
<VDSRoot>:
    orientation: 'vertical'
    spacing: '0dp'
    padding: '0dp'

    # ── Header bar ───────────────────────────────────────────────────────────
    BoxLayout:
        size_hint_y: None
        height: '48dp'
        canvas.before:
            Color:
                rgba: 0.09, 0.13, 0.22, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            markup: True
            text: '[b]RANVDS[/b]  —  Radio Access Network Vulnerability Detection System'
            font_size: '15sp'
            halign: 'center'
            valign: 'middle'
            color: 0.88, 0.94, 1, 1

    # ── Main tabs ────────────────────────────────────────────────────────────
    TabbedPanel:
        do_default_tab: False
        tab_width: '200dp'
        tab_height: '36dp'

        # ════════════════════════════════════════════════════════════════
        #  Tab 1 — Live Capture
        # ════════════════════════════════════════════════════════════════
        TabbedPanelItem:
            text: 'Live Capture'
            BoxLayout:
                orientation: 'vertical'
                padding: '18dp'
                spacing: '10dp'

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Target IP:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.live_ip
                        multiline: False
                        hint_text: '127.0.0.1'
                        on_text: root.live_ip = self.text

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'SCAT type:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Spinner:
                        text: root.scat_type
                        values: ['sec', 'qc']
                        size_hint_x: None
                        width: '110dp'
                        on_text: root.scat_type = self.text
                    Label:
                        text: 'Interface:'
                        size_hint_x: None
                        width: '100dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.scat_iface
                        multiline: False
                        size_hint_x: None
                        width: '90dp'
                        on_text: root.scat_iface = self.text

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Model (optional):'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.scat_model
                        multiline: False
                        hint_text: 'e.g. e5123'
                        on_text: root.scat_model = self.text

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Start magic (optional):'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.scat_start_magic
                        multiline: False
                        hint_text: 'e.g. 0xffffffff'
                        on_text: root.scat_start_magic = self.text

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output folder:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        text: root.live_output_dir
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('live_dir')

                Widget:
                    size_hint_y: None
                    height: '16dp'

                BoxLayout:
                    size_hint_y: None
                    height: '46dp'
                    spacing: '10dp'
                    Button:
                        text: 'Start Live Capture'
                        font_size: '14sp'
                        disabled: root.is_busy or root.is_live_running
                        on_release: root.run_live_generation()
                    Button:
                        text: 'Stop Capture'
                        size_hint_x: None
                        width: '150dp'
                        disabled: not root.is_live_running
                        on_release: root.stop_live_capture()

        # ════════════════════════════════════════════════════════════════
        #  Tab 2 — Modem Log Analyzer
        # ════════════════════════════════════════════════════════════════
        TabbedPanelItem:
            text: 'Modem Log'
            BoxLayout:
                orientation: 'vertical'
                padding: '18dp'
                spacing: '10dp'

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Dump type:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Spinner:
                        text: root.dump_type
                        values: ['sec', 'qc']
                        size_hint_x: None
                        width: '110dp'
                        on_text: root.dump_type = self.text
                    Label:
                        text: 'Model (optional):'
                        size_hint_x: None
                        width: '160dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.dump_model
                        multiline: False
                        hint_text: 'e.g. e5123'
                        on_text: root.dump_model = self.text

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Dump file:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        text: root.dump_path if root.dump_path else '(no file selected)'
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('dump')

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output folder:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        text: root.dump_output_dir
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('dump_dir')

                Widget:
                    size_hint_y: None
                    height: '16dp'

                BoxLayout:
                    size_hint_y: None
                    height: '46dp'
                    spacing: '10dp'
                    Button:
                        text: 'Start Analyzer'
                        font_size: '14sp'
                        disabled: root.is_busy or root.is_dump_running or not root.dump_path
                        on_release: root.run_dump_analysis()
                    Button:
                        text: 'Stop Analyzer'
                        size_hint_x: None
                        width: '150dp'
                        disabled: not root.is_dump_running
                        on_release: root.stop_dump_analysis()

        # ════════════════════════════════════════════════════════════════
        #  Tab 3 — PCAP Analyzer
        # ════════════════════════════════════════════════════════════════
        TabbedPanelItem:
            text: 'PCAP Analyzer'
            BoxLayout:
                orientation: 'vertical'
                padding: '18dp'
                spacing: '10dp'

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'PCAP file:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        text: root.pcap_path if root.pcap_path else '(no file selected)'
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('pcap')

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output folder:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        text: root.pcap_output_dir
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('pcap_dir')

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output name (optional):'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.output_name
                        multiline: False
                        hint_text: 'e.g. result.ods  (auto-named if blank)'
                        on_text: root.output_name = self.text

                Widget:
                    size_hint_y: None
                    height: '16dp'

                BoxLayout:
                    size_hint_y: None
                    height: '46dp'
                    spacing: '10dp'
                    Button:
                        text: 'Analysis Options'
                        size_hint_x: None
                        width: '210dp'
                        on_release: root.open_pcap_selection_menu()
                    Button:
                        text: 'Generate ODS'
                        font_size: '14sp'
                        disabled: root.is_busy or not root.pcap_path
                        on_release: root.run_pcap_generation()

        # ════════════════════════════════════════════════════════════════
        #  Tab 4 — Security Evaluator
        # ════════════════════════════════════════════════════════════════
        TabbedPanelItem:
            text: 'Security Evaluator'
            BoxLayout:
                orientation: 'vertical'
                padding: '18dp'
                spacing: '10dp'

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'ODS file:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        id: ods_label
                        text: root.ods_path if root.ods_path else '(no file selected)'
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('ods')

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output folder:'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    Label:
                        id: out_label
                        text: root.output_dir
                        text_size: self.size
                        halign: 'left'
                        valign: 'middle'
                        shorten: True
                        shorten_from: 'left'
                    Button:
                        text: 'Browse'
                        size_hint_x: None
                        width: '110dp'
                        on_release: root.open_file_chooser('dir')

                BoxLayout:
                    size_hint_y: None
                    height: '38dp'
                    spacing: '8dp'
                    Label:
                        text: 'Output name (optional):'
                        size_hint_x: None
                        width: '170dp'
                        halign: 'right'
                        valign: 'middle'
                        text_size: self.size
                    TextInput:
                        text: root.security_output_name
                        multiline: False
                        hint_text: 'e.g. security.ods  (auto-named if blank)'
                        on_text: root.security_output_name = self.text

                Widget:
                    size_hint_y: None
                    height: '16dp'

                BoxLayout:
                    size_hint_y: None
                    height: '46dp'
                    spacing: '10dp'
                    Button:
                        text: 'Evaluator Options'
                        size_hint_x: None
                        width: '210dp'
                        on_release: root.open_security_selection_menu()
                    Button:
                        text: 'Generate Security ODS'
                        font_size: '14sp'
                        disabled: root.is_busy or not root.ods_path
                        on_release: root.run_generation()

    # ── Log area (always visible) ────────────────────────────────────────────
    BoxLayout:
        size_hint_y: None
        height: '24dp'
        padding: ('10dp', '2dp')
        spacing: '6dp'
        canvas.before:
            Color:
                rgba: 0.12, 0.12, 0.14, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: 'Log'
            font_size: '12sp'
            bold: True
            halign: 'left'
            valign: 'middle'
            text_size: self.size
            color: 0.75, 0.85, 1, 1
        Button:
            text: 'Clear'
            size_hint: None, None
            size: '62dp', '20dp'
            font_size: '11sp'
            on_release: root.log_text = ''

    ScrollView:
        id: log_scroll
        size_hint_y: None
        height: '200dp'
        do_scroll_x: False
        bar_width: '8dp'
        scroll_type: ['bars', 'content']
        TextInput:
            id: log_text
            text: root.log_text
            readonly: True
            multiline: True
            size_hint_y: None
            height: max(self.minimum_height, log_scroll.height)
            font_size: '13sp'
            background_color: 0.07, 0.07, 0.09, 1
            foreground_color: 0.9, 0.9, 0.9, 1
            cursor_color: 0.07, 0.07, 0.09, 0
            padding: [8, 4, 8, 4]
"""


class VDSRoot(BoxLayout):
    """Root widget for the RANVDS GUI, orchestrating capture, analysis, and ODS generation."""

    ods_path = StringProperty("")
    output_dir = StringProperty(str(Path.cwd().resolve()))
    log_text = StringProperty("")
    is_busy = BooleanProperty(False)
    _pcap_profile: dict = {}
    _security_profile: dict = {}
    pcap_path = StringProperty("")
    output_name = StringProperty("")
    pcap_output_dir = StringProperty(str(Path.cwd().resolve()))
    security_output_name = StringProperty("")
    # Security randomness retransmission window (seconds), default 10
    security_retx_secs = StringProperty("10")
    tmsi_collision_max = StringProperty("0.01")
    tmsi_h_norm_min = StringProperty("0.99")
    tmsi_succ_hamm_p_min = StringProperty("0.01")
    tmsi_chi2_p_min = StringProperty("0.01")
    # Live-related properties
    live_ip = StringProperty("127.0.0.1")
    scat_type = StringProperty("sec")
    scat_model = StringProperty("")
    scat_iface = StringProperty("4")
    scat_start_magic = StringProperty("")
    live_output_dir = StringProperty(str(Path.cwd().resolve()))
    # Non-blocking live capture state
    is_live_running = BooleanProperty(False)
    live_proc = ObjectProperty(None, allownone=True)
    live_pcap = StringProperty("")

    # Dump-related properties
    dump_type = StringProperty("sec")
    dump_model = StringProperty("")
    dump_path = StringProperty("")
    dump_output_dir = StringProperty(str(Path.cwd().resolve()))
    # Non-blocking dump analyzer state
    is_dump_running = BooleanProperty(False)
    dump_proc = ObjectProperty(None, allownone=True)
    dump_pcap = StringProperty("")

    def _build_checkbox_popup(self, title: str, groups: dict, current_profile, cols: int = 2) -> tuple:
        """Build a scrollable checkbox popup. Returns (popup, checkboxes_dict)."""
        content = BoxLayout(orientation='vertical', spacing='4dp', padding='6dp')
        scroll = ScrollView(do_scroll_x=False)
        inner = BoxLayout(orientation='vertical', size_hint_y=None, spacing='2dp', padding='2dp')
        inner.bind(minimum_height=inner.setter('height'))

        checkboxes: dict = {}

        for section_name, entries in groups.items():
            hdr = Label(
                text=f'[b]{section_name}[/b]',
                markup=True,
                size_hint_y=None,
                height='28dp',
                halign='left',
                valign='middle',
            )
            hdr.bind(size=lambda lbl, sz: setattr(lbl, 'text_size', sz))
            inner.add_widget(hdr)

            grid = GridLayout(cols=cols, size_hint_y=None, row_default_height='28dp',
                              spacing=('4dp', '2dp'))
            grid.bind(minimum_height=grid.setter('height'))

            for key_or_keys, label_text in entries:
                keys = key_or_keys if isinstance(key_or_keys, list) else [key_or_keys]
                active = all(getattr(current_profile, k, True) for k in keys)
                cb = CheckBox(active=active, size_hint_x=None, width='28dp')
                lbl = Label(text=label_text, halign='left', valign='middle', size_hint_x=1)
                lbl.bind(size=lambda l, s: setattr(l, 'text_size', s))
                item = BoxLayout(spacing='2dp')
                item.add_widget(cb)
                item.add_widget(lbl)
                grid.add_widget(item)
                checkboxes[tuple(keys)] = cb

            if len(entries) % cols != 0:
                for _ in range(cols - (len(entries) % cols)):
                    grid.add_widget(Label())

            inner.add_widget(grid)

        scroll.add_widget(inner)
        content.add_widget(scroll)

        btn_row = BoxLayout(size_hint_y=None, height='40dp', spacing='6dp')
        sel_all_btn   = Button(text='Select All')
        desel_all_btn = Button(text='Deselect All')
        ok_btn        = Button(text='OK')
        cancel_btn    = Button(text='Cancel')
        btn_row.add_widget(sel_all_btn)
        btn_row.add_widget(desel_all_btn)
        btn_row.add_widget(ok_btn)
        btn_row.add_widget(cancel_btn)
        content.add_widget(btn_row)

        popup = Popup(title=title, content=content, size_hint=(0.72, 0.88))
        sel_all_btn.bind(on_release=lambda *_: [setattr(cb, 'active', True) for cb in checkboxes.values()])
        desel_all_btn.bind(on_release=lambda *_: [setattr(cb, 'active', False) for cb in checkboxes.values()])
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())
        return popup, checkboxes, ok_btn

    def open_pcap_selection_menu(self) -> None:
        """Open the PCAP analysis selection popup (full per-generation extractor list)."""
        from selection_profile import SelectionProfile, PROFILE_LABELS, PROFILE_GROUPS
        current = SelectionProfile.from_dict(self._pcap_profile) if self._pcap_profile else SelectionProfile()
        # Convert PROFILE_GROUPS to (key, label) entry format
        groups_as_entries = {
            gen: [(k, PROFILE_LABELS.get(k, k)) for k in keys]
            for gen, keys in PROFILE_GROUPS.items()
        }
        popup, checkboxes, ok_btn = self._build_checkbox_popup(
            'PCAP Analysis Options', groups_as_entries, current, cols=2
        )

        def do_ok(_btn):
            flat: dict = {}
            for keys_tuple, cb in checkboxes.items():
                for k in keys_tuple:
                    flat[k] = cb.active
            self._pcap_profile = flat
            popup.dismiss()

        ok_btn.bind(on_release=do_ok)
        popup.open()

    def open_security_selection_menu(self) -> None:
        """Open the Security Evaluator options popup (coarse modules + indicators thresholds)."""
        from selection_profile import SelectionProfile, SECURITY_MENU_GROUPS
        current = SelectionProfile.from_dict(self._security_profile) if self._security_profile else SelectionProfile()
        popup, checkboxes, ok_btn = self._build_checkbox_popup(
            'Security Evaluator Options', SECURITY_MENU_GROUPS, current, cols=2
        )

        # Inject Parameters section below the scroll, above the buttons
        content = popup.content
        # Remove the last child (btn_row) temporarily, add params, re-add
        btn_row = content.children[0]
        content.remove_widget(btn_row)

        params_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing='3dp')
        params_box.bind(minimum_height=params_box.setter('height'))

        param_hdr = Label(text='[b]Evaluation Thresholds[/b]', markup=True,
                          size_hint_y=None, height='28dp', halign='left', valign='middle')
        param_hdr.bind(size=lambda l, s: setattr(l, 'text_size', s))
        params_box.add_widget(param_hdr)

        def _param_row(label_text: str, current_val: str, input_filter: str):
            row = BoxLayout(size_hint_y=None, height='30dp', spacing='6dp')
            lbl = Label(text=label_text, size_hint_x=None, width='220dp',
                        halign='left', valign='middle')
            lbl.bind(size=lambda l, s: setattr(l, 'text_size', s))
            ti = TextInput(text=current_val, multiline=False, input_filter=input_filter,
                           size_hint_x=1)
            row.add_widget(lbl)
            row.add_widget(ti)
            params_box.add_widget(row)
            return ti

        ti_retx   = _param_row('Retransmit window (sec):', self.security_retx_secs, 'int')
        ti_coll   = _param_row('Reuse rate max:', self.tmsi_collision_max, 'float')
        ti_hnorm  = _param_row('H_norm min:', self.tmsi_h_norm_min, 'float')
        ti_hamm   = _param_row('Succ. Hamming p min:', self.tmsi_succ_hamm_p_min, 'float')
        ti_chi2   = _param_row('Chi2 p min:', self.tmsi_chi2_p_min, 'float')

        content.add_widget(params_box)
        content.add_widget(btn_row)

        def do_ok(_btn):
            flat: dict = {}
            for keys_tuple, cb in checkboxes.items():
                for k in keys_tuple:
                    flat[k] = cb.active
            self._security_profile = flat
            self.security_retx_secs    = ti_retx.text
            self.tmsi_collision_max    = ti_coll.text
            self.tmsi_h_norm_min       = ti_hnorm.text
            self.tmsi_succ_hamm_p_min  = ti_hamm.text
            self.tmsi_chi2_p_min       = ti_chi2.text
            popup.dismiss()

        ok_btn.bind(on_release=do_ok)
        popup.open()

    def _append_log(self, msg: str) -> None:
        """Append a message to the log area."""
        self.log_text += (msg + "\n")
        sv = self.ids.get('log_scroll')
        if sv:
            # Let layout update, then scroll to bottom
            from kivy.clock import Clock
            Clock.schedule_once(lambda _dt: setattr(sv, 'scroll_y', 0))
            Clock.schedule_once(lambda _dt: setattr(sv, 'scroll_y', 0), 0.05)

    def _locate_ranvds_py(self) -> Path | None:
        """Locate ranvds.py similar to _run_ranvds_inprocess."""
        bases = [Path(__file__).resolve().parent]
        try:
            onefile_tmp = os.environ.get('NUITKA_ONEFILE_TEMP')
            if onefile_tmp:
                p = Path(onefile_tmp)
                if p.exists():
                    bases.insert(0, p)
        except Exception:
            pass
        try:
            argv_base = Path(sys.argv[0]).resolve().parent
            if argv_base not in bases:
                bases.append(argv_base)
        except Exception:
            pass
        bases.append(Path.cwd())
        for b in bases:
            cand = (b / 'ranvds.py')
            if cand.exists():
                return cand.resolve()
        return None

    def _load_ranvds_module(self, run_cwd: Path):
        """Import RANVDS as a Python module. Prefer normal import so Nuitka onefile does not need a loose ranvds.py.

        Returns the imported RANVDS module object.
        """
        # First try normal import; works both in development and Nuitka (compiled module)
        try:
            return importlib.import_module('RANVDS')
        except Exception:
            pass
        # Fallback: load from a nearby file for development environments only
        ranvds_py = self._locate_ranvds_py()
        if not ranvds_py:
            raise FileNotFoundError('ranvds.py not found near application.')
        module_dir = str(ranvds_py.parent)
        old_sys_path0 = None
        try:
            # Ensure sibling imports resolve
            sys.path.insert(0, module_dir)
            old_sys_path0 = module_dir
            spec = importlib.util.spec_from_file_location('RANVDS_runtime_live', ranvds_py)
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[arg-type]
            return mod
        finally:
            try:
                if old_sys_path0 and sys.path and sys.path[0] == old_sys_path0:
                    sys.path.pop(0)
            except Exception:
                pass

    def _run_ranvds_inprocess(self, args: list[str], run_cwd: Path) -> tuple[int, str]:
        """
        Execute RANVDS's main() in-process using module import, simulating CLI with args.

        Returns: (returncode, combined_output)

        This method runs RANVDS in-process, capturing its output and logging.
        """
        # Prepare capture buffers
        std_buf = io.StringIO()
        log_buf = io.StringIO()

        # Temporary logging handler to capture RANVDS logging
        root_logger = logging.getLogger()
        handler = logging.StreamHandler(log_buf)
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        handler.setLevel(logging.DEBUG)
        root_logger.addHandler(handler)

        # Snapshot and prepare state
        old_argv = sys.argv[:]
        old_cwd = os.getcwd()
        rc = 0
        ranvds = None
        module_dir = None
        try:
            try:
                # Prefer normal module import (works in Nuitka onefile)
                ranvds = importlib.import_module('ranvds')
            except Exception:
                # Fallback: load from a nearby file for development
                ranvds_py = self._locate_ranvds_py()
                if not ranvds_py:
                    return 1, 'ranvds.py not found near application.'
                module_dir = str(ranvds_py.parent)
                sys.path.insert(0, module_dir)
                spec = importlib.util.spec_from_file_location('VDS_runtime', ranvds_py)
                assert spec and spec.loader
                ranvds = importlib.util.module_from_spec(spec)
                # Exec once to populate the module
                with redirect_stdout(std_buf), redirect_stderr(std_buf):
                    spec.loader.exec_module(ranvds)  # type: ignore[arg-type]

            # Simulate script argv: program name + args
            sys.argv = ['ranvds'] + args
            with redirect_stdout(std_buf), redirect_stderr(std_buf):
                # Change working directory as required by backend
                os.chdir(str(run_cwd))
                if hasattr(ranvds, 'main') and callable(getattr(ranvds, 'main')):
                    try:
                        getattr(ranvds, 'main')()
                    except SystemExit as e:  # in case main calls sys.exit
                        rc = int(e.code) if isinstance(e.code, int) else 1
                else:
                    # No main; treat as success
                    rc = 0
        except SystemExit as e:
            rc = int(e.code) if isinstance(e.code, int) else 1
        except Exception:
            rc = 1
            # Also append traceback to output buffer
            std_buf.write(traceback.format_exc(limit=5))
        finally:
            # Restore state
            try:
                os.chdir(old_cwd)
            except Exception:
                pass
            sys.argv = old_argv
            # Remove path we inserted
            try:
                if module_dir and sys.path and sys.path[0] == module_dir:
                    sys.path.pop(0)
            except Exception:
                pass
            root_logger.removeHandler(handler)

        combined = std_buf.getvalue() + log_buf.getvalue()
        return rc, combined

    def _post_log(self, msg: str) -> None:
        """Ensure log updates run on the Kivy main thread."""
        Clock.schedule_once(lambda _dt: self._append_log(msg))

    def open_file_chooser(self, mode: str) -> None:
        """Open a file or directory chooser for the specified `mode`."""
        # Default to user data folders we create, not a temp dir
        def _safe_dir(p: Path) -> Path:
            try:
                p.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return p if p.exists() else Path.home()
        if mode == 'ods':
            start_dir = _safe_dir(Path(self.output_dir))
        elif mode == 'pcap':
            start_dir = _safe_dir(Path(self.live_output_dir))
        elif mode == 'dir':
            start_dir = _safe_dir(Path(self.output_dir))
        elif mode == 'pcap_dir':
            start_dir = _safe_dir(Path(self.pcap_output_dir))
        elif mode == 'live_dir':
            start_dir = _safe_dir(Path(self.live_output_dir))
        elif mode == 'dump':
            # Modem dumps can be anywhere; default to home
            start_dir = Path.home()
        elif mode == 'dump_dir':
            start_dir = _safe_dir(Path(self.dump_output_dir or self.live_output_dir))
        else:
            start_dir = Path.home()
        chooser = FileChooserListView(
            path=str(start_dir.resolve()),
            filters={'ods': ['*.ods'], 'pcap': ['*.pcap', '*.pcapng'], 'dump': ['*.sdm', '*.qmdl', '*.qmdl2', '*.lpd', '*.bin', '*.*']}.get(mode, []),
        )
        # Be compatible with older Kivy where 'dirselect' kw/prop may not exist
        try:
            chooser.multiselect = False
            if mode in ('dir', 'pcap_dir', 'live_dir'):
                chooser.dirselect = True
        except Exception:
            pass
        ok_btn = Button(text='OK', size_hint_y=None, height='36dp')
        cancel_btn = Button(text='Cancel', size_hint_y=None, height='36dp')
        footer = BoxLayout(size_hint_y=None, height='40dp', spacing='6dp')
        footer.add_widget(ok_btn)
        footer.add_widget(cancel_btn)
        content = BoxLayout(orientation='vertical')
        content.add_widget(chooser)
        content.add_widget(footer)
        popup = Popup(title='Select file' if mode in ('ods','pcap') else 'Select folder', content=content, size_hint=(0.9, 0.9))

        def do_ok(_btn):
            try:
                sel = chooser.selection
                # Prefer explicit selection; fallback to current path for dir mode
                if mode == 'ods':
                    if sel:
                        p = Path(sel[0])
                        if p.is_file():
                            self.ods_path = str(p.resolve())
                        else:
                            self._post_log('Selection is not a valid .ods file.')
                    else:
                        self._post_log('No .ods file selected.')
                elif mode == 'pcap':
                    if sel:
                        p = Path(sel[0])
                        if p.is_file() and p.suffix.lower() in ['.pcap', '.pcapng']:
                            self.pcap_path = str(p.resolve())
                        else:
                            self._post_log('Selection is not a valid .pcap/.pcapng file.')
                    else:
                        self._post_log('No PCAP file selected.')
                elif mode == 'dump':
                    if sel:
                        p = Path(sel[0])
                        if p.is_file():
                            self.dump_path = str(p.resolve())
                        else:
                            self._post_log('Selection is not a valid dump file.')
                    else:
                        self._post_log('No dump file selected.')
                elif mode == 'dir':
                    target = Path(sel[0]) if sel else Path(chooser.path)
                    # If a file got selected by mistake, use its parent
                    if target.is_file():
                        target = target.parent
                    if not target.exists():
                        try:
                            target.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self._post_log(f'Failed to create folder: {e}')
                            return
                    if target.is_dir():
                        self.output_dir = str(target.resolve())
                    else:
                        self._post_log('Invalid selection for output folder.')
                elif mode == 'pcap_dir':
                    target = Path(sel[0]) if sel else Path(chooser.path)
                    if not target.exists():
                        try:
                            target.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self._post_log(f'Failed to create folder: {e}')
                            return
                    if target.is_dir():
                        self.pcap_output_dir = str(target.resolve())
                    else:
                        self._post_log('Invalid selection for PCAP output folder.')
                elif mode == 'live_dir':
                    base_target = Path(sel[0]) if sel else Path(chooser.path)
                    # If a file got selected by mistake, use its parent
                    if base_target.is_file():
                        base_target = base_target.parent
                    # Normalize to the PCAPs subfolder
                    if base_target.name.lower() == 'pcaps':
                        pcap_dir = base_target
                    else:
                        pcap_dir = base_target / 'PCAPs'
                    if not pcap_dir.exists():
                        try:
                            pcap_dir.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self._post_log(f'Failed to create PCAPs folder: {e}')
                            return
                    if pcap_dir.is_dir():
                        self.live_output_dir = str(pcap_dir.resolve())
                    else:
                        self._post_log('Invalid selection for Live output folder.')
                elif mode == 'dump_dir':
                    base_target = Path(sel[0]) if sel else Path(chooser.path)
                    # If a file got selected by mistake, use its parent
                    if base_target.is_file():
                        base_target = base_target.parent
                    # Normalize to the PCAPs subfolder
                    if base_target.name.lower() == 'pcaps':
                        pcap_dir = base_target
                    else:
                        pcap_dir = base_target / 'PCAPs'
                    if not pcap_dir.exists():
                        try:
                            pcap_dir.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self._post_log(f'Failed to create PCAPs folder: {e}')
                            return
                    if pcap_dir.is_dir():
                        self.dump_output_dir = str(pcap_dir.resolve())
                    else:
                        self._post_log('Invalid selection for Dump output folder.')
                else:
                    self._post_log('Unknown selection mode.')
            except Exception:
                self._post_log('Error while selecting path.')
                self._post_log(traceback.format_exc(limit=3))
            finally:
                popup.dismiss()

        ok_btn.bind(on_release=do_ok)
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())
        popup.open()

    def run_generation(self) -> None:
        """Start Security ODS generation in a background thread from the selected ODS."""
        if not self.ods_path:
            return
        self.is_busy = True
        self._append_log(f"Starting generation from: {self.ods_path}")
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def _worker(self) -> None:
        """Start Security ODS generation asynchronously via RANVDS and spawn a monitor."""
        def start_failed(msg: str) -> None:
            self.is_busy = False
            self._append_log(msg)

        try:
            ods = Path(self.ods_path)
            outdir = Path(self.output_dir)
            outdir.mkdir(parents=True, exist_ok=True)

            # Snapshot existing ODS files to detect the newly created one later
            before = {p.resolve() for p in outdir.glob('*.ods')}

            # Load RANVDS API module (supports Nuitka onefile and dev fallback)
            try:
                ranvds = self._load_ranvds_module(outdir)
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: start_failed(f"Error loading RANVDS module:\n{err}"))
                return

            # Launch non-blocking security report generation with configurable retransmission window
            try:
                secs_txt = (self.security_retx_secs or '10').strip()
                try:
                    secs_val = float(secs_txt)
                except Exception:
                    secs_val = 10.0
                th = {}
                try:
                    v = float((self.tmsi_collision_max or '').strip())
                    th['collision_max'] = v
                except Exception:
                    pass
                try:
                    v = float((self.tmsi_h_norm_min or '').strip())
                    th['h_norm_min'] = v
                except Exception:
                    pass
                try:
                    v = float((self.tmsi_succ_hamm_p_min or '').strip())
                    th['succ_hamm_p_min'] = v
                except Exception:
                    pass
                try:
                    v = float((self.tmsi_chi2_p_min or '').strip())
                    th['chi2_p_min'] = v
                except Exception:
                    pass
                profile_dict = self._security_profile or None
                proc = ranvds.start_security_report_nonblocking(
                    str(ods), output_dir=str(outdir), retransmit_window_seconds=secs_val, tmsi_thresholds=(th or None), profile_dict=profile_dict
                )
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: start_failed(f"Error starting security generation:\n{err}"))
                return

            # Log on UI thread
            Clock.schedule_once(lambda *_: self._append_log(f"Security generation started (pid={getattr(proc, 'pid', None)})."))

            # Spawn monitor to wait for completion and handle optional rename
            desired_name = (self.security_output_name or '').strip()
            t = threading.Thread(
                target=self._monitor_security_end,
                args=(proc, str(outdir), before, ods.stem, desired_name),
                daemon=True,
            )
            t.start()
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: start_failed(f"Error:\n{err}"))

    def _worker_live(self) -> None:
        def done(ok: bool, msg: str) -> None:
            self.is_busy = False
            self._append_log(msg)

        try:
            # Determine the PCAPs directory: use live_output_dir directly as PCAPs folder
            pcap_dir = Path(self.live_output_dir or (Path(__file__).resolve().parent / 'PCAPs'))
            pcap_dir.mkdir(parents=True, exist_ok=True)
            # ranvds.py writes to CWD/PCAPs, so set cwd to the parent of the selected PCAPs folder
            run_cwd = pcap_dir.parent

            # Snapshot existing PCAP files under the selected PCAPs directory
            before = {p.resolve() for p in pcap_dir.glob('*.pcap*')}

            # Build RANVDS args
            args = ['-l']
            ip = (self.live_ip or '').strip()
            if ip and ip != '127.0.0.1':
                args += [ip]
            # SCAT parameters
            scat_type = (self.scat_type or 'sec').strip()
            if scat_type not in ('sec', 'qc'):
                scat_type = 'sec'
            args += ['-t', scat_type]
            iface = (self.scat_iface or '4').strip()
            args += ['-i', iface]
            model = (self.scat_model or '').strip()
            if model:
                args += ['-m', model]
            magic = (self.scat_start_magic or '').strip()
            if magic:
                args += ['--start-magic', magic]

            self._post_log(f"Running: ranvds.py {' '.join(args)} (cwd={run_cwd})")
            rc, out = self._run_ranvds_inprocess(args, run_cwd)

            created_from_output = None
            if out:
                for line in out.splitlines():
                    self._post_log(line)
                    if line.startswith('PCAP_CREATED '):
                        created_from_output = line.split(' ', 1)[1].strip()

            if rc != 0:
                Clock.schedule_once(lambda *_: done(False, f"Live failed (code {rc})."))
                return

            # Determine created PCAP path
            final_path = None
            if created_from_output:
                p = Path(created_from_output)
                if p.exists():
                    final_path = p.resolve()
            if final_path is None:
                after = {p.resolve() for p in pcap_dir.glob('*.pcap*')}
                created = list(after - before)
                if created:
                    created.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                    final_path = created[0]

            if final_path:
                # Expose PCAP to the PCAP→ODS section
                Clock.schedule_once(lambda *_: setattr(self, 'pcap_path', str(final_path)))
                Clock.schedule_once(lambda *_: done(True, f"Done. PCAP saved: {final_path}"))
            else:
                Clock.schedule_once(lambda *_: done(False, "Live completed, but no PCAP was found."))
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: done(False, f"Error:\n{err}"))

    def _worker_live_start(self) -> None:
        """Start SCAT live capture in a non-blocking way and spawn a monitor."""
        try:
            # Determine the PCAPs directory and working dir
            pcap_dir = Path(self.live_output_dir or (Path(__file__).resolve().parent / 'PCAPs'))
            pcap_dir.mkdir(parents=True, exist_ok=True)
            run_cwd = pcap_dir.parent

            # Load RANVDS API
            try:
                ranvds = self._load_ranvds_module(run_cwd)
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: self._append_log(f"Error loading ranvds.py:\n{err}"))
                return

            # Resolve USB bus/port
            scat_type = (self.scat_type or 'sec').strip()
            try:
                bus, port = ranvds.detect_cell(scat_type)
                if not bus:
                    Clock.schedule_once(lambda *_: self._append_log('No supported USB device detected.'))
                    return
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: self._append_log(f"USB detection failed:\n{err}"))
                return

            # Prepare optional params
            iface = (self.scat_iface or '4').strip()
            model = (self.scat_model or '').strip() or None
            magic = (self.scat_start_magic or '').strip() or None

            # Start SCAT non-blocking and direct output to the chosen pcap_dir
            old_cwd = os.getcwd()
            try:
                os.chdir(str(run_cwd))
                proc, pcap_path = ranvds.start_live_capture_nonblocking(
                    bus, port, scat_type, iface, model, magic, pcap_dir=str(pcap_dir)
                )
            finally:
                try:
                    os.chdir(old_cwd)
                except Exception:
                    pass

            # Store state and log (on UI thread)
            def set_started(_dt=0):
                self.live_proc = proc
                self.live_pcap = str(pcap_path)
                self.is_live_running = True
                pid = getattr(proc, 'pid', None)
                self._append_log(f"Live started (pid={pid}). Writing to: {pcap_path}")
            Clock.schedule_once(set_started)

            # Spawn monitor thread with explicit handles to avoid race
            t = threading.Thread(target=self._monitor_live_end, args=(proc, str(pcap_path)), daemon=True)
            t.start()
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: self._append_log(f"Error starting live:\n{err}"))

    def _monitor_live_end(self, proc=None, pcap_path_str: str | None = None) -> None:
        """Wait for the SCAT child to exit, then validate and expose the PCAP.

        Accepts optional explicit proc and pcap path to avoid race with UI thread.
        """
        try:
            proc = proc or self.live_proc
            pcap_path = Path(pcap_path_str) if pcap_path_str else (Path(self.live_pcap) if self.live_pcap else None)
            if not proc or not pcap_path:
                Clock.schedule_once(lambda *_: self._append_log('No live process to monitor.'))
                return
            # Wait loop
            try:
                while True:
                    alive = False
                    try:
                        alive = proc.is_alive()
                    except Exception:
                        pass
                    if not alive:
                        break
                    time.sleep(0.3)
            except Exception:
                pass

            # Ensure process resources are collected
            try:
                proc.wait()
            except Exception:
                pass

            # Small wait for file flush
            try:
                for _ in range(10):
                    if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                        break
                    time.sleep(0.3)
            except Exception:
                pass

            # Update UI with result
            def finalize(_dt=0):
                self.is_live_running = False
                if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                    # Expose PCAP to the PCAP → ODS section
                    self.pcap_path = str(pcap_path.resolve())
                    self._append_log(f"Live finished. PCAP saved: {pcap_path}")
                else:
                    try:
                        exists = pcap_path.exists()
                        size = pcap_path.stat().st_size if exists else 'N/A'
                    except Exception:
                        exists, size = False, 'N/A'
                    self._append_log(f"Live finished, but no valid PCAP was found. Exists={exists}, Size={size}, Path={pcap_path}")
                self.live_proc = None
            Clock.schedule_once(finalize)
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: self._append_log(f"Monitor error:\n{err}"))

    def _worker_dump_start(self) -> None:
        """Start SCAT dump analyzer non-blocking and spawn a monitor."""
        try:
            # Determine the PCAPs directory for dump output
            pcap_dir = Path(self.dump_output_dir or self.live_output_dir or (Path(__file__).resolve().parent / 'PCAPs'))
            pcap_dir.mkdir(parents=True, exist_ok=True)

            # Load RANVDS API
            try:
                ranvds = self._load_ranvds_module(pcap_dir.parent)
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: self._append_log(f"Error loading ranvds.py:\n{err}"))
                return

            scat_type = (self.dump_type or 'sec').strip()
            model = (self.dump_model or '').strip() or None
            dump_file = (self.dump_path or '').strip()
            if not dump_file:
                Clock.schedule_once(lambda *_: self._append_log('No dump file selected.'))
                return

            # Start analyzer (no need to chdir; API accepts absolute output dir)
            proc, pcap_path = ranvds.start_dump_analyzer_nonblocking(
                scat_type=scat_type,
                dump_files=[dump_file],
                scat_model=model,
                pcap_dir=str(pcap_dir),
            )

            # Store state and log on UI thread
            def set_started(_dt=0):
                self.dump_proc = proc
                self.dump_pcap = str(pcap_path)
                self.is_dump_running = True
                pid = getattr(proc, 'pid', None)
                self._append_log(f"Dump analyzer started (pid={pid}). Writing to: {pcap_path}")
            Clock.schedule_once(set_started)

            # Spawn monitor
            t = threading.Thread(target=self._monitor_dump_end, args=(proc, str(pcap_path)), daemon=True)
            t.start()
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: self._append_log(f"Error starting dump analyzer:\n{err}"))

    def _monitor_dump_end(self, proc=None, pcap_path_str: str | None = None) -> None:
        """Wait for dump analyzer to exit and expose PCAP path to PCAP Analyzer section."""
        try:
            proc = proc or self.dump_proc
            pcap_path = Path(pcap_path_str) if pcap_path_str else (Path(self.dump_pcap) if self.dump_pcap else None)
            if not proc or not pcap_path:
                Clock.schedule_once(lambda *_: self._append_log('No dump process to monitor.'))
                return
            # Wait loop
            try:
                while True:
                    alive = False
                    try:
                        alive = proc.is_alive()
                    except Exception:
                        pass
                    if not alive:
                        break
                    time.sleep(0.3)
            except Exception:
                pass

            # Ensure process resources are collected
            try:
                proc.wait()
            except Exception:
                pass

            # Small wait for file flush
            try:
                for _ in range(10):
                    if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                        break
                    time.sleep(0.3)
            except Exception:
                pass

            # Update UI with result
            def finalize(_dt=0):
                self.is_dump_running = False
                if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                    # Expose PCAP to the PCAP → ODS section
                    self.pcap_path = str(pcap_path.resolve())
                    self._append_log(f"Dump analysis finished. PCAP saved: {pcap_path}")
                else:
                    try:
                        exists = pcap_path.exists()
                        size = pcap_path.stat().st_size if exists else 'N/A'
                    except Exception:
                        exists, size = False, 'N/A'
                    self._append_log(f"Dump analysis finished, but no valid PCAP was found. Exists={exists}, Size={size}, Path={pcap_path}")
                self.dump_proc = None
            Clock.schedule_once(finalize)
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: self._append_log(f"Monitor error (dump):\n{err}"))
 
    def _monitor_security_end(self, proc=None, outdir_str: str | None = None, before_set=None, prefix: str | None = None, desired_name: str | None = None) -> None:
        """Wait for the Security report child process to exit, then locate and optionally rename the output ODS.
        
        Arguments:
            proc: The subprocess-like adapter returned by RANVDS.start_security_report_nonblocking.
            outdir_str: The output directory where the ODS is written.
            before_set: A set of Path objects that existed before starting, to detect new files.
            prefix: Expected ODS filename prefix (ods.stem) used by the writer.
            desired_name: Optional custom filename requested by the user.
        """
        try:
            proc = proc
            if not proc or not outdir_str:
                Clock.schedule_once(lambda *_: (setattr(self, 'is_busy', False), self._append_log('No security process to monitor.')))
                return
            # Wait loop
            try:
                while True:
                    alive = False
                    try:
                        alive = proc.is_alive()
                    except Exception:
                        pass
                    if not alive:
                        break
                    time.sleep(0.3)
            except Exception:
                pass

            # Ensure process resources are collected and get return code
            rc = None
            try:
                rc = proc.wait()
            except Exception:
                try:
                    rc = getattr(proc, 'returncode', None)
                except Exception:
                    rc = None

            outdir = Path(outdir_str)
            final_path = None
            if rc == 0:
                # Detect the created ODS
                try:
                    after = {p.resolve() for p in outdir.glob('*.ods')}
                    created = list(after - (before_set or set()))
                    if created:
                        created.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                        final_path = created[0]
                    else:
                        # Fallbacks: expected default name or most recent ODS
                        if prefix:
                            base = (outdir / f"{prefix}_Security.ods").resolve()
                            if base.exists():
                                final_path = base
                        if final_path is None:
                            all_ods = list(outdir.glob('*.ods'))
                            if all_ods:
                                all_ods.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                                final_path = all_ods[0].resolve()
                except Exception:
                    final_path = None

                # Optional rename to custom filename
                if final_path and desired_name:
                    name = desired_name
                    if not name.lower().endswith('.ods'):
                        name += '.ods'
                    dest = (outdir / Path(name).name).resolve()
                    try:
                        if dest.resolve() != final_path.resolve():
                            base = dest.stem
                            ext = dest.suffix
                            parent = dest.parent
                            candidate = dest
                            i = 1
                            while candidate.exists():
                                candidate = parent / f"{base} ({i}){ext}"
                                i += 1
                            try:
                                final_path.rename(candidate)
                                final_path = candidate
                            except Exception:
                                Clock.schedule_once(lambda *_: self._append_log('Warning: failed to rename to the desired name; keeping default.'))
                    except Exception:
                        Clock.schedule_once(lambda *_: self._append_log('Warning: failed to prepare rename; keeping default.'))

            # Finalize on UI thread
            def finalize(_dt=0):
                self.is_busy = False
                if rc == 0 and final_path:
                    self._append_log(f"Done: {final_path}")
                elif rc == 0:
                    self._append_log("Done. Security ODS written to the selected folder.")
                else:
                    code_str = str(rc) if rc is not None else 'unknown'
                    self._append_log(f"Security generation failed (code {code_str}).")
            Clock.schedule_once(finalize)
        except Exception:
            err = traceback.format_exc(limit=5)
            def finalize_err(_dt=0):
                self.is_busy = False
                self._append_log(f"Monitor error (security):\n{err}")
            Clock.schedule_once(finalize_err)
 
    def run_dump_analysis(self) -> None:
        """Start modem log analysis from the selected dump in a background thread."""
        if self.is_dump_running or not self.dump_path:
            return
        self._append_log("Starting Modem Log Analyzer...")
        t = threading.Thread(target=self._worker_dump_start, daemon=True)
        t.start()

    def stop_dump_analysis(self) -> None:
        """Request the running dump analyzer to stop (SIGINT)."""
        proc = self.dump_proc
        if not proc:
            return
        try:
            ok = False
            try:
                ok = proc.send_sigint()
            except Exception:
                ok = False
            self._append_log("Stopping dump analyzer..." + (" (SIGINT sent)" if ok else ""))
        except Exception:
            self._append_log('Failed to send stop signal (dump).')

    def run_pcap_generation(self) -> None:
        """Generate an ODS from the selected PCAP in a background thread."""
        if not self.pcap_path:
            return
        self.is_busy = True
        self._append_log(f"Processing PCAP: {self.pcap_path}")
        t = threading.Thread(target=self._worker_pcap, daemon=True)
        t.start()

    def run_live_generation(self) -> None:
        """Start SCAT live capture in a background thread."""
        if self.is_live_running:
            return
        self._append_log("Starting Live Capture...")
        t = threading.Thread(target=self._worker_live_start, daemon=True)
        t.start()

    def stop_live_capture(self) -> None:
        """Request the running live capture to stop (SIGINT)."""
        proc = self.live_proc
        if not proc:
            return
        try:
            ok = False
            try:
                ok = proc.send_sigint()
            except Exception:
                ok = False
            self._append_log("Stopping live capture..." + (" (SIGINT sent)" if ok else ""))
        except Exception:
            self._append_log('Failed to send stop signal.')

    def _worker_pcap(self) -> None:
        def done(ok: bool, msg: str) -> None:
            self.is_busy = False
            self._append_log(msg)

        try:
            pcap = Path(self.pcap_path)
            outdir = Path(self.pcap_output_dir or self.output_dir)
            outdir.mkdir(parents=True, exist_ok=True)

            # Use the selected output directory directly as CWD; RANVDS.py writes there
            run_cwd = outdir

            # Snapshot existing ODS files
            before = {p.resolve() for p in outdir.glob('*.ods')}

            # Build RANVDS args
            args = ['-p', str(pcap)]
            name = (self.output_name or '').strip()
            expected = None
            if name:
                if not name.lower().endswith('.ods'):
                    name += '.ods'
                expected = (outdir / name).resolve()
                args += ['-o', name]
            if self._pcap_profile:
                args += ['--profile-json', _gui_json.dumps(self._pcap_profile)]

            self._post_log(f"Running: RANVDS {' '.join(args)} (cwd={run_cwd})")
            try:
                rc, out = self._run_ranvds_inprocess(args, run_cwd)
            except Exception:
                err = traceback.format_exc(limit=5)
                Clock.schedule_once(lambda *_: done(False, f"Error running RANVDS:\n{err}"))
                return

            # Stream outputs to log
            if out:
                for line in out.splitlines():
                    self._post_log(line)

            if rc != 0:
                Clock.schedule_once(lambda *_: done(False, f"Failure (code {rc}) processing PCAP."))
                return

            # Try to determine generated ODS path
            new_path = None
            if expected and expected.exists():
                new_path = expected
            else:
                after = {p.resolve() for p in outdir.glob('*.ods')}
                created = list(after - before)
                if created:
                    # choose the most recent
                    created.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                    new_path = created[0]
                    
            # Auto-fill the next section (Security from ODS) with the produced ODS
            if new_path:
                Clock.schedule_once(lambda *_: setattr(self, 'ods_path', str(new_path)))
                # Keep Security output directory aligned to where the ODS was written
                Clock.schedule_once(lambda *_: setattr(self, 'output_dir', str(outdir.resolve())))

            msg = f"Done: {new_path}" if new_path else "Done. ODS file written to the selected folder."
            Clock.schedule_once(lambda *_: done(True, msg))
        except Exception:
            err = traceback.format_exc(limit=5)
            Clock.schedule_once(lambda *_: done(False, f"Error:\n{err}"))


class VDSApp(App):
    """Kivy application for the RANVDS GUI."""

    def build(self):
        """Build the UI and configure default directories and properties."""
        Builder.load_string(KV)
        self.title = 'RANVDS - Radio Access Network Vulnerability Detection System'
        # Try to locate and assign the application icon from system or source paths.
        try:
            icon_path = _find_app_icon()
        except Exception:
            icon_path = None
        if icon_path:
            try:
                self.icon = icon_path
            except Exception:
                # Non-fatal if the window backend does not support custom icons
                pass
        # Set a comfortable initial window size for the tabbed layout
        try:
            Window.minimum_width = 860
            Window.minimum_height = 680
            Window.size = (960, 740)
        except Exception:
            Window.size = (960, 740)
        # Create default folders under a writable data directory
        # Priority:
        # 1) VDS_DATA_DIR (explicit override)
        # 2) /usr/local/share/ranvds if it exists and is writable (system install)
        # 3) XDG_DATA_HOME/ranvds
        # 4) ~/.local/share/ranvds
        env_dir = os.environ.get('VDS_DATA_DIR')
        system_dir = Path('/usr/local/share/ranvds')
        if env_dir:
            base = Path(env_dir)
        elif system_dir.exists() and os.access(system_dir, os.W_OK):
            base = system_dir
        else:
            xdg_home = os.environ.get('XDG_DATA_HOME')
            base = Path(xdg_home) / 'ranvds' if xdg_home else (Path.home() / '.local' / 'share' / 'ranvds')
        pcap_dir = base / 'PCAPs'
        results_dir = base / 'Results'
        pcap_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)

        # Configure defaults
        root = VDSRoot()
        root.live_output_dir = str(pcap_dir.resolve())
        root.dump_output_dir = str(pcap_dir.resolve())
        root.pcap_output_dir = str(results_dir.resolve())
        root.output_dir = str(results_dir.resolve())
        # Seed log so the area is visibly active
        try:
            root._append_log('Ready.')
        except Exception:
            pass
        return root


if __name__ == '__main__':
    VDSApp().run()

