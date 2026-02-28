"""
SafeClick – Intelligent Phishing Detection Tool
Entry point: python main.py
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Ensure the project root is on sys.path for all imports
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.database import DatabaseManager
from core.monitor import ClipboardMonitor
from core.notifier import NotificationManager
from gui.dashboard import DashboardUI
from gui.settings import SettingsUI


class SafeClickApp:
    # ── Colours ──────────────────────────────────────────────────────────
    _BLUE   = '#1565C0'
    _TEAL   = '#00BCD4'
    _BG_BAR = '#E3F2FD'

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SafeClick – Intelligent Phishing Detection")
        self.root.geometry("960x680")
        self.root.minsize(820, 600)
        self.root.configure(bg='white')

        self.db       = DatabaseManager()
        self.notifier = NotificationManager()
        self.classifier = None   # loaded asynchronously

        self._build_header()
        self._build_scan_bar()
        self._show_loading_overlay()

        # Load classifier in background so the window appears immediately
        self.root.after(120, self._start_classifier_load)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=self._BLUE, height=54)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡  SafeClick",
                 font=('Arial', 17, 'bold'),
                 bg=self._BLUE, fg='white').pack(side='left', padx=16, pady=8)

        self._status_var = tk.StringVar(value="⏳  Loading…")
        tk.Label(hdr, textvariable=self._status_var,
                 font=('Arial', 10),
                 bg=self._BLUE, fg='#B3E5FC').pack(side='right', padx=16)

    def _build_scan_bar(self):
        bar = tk.Frame(self.root, bg=self._BG_BAR, pady=6)
        bar.pack(fill='x')

        inner = tk.Frame(bar, bg=self._BG_BAR)
        inner.pack(fill='x', padx=12)

        tk.Label(inner, text="Scan URL:", font=('Arial', 10),
                 bg=self._BG_BAR).pack(side='left')

        self._url_entry = ttk.Entry(inner, width=58, font=('Arial', 10))
        self._url_entry.pack(side='left', padx=8)
        self._url_entry.bind('<Return>', lambda _e: self._manual_scan())

        ttk.Button(inner, text="Scan", command=self._manual_scan).pack(side='left')

        self._result_var = tk.StringVar()
        self._result_lbl = tk.Label(inner, textvariable=self._result_var,
                                    font=('Arial', 10, 'bold'), bg=self._BG_BAR)
        self._result_lbl.pack(side='left', padx=10)

    def _show_loading_overlay(self):
        self._overlay = tk.Frame(self.root, bg='white')
        self._overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        tk.Label(self._overlay,
                 text="Loading SafeClick…\n(Training ML model on first run – please wait)",
                 font=('Arial', 13), bg='white', fg='#555').pack(expand=True)

    def _build_notebook(self):
        """Called after classifier is ready."""
        self._overlay.destroy()

        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=6, pady=6)

        self.dashboard  = DashboardUI(nb, self.db)
        self.settings_ui = SettingsUI(nb, self)

        nb.add(self.dashboard.frame,   text='  Dashboard  ')
        nb.add(self.settings_ui.frame, text='  Settings  ')

    # ── Classifier loading ────────────────────────────────────────────────

    def _start_classifier_load(self):
        threading.Thread(target=self._load_classifier, daemon=True).start()

    def _load_classifier(self):
        from core.classifier import URLClassifier
        self.classifier = URLClassifier()
        self.root.after(0, self._on_classifier_ready)

    def _on_classifier_ready(self):
        self._build_notebook()
        self.monitor = ClipboardMonitor(self._on_url_detected)
        self.monitor.start_monitoring()
        self._status_var.set("●  Monitoring Active")
        # re-colour status label green
        for w in self.root.winfo_children():
            if isinstance(w, tk.Frame) and w.cget('bg') == self._BLUE:
                for lbl in w.winfo_children():
                    if isinstance(lbl, tk.Label) and \
                            lbl.cget('textvariable') == str(self._status_var):
                        lbl.config(fg='#69F0AE')

    # ── URL scanning ──────────────────────────────────────────────────────

    def _on_url_detected(self, url: str):
        """Called from ClipboardMonitor daemon thread."""
        if self.classifier is None:
            return
        status, conf = self.classifier.predict(url)
        self.db.insert_log(url, status, conf, scan_type='automatic')

        settings = self.settings_ui.get_settings() if hasattr(self, 'settings_ui') else {}
        if settings.get('notify_phishing', True) and status in ('phishing', 'suspicious'):
            if status == 'phishing':
                self.notifier.show_alert(url, conf)
            else:
                self.notifier.show_suspicious(url, conf)
        elif settings.get('notify_safe', False) and status == 'safe':
            self.notifier.show_safe(url, conf)

        self.root.after(0, self._refresh_dashboard)

    def _manual_scan(self):
        if self.classifier is None:
            messagebox.showinfo("Not Ready", "ML model is still loading, please wait.")
            return
        raw = self._url_entry.get().strip()
        if not raw:
            messagebox.showwarning("Input required", "Please enter a URL to scan.")
            return

        url = raw if raw.startswith(('http://', 'https://')) else 'https://' + raw
        status, conf = self.classifier.predict(url)
        self.db.insert_log(url, status, conf, scan_type='manual')

        _colors = {'safe': '#2E7D32', 'phishing': '#C62828', 'suspicious': '#E65100'}
        _icons  = {'safe': '✓ SAFE', 'phishing': '⚠ PHISHING', 'suspicious': '⚠ SUSPICIOUS'}

        self._result_var.set(f"{_icons.get(status, status.upper())}  ({conf:.1%})")
        self._result_lbl.config(fg=_colors.get(status, 'black'))
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        if hasattr(self, 'dashboard'):
            self.dashboard.refresh_data()

    # ── App lifecycle ─────────────────────────────────────────────────────

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        if hasattr(self, 'monitor'):
            self.monitor.stop()
        self.root.destroy()


def main():
    SafeClickApp().run()


if __name__ == '__main__':
    main()
