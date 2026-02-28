import tkinter as tk
from tkinter import ttk


class SettingsUI:
    """Tab for monitoring preferences and detection sensitivity."""

    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self._build()

    def _build(self):
        ttk.Label(self.frame, text="SafeClick  Settings",
                  font=('Arial', 14, 'bold')).pack(pady=(18, 6))

        # ── Monitoring section ─────────────────────────────────────────────
        mon = ttk.LabelFrame(self.frame, text=" Monitoring ", padding=12)
        mon.pack(fill='x', padx=24, pady=8)

        self._auto_monitor = tk.BooleanVar(value=True)
        ttk.Checkbutton(mon, text="Enable automatic clipboard monitoring",
                        variable=self._auto_monitor,
                        command=self._toggle_monitor).pack(anchor='w')

        self._notify_phishing = tk.BooleanVar(value=True)
        ttk.Checkbutton(mon, text="Show desktop notifications for phishing / suspicious URLs",
                        variable=self._notify_phishing).pack(anchor='w', pady=(4, 0))

        self._notify_safe = tk.BooleanVar(value=False)
        ttk.Checkbutton(mon, text="Show desktop notifications for safe URLs",
                        variable=self._notify_safe).pack(anchor='w')

        # ── Sensitivity section ────────────────────────────────────────────
        sens = ttk.LabelFrame(self.frame, text=" Detection Sensitivity ", padding=12)
        sens.pack(fill='x', padx=24, pady=8)

        ttk.Label(sens, text="Confidence threshold to flag a URL as phishing:").pack(anchor='w')

        self._threshold = tk.DoubleVar(value=0.70)
        self._thresh_lbl = ttk.Label(sens, text="70%", font=('Arial', 10, 'bold'))

        scale = ttk.Scale(sens, from_=0.50, to=0.99, orient='horizontal',
                          variable=self._threshold, length=260,
                          command=lambda v: self._thresh_lbl.config(
                              text=f"{float(v):.0%}"))
        scale.pack(anchor='w', pady=(4, 2))
        self._thresh_lbl.pack(anchor='w')

        # ── About section ──────────────────────────────────────────────────
        about = ttk.LabelFrame(self.frame, text=" About ", padding=12)
        about.pack(fill='x', padx=24, pady=8)

        for line in (
            "SafeClick v1.0.0  –  Intelligent Phishing Detection Tool",
            "Bhoj Reddy Engineering College for Women",
            "Department of Computer Science and Engineering",
            "",
            "Tech stack: Python 3 · Tkinter · Scikit-learn · SQLite · Plyer",
        ):
            ttk.Label(about, text=line).pack(anchor='w')

    # ── Public API ─────────────────────────────────────────────────────────

    def get_settings(self) -> dict:
        return {
            'auto_monitor':     self._auto_monitor.get(),
            'notify_phishing':  self._notify_phishing.get(),
            'notify_safe':      self._notify_safe.get(),
            'threshold':        self._threshold.get(),
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    def _toggle_monitor(self):
        if hasattr(self.app, 'monitor'):
            if self._auto_monitor.get():
                self.app.monitor.start_monitoring()
            else:
                self.app.monitor.stop()
