import tkinter as tk
from tkinter import ttk, messagebox


class DashboardUI:
    """Tab showing live statistics tiles and a scrollable scan-history table."""

    def __init__(self, parent, db_manager):
        self.db = db_manager
        self.frame = ttk.Frame(parent)
        self._build()

    def _build(self):
        # ── Statistics tiles ──────────────────────────────────────────────
        stats_frame = ttk.LabelFrame(self.frame, text=" Statistics ", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=(8, 4))

        self._stat_vars = {
            'total':      tk.StringVar(value='0'),
            'safe':       tk.StringVar(value='0'),
            'phishing':   tk.StringVar(value='0'),
            'suspicious': tk.StringVar(value='0'),
        }
        tiles = [
            ('Total Scans', 'total',      '#1976D2'),
            ('Safe',        'safe',       '#388E3C'),
            ('Phishing',    'phishing',   '#D32F2F'),
            ('Suspicious',  'suspicious', '#F57C00'),
        ]
        for col, (label, key, color) in enumerate(tiles):
            stats_frame.columnconfigure(col, weight=1)
            cell = tk.Frame(stats_frame, relief='groove', bd=1, padx=10, pady=6)
            cell.grid(row=0, column=col, padx=6, sticky='ew')
            tk.Label(cell, textvariable=self._stat_vars[key],
                     font=('Arial', 22, 'bold'), fg=color).pack()
            tk.Label(cell, text=label, font=('Arial', 9)).pack()

        # ── Admin action buttons ───────────────────────────────────────────
        admin_frame = ttk.LabelFrame(self.frame, text=" Admin Actions ", padding=8)
        admin_frame.pack(fill='x', padx=10, pady=4)

        ttk.Button(admin_frame, text="Delete Logs > 30 days",
                   command=self._delete_old).pack(side='left', padx=4)
        ttk.Button(admin_frame, text="Clear All Logs",
                   command=self._clear_all).pack(side='left', padx=4)
        ttk.Button(admin_frame, text="⟳  Refresh",
                   command=self.refresh_data).pack(side='right', padx=4)

        # ── Scan-history Treeview ─────────────────────────────────────────
        hist_frame = ttk.LabelFrame(self.frame, text=" Scan History ", padding=5)
        hist_frame.pack(fill='both', expand=True, padx=10, pady=(4, 8))

        cols = ('ID', 'URL', 'Status', 'Confidence', 'Type', 'Timestamp')
        self.tree = ttk.Treeview(hist_frame, columns=cols, show='headings', height=16)
        widths   = [45, 310, 90, 90, 80, 155]
        anchors  = ['center', 'w', 'center', 'center', 'center', 'center']
        for col, w, a in zip(cols, widths, anchors):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=a, stretch=(col == 'URL'))

        self.tree.tag_configure('phishing',   background='#FFEBEE', foreground='#B71C1C')
        self.tree.tag_configure('suspicious', background='#FFF3E0', foreground='#E65100')
        self.tree.tag_configure('safe',       background='#E8F5E9', foreground='#1B5E20')

        vsb = ttk.Scrollbar(hist_frame, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(hist_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        hist_frame.rowconfigure(0, weight=1)
        hist_frame.columnconfigure(0, weight=1)

        self.refresh_data()

    # ── Public API ─────────────────────────────────────────────────────────

    def refresh_data(self):
        stats = self.db.get_stats()
        for key, var in self._stat_vars.items():
            var.set(str(stats[key]))

        for row in self.tree.get_children():
            self.tree.delete(row)

        for log in self.db.get_logs(limit=200):
            log_id, _uid, url, status, confidence, scan_type, timestamp = log
            conf_str = f"{float(confidence):.1%}" if confidence is not None else 'N/A'
            url_disp = (url[:55] + '…') if len(url) > 55 else url
            tag = status.lower() if status.lower() in ('safe', 'phishing', 'suspicious') else ''
            self.tree.insert('', 'end',
                             values=(log_id, url_disp, status.upper(),
                                     conf_str, scan_type, timestamp),
                             tags=(tag,))

    # ── Private helpers ────────────────────────────────────────────────────

    def _delete_old(self):
        n = self.db.delete_old_logs(30)
        messagebox.showinfo("Done", f"Deleted {n} log entr{'y' if n == 1 else 'ies'} older than 30 days.")
        self.refresh_data()

    def _clear_all(self):
        if messagebox.askyesno("Confirm", "Clear ALL scan logs?\nThis cannot be undone."):
            self.db.clear_all_logs()
            self.refresh_data()
