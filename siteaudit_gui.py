#!/usr/bin/env python3
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import siteaudit

GRADE_COLORS = {"A": "#15803d", "B": "#4d7c0f", "C": "#a16207", "D": "#c2410c", "F": "#b91c1c"}
MUTED = "#6b7280"
SHORT = {"high": "high", "medium": "med", "low": "low", "info": "info"}

ROW_TAGS = {
    "high": {"background": "#fbe9e7", "foreground": "#7f1d1d"},
    "medium": {"background": "#fdf3d8", "foreground": "#713f12"},
    "low": {"background": "#e8f0fb", "foreground": "#1e3a8a"},
    "info": {"background": "#f4f4f5", "foreground": "#3f3f46"},
}


class App:
    def __init__(self, root):
        self.root = root
        self.result = None
        self.findings = []
        self.stop_event = threading.Event()
        self.events = queue.Queue()
        self.started_at = 0.0

        root.title("siteaudit — made by exovmiscoding")
        root.geometry("1060x720")
        root.minsize(780, 520)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Muted.TLabel", foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Toolbutton", padding=(9, 3))

        self.url_var = tk.StringVar(value="https://")
        self.auth_var = tk.BooleanVar(value=False)
        self.filter_var = tk.StringVar(value="")
        self.sev_var = tk.StringVar(value="all")
        self.status_var = tk.StringVar(value="Ready.")
        self.summary_var = tk.StringVar(value="")
        self.timeout_var = tk.StringVar(value="10")
        self.delay_var = tk.StringVar(value="0.25")
        self.maxreq_var = tk.StringVar(value="60")
        self.insecure_var = tk.BooleanVar(value=False)
        self.options_open = False

        self._build()

    def _build(self):
        outer = ttk.Frame(self.root, padding=(14, 12, 14, 10))
        outer.pack(fill="both", expand=True)

        bar = ttk.Frame(outer)
        bar.pack(fill="x")
        self.url_entry = ttk.Entry(bar, textvariable=self.url_var, font=("Consolas", 11))
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.run_btn = ttk.Button(bar, text="Audit", command=self._start, width=10)
        self.run_btn.pack(side="left", padx=(8, 0))
        self.cancel_btn = ttk.Button(
            bar, text="Cancel", command=self._cancel, width=9, state="disabled"
        )
        self.cancel_btn.pack(side="left", padx=(6, 0))
        self.options_btn = ttk.Button(
            bar, text="Options", command=self._toggle_options, width=10
        )
        self.options_btn.pack(side="left", padx=(6, 0))

        opts = ttk.Frame(outer)
        self.options_frame = opts
        ttk.Label(opts, text="Timeout").pack(side="left")
        ttk.Spinbox(opts, from_=1, to=120, width=4, textvariable=self.timeout_var).pack(
            side="left", padx=(4, 12)
        )
        ttk.Label(opts, text="Delay").pack(side="left")
        ttk.Spinbox(
            opts, from_=0.1, to=10, increment=0.05, width=4, textvariable=self.delay_var
        ).pack(side="left", padx=(4, 12))
        ttk.Label(opts, text="Requests").pack(side="left")
        ttk.Spinbox(opts, from_=10, to=200, width=4, textvariable=self.maxreq_var).pack(
            side="left", padx=(4, 16)
        )
        ttk.Checkbutton(
            opts, text="Skip TLS verification", variable=self.insecure_var
        ).pack(side="left")

        self.auth_row = ttk.Frame(outer)
        self.auth_row.pack(fill="x", pady=(8, 10))
        ttk.Checkbutton(
            self.auth_row,
            text="I own this site or have permission to test it",
            variable=self.auth_var,
        ).pack(side="left")

        filter_row = ttk.Frame(outer)
        filter_row.pack(fill="x", pady=(0, 10))
        self.filter_entry = ttk.Entry(filter_row, textvariable=self.filter_var, width=28)
        self.filter_entry.pack(side="left", ipady=2)
        self.filter_var.trace_add("write", lambda *_a: self._render())
        ttk.Label(filter_row, text="filter", style="Muted.TLabel").pack(
            side="left", padx=(6, 14)
        )
        self.sev_buttons = {}
        for sev in ["all"] + list(siteaudit.SEVERITIES):
            btn = ttk.Radiobutton(
                filter_row,
                text=sev,
                value=sev,
                variable=self.sev_var,
                style="Toolbutton",
                command=self._render,
            )
            btn.pack(side="left", padx=(0, 4))
            self.sev_buttons[sev] = btn

        head = ttk.Frame(outer)
        head.pack(fill="x", pady=(0, 8))
        self.grade_label = ttk.Label(
            head, textvariable=self.summary_var, font=("Segoe UI", 12, "bold"), foreground=MUTED
        )
        self.grade_label.pack(side="left")

        panes = ttk.Panedwindow(outer, orient="vertical")
        panes.pack(fill="both", expand=True)

        table_wrap = ttk.Frame(panes)
        self.tree = ttk.Treeview(
            table_wrap, columns=("severity", "title"), show="headings", selectmode="browse"
        )
        self.tree.heading("severity", text="Severity", anchor="w")
        self.tree.heading("title", text="Finding", anchor="w")
        self.tree.column("severity", width=96, anchor="w", stretch=False)
        self.tree.column("title", width=820, anchor="w")
        for sev, colors in ROW_TAGS.items():
            self.tree.tag_configure(sev, **colors)
        scroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        panes.add(table_wrap, weight=3)

        detail_wrap = ttk.Frame(panes)
        self.detail = tk.Text(
            detail_wrap,
            wrap="word",
            height=11,
            font=("Consolas", 9),
            padx=10,
            pady=9,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#d4d4d8",
        )
        detail_scroll = ttk.Scrollbar(detail_wrap, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set, state="disabled")
        self.detail.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")
        panes.add(detail_wrap, weight=2)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=140)
        self.progress.pack(side="left")
        ttk.Label(bottom, textvariable=self.status_var, style="Muted.TLabel").pack(
            side="left", padx=(10, 0)
        )
        ttk.Label(bottom, text=siteaudit.CREDIT, style="Muted.TLabel").pack(side="right")
        self.export_json_btn = ttk.Button(
            bottom, text="JSON", command=self._export_json, width=8, state="disabled"
        )
        self.export_json_btn.pack(side="right")
        self.export_md_btn = ttk.Button(
            bottom, text="Markdown", command=self._export_md, width=10, state="disabled"
        )
        self.export_md_btn.pack(side="right", padx=(0, 6))
        self.copy_btn = ttk.Button(
            bottom, text="Copy", command=self._copy, width=8, state="disabled"
        )
        self.copy_btn.pack(side="right", padx=(0, 6))

        self.url_entry.bind("<Return>", lambda _event: self._start())
        self.root.bind("<Escape>", lambda _event: self._cancel())
        self.root.bind("<Control-f>", lambda _event: self._focus_filter())
        self.root.bind("<Control-e>", lambda _event: self._export_json())
        self.root.bind("<Control-Shift-M>", lambda _event: self._export_md())
        self.root.bind("<Control-Shift-m>", lambda _event: self._export_md())
        self.url_entry.focus_set()
        self.root.after(100, self._poll)

    def _focus_filter(self):
        self.filter_entry.focus_set()
        self.filter_entry.select_range(0, "end")
        return "break"

    def _toggle_options(self):
        self.options_open = not self.options_open
        if self.options_open:
            self.options_frame.pack(fill="x", pady=(8, 2), before=self.auth_row)
        else:
            self.options_frame.pack_forget()
        self.options_btn.configure(text="Hide" if self.options_open else "Options")

    def _options(self):
        try:
            timeout = float(self.timeout_var.get())
            delay = float(self.delay_var.get())
            max_requests = int(self.maxreq_var.get())
        except ValueError:
            messagebox.showerror("siteaudit", "Timeout, delay and requests must be numbers.")
            return None
        if timeout <= 0 or delay < 0 or max_requests < 10:
            messagebox.showerror("siteaudit", "Use a positive timeout, delay >= 0, requests >= 10.")
            return None
        return {
            "timeout": timeout,
            "delay": delay,
            "max_requests": max_requests,
            "insecure": self.insecure_var.get(),
        }

    def _start(self):
        url = self.url_var.get().strip()
        if not url or url in ("https://", "http://"):
            messagebox.showwarning("siteaudit", "Enter a target URL.")
            return
        if not self.auth_var.get():
            messagebox.showwarning("siteaudit", "Confirm you own the site or have permission.")
            return
        opts = self._options()
        if opts is None:
            return

        self.tree.delete(*self.tree.get_children())
        self._set_detail("")
        self.findings = []
        self.result = None
        self.sev_var.set("all")
        self.summary_var.set("Auditing…")
        self.grade_label.configure(foreground=MUTED)
        self.status_var.set(url)
        self.copy_btn.configure(state="disabled")
        self.export_json_btn.configure(state="disabled")
        self.export_md_btn.configure(state="disabled")
        self.run_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.start(12)
        self.stop_event.clear()
        self.started_at = time.monotonic()

        threading.Thread(target=self._worker, args=(url, opts), daemon=True).start()

    def _worker(self, url, opts):
        try:
            result = siteaudit.run_audit(
                url,
                timeout=opts["timeout"],
                delay=opts["delay"],
                max_requests=opts["max_requests"],
                insecure=opts["insecure"],
                progress=lambda message: self.events.put(("status", message)),
                should_stop=self.stop_event.is_set,
            )
        except siteaudit.TargetError as e:
            self.events.put(("error", str(e)))
        except Exception as e:
            self.events.put(("error", "%s: %s" % (type(e).__name__, e)))
        else:
            self.events.put(("done", result))

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "error":
                    self._finish()
                    self.status_var.set("Failed.")
                    self.summary_var.set("")
                    messagebox.showerror("siteaudit", payload)
                elif kind == "done":
                    self._finish()
                    self._show_result(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _finish(self):
        self.progress.stop()
        self.run_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")

    def _show_result(self, result):
        self.result = result
        if result.error:
            self.status_var.set(result.error)
            self.summary_var.set("")
            return
        ordered = siteaudit.sort_findings(result.audit.findings)
        self.findings = ordered
        c = siteaudit.counts(ordered)
        letter, score = siteaudit.grade(ordered)
        self.summary_var.set(
            "%s  %d/100     %d high · %d medium · %d low · %d info"
            % (letter, score, c["high"], c["medium"], c["low"], c["info"])
        )
        self.grade_label.configure(foreground=GRADE_COLORS.get(letter, MUTED))
        self._update_chips(ordered, c)
        self.sev_var.set("all")
        self._render()
        self.status_var.set(
            "%s — %d requests, %.1fs%s"
            % (
                result.target,
                result.audit.client.count,
                time.monotonic() - self.started_at,
                " (cancelled)" if result.cancelled else "",
            )
        )
        for button in (self.copy_btn, self.export_json_btn, self.export_md_btn):
            button.configure(state="normal")

    def _update_chips(self, ordered, c):
        self.sev_buttons["all"].configure(text="all %d" % len(ordered))
        for sev in siteaudit.SEVERITIES:
            self.sev_buttons[sev].configure(text="%s %d" % (SHORT[sev], c[sev]))

    def _render(self):
        self.tree.delete(*self.tree.get_children())
        if self.result is None or self.result.error:
            return
        query = self.filter_var.get().strip().lower()
        sev = self.sev_var.get()
        shown = 0
        for index, f in enumerate(self.findings):
            if sev != "all" and f.severity != sev:
                continue
            if query and query not in (f.title + " " + f.detail + " " + f.evidence).lower():
                continue
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(siteaudit.SEV_LABEL[f.severity], f.title),
                tags=(f.severity,),
            )
            shown += 1
        if not shown:
            self.tree.insert("", "end", iid="none", values=("—", "nothing matches"), tags=("info",))
            self._set_detail("")
        else:
            self._select_first()

    def _select_first(self):
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])

    def _show_detail(self, _event=None):
        selection = self.tree.selection()
        if not selection or not selection[0].isdigit():
            self._set_detail("")
            return
        index = int(selection[0])
        if index >= len(self.findings):
            return
        f = self.findings[index]
        lines = [
            "[%s] %s" % (siteaudit.SEV_LABEL[f.severity], f.title),
            "",
            f.detail.strip(),
        ]
        if f.evidence:
            lines += ["", "Evidence:", f.evidence]
        if f.remediation:
            lines += ["", "Fix:", f.remediation]
        self._set_detail("\n".join(lines))

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _cancel(self):
        if str(self.cancel_btn["state"]) != "normal":
            return
        self.stop_event.set()
        self.status_var.set("Cancelling…")

    def _copy(self):
        if not self.result or self.result.error:
            return
        lines = [self.result.target, self.summary_var.get(), ""]
        lines += [
            "[%s] %s" % (siteaudit.SEV_LABEL[f.severity], f.title) for f in self.findings
        ]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set("Copied to clipboard.")

    def _export_json(self):
        if not self.result or self.result.error:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")], title="Save JSON report"
        )
        if path:
            siteaudit.write_json(path, self.result)
            self.status_var.set("Saved " + path)

    def _export_md(self):
        if not self.result or self.result.error:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".md", filetypes=[("Markdown", "*.md")], title="Save Markdown report"
        )
        if path:
            siteaudit.write_markdown(path, self.result)
            self.status_var.set("Saved " + path)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
