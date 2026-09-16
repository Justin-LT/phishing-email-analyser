#!/usr/bin/env python3
"""Desktop GUI for the phishing email analyser.

Built with tkinter, which comes bundled with Python on Windows and Mac, so
there's nothing extra to install for this on top of Python itself. Choose
a .eml file, pick a checking mode, and it shows the same findings as the
command line tool, just laid out for someone who'd rather not open a
terminal.
"""

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from analyser import api_key_store, contacts, reputation
from analyser.parser import get_body_text_and_html, load_email
from analyser.report import write_html_report
from analyser.scoring import risk_category, run_checks

BACKGROUND = "#1e1f26"
PANEL = "#2a2c36"
CONSOLE = "#15161c"
TEXT_COLOUR = "#e6e6e6"
MUTED_COLOUR = "#9a9ca8"
ACCENT = "#4f8cff"
RISK_COLOURS = {"Low": "#2e7d32", "Medium": "#b8860b", "High": "#c62828"}


class PhishingAnalyserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Analyser")
        self.root.geometry("780x660")
        self.root.minsize(680, 560)
        self.root.configure(bg=BACKGROUND)

        self.current_path = None
        self.last_result = None  # (subject, sender, findings, score, category)
        self.result_queue = queue.Queue()

        self._build_style()
        self._build_layout()
        self._load_saved_key()
        self._load_saved_contacts()
        self._poll_queue()

    # -- layout -----------------------------------------------------

    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=BACKGROUND)
        style.configure("TLabelframe", background=BACKGROUND, foreground=TEXT_COLOUR)
        style.configure("TLabelframe.Label", background=BACKGROUND, foreground=MUTED_COLOUR, font=("Segoe UI", 9, "bold"))
        style.configure("TLabel", background=BACKGROUND, foreground=TEXT_COLOUR, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BACKGROUND, foreground=MUTED_COLOUR, font=("Segoe UI", 9))
        style.configure("Heading.TLabel", background=BACKGROUND, foreground=TEXT_COLOUR, font=("Segoe UI", 17, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8, background=ACCENT, foreground="white")
        style.map("Accent.TButton", background=[("active", "#3f74d1"), ("disabled", "#3a3d4a")])
        style.configure("TRadiobutton", background=BACKGROUND, foreground=TEXT_COLOUR, font=("Segoe UI", 10))
        style.map("TRadiobutton", background=[("active", BACKGROUND)])
        style.configure("TEntry", padding=4)

    def _build_layout(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=24, pady=(22, 6))
        ttk.Label(header, text="Phishing Email Analyser", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(header, text="Check a saved email for the usual phishing tells.", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

        file_frame = ttk.Frame(self.root)
        file_frame.pack(fill="x", padx=24, pady=14)
        self.file_label = ttk.Label(file_frame, text="No file selected", wraplength=520)
        self.file_label.pack(side="left", fill="x", expand=True)
        ttk.Button(file_frame, text="Choose .eml file...", command=self.choose_file).pack(side="right")

        mode_frame = ttk.LabelFrame(self.root, text="CHECKING MODE")
        mode_frame.pack(fill="x", padx=24, pady=(0, 12))
        self.mode = tk.StringVar(value="offline")
        ttk.Radiobutton(
            mode_frame, text="Quick check — offline heuristics only",
            variable=self.mode, value="offline",
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ttk.Radiobutton(
            mode_frame, text="Full check — heuristics plus a VirusTotal lookup on every link",
            variable=self.mode, value="online",
        ).pack(anchor="w", padx=12, pady=(2, 10))

        key_frame = ttk.LabelFrame(self.root, text="VIRUSTOTAL API KEY  (only needed for the full check)")
        key_frame.pack(fill="x", padx=24, pady=(0, 12))
        key_row = ttk.Frame(key_frame)
        key_row.pack(fill="x", padx=12, pady=(10, 4))
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_row, textvariable=self.key_var, show="*", width=42)
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="Save", command=self.save_key).pack(side="left", padx=(8, 0))
        ttk.Button(key_row, text="Clear", command=self.clear_key).pack(side="left", padx=(6, 0))
        ttk.Label(
            key_frame,
            text="Saved locally on this computer only. Get a free key at virustotal.com/gui/join-us",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=12, pady=(0, 10))

        contacts_frame = ttk.LabelFrame(self.root, text="KNOWN CONTACTS  (optional, catches someone impersonating a specific person)")
        contacts_frame.pack(fill="x", padx=24, pady=(0, 12))
        contacts_row = ttk.Frame(contacts_frame)
        contacts_row.pack(fill="x", padx=12, pady=(10, 4))
        self.contact_name_var = tk.StringVar()
        self.contact_domain_var = tk.StringVar()
        ttk.Entry(contacts_row, textvariable=self.contact_name_var, width=20).pack(side="left")
        ttk.Label(contacts_row, text="  really sends from  ").pack(side="left")
        ttk.Entry(contacts_row, textvariable=self.contact_domain_var, width=20).pack(side="left")
        ttk.Button(contacts_row, text="Add", command=self.add_contact).pack(side="left", padx=(8, 0))
        ttk.Button(contacts_row, text="Remove selected", command=self.remove_contact).pack(side="left", padx=(6, 0))

        self.contacts_list = tk.Listbox(
            contacts_frame, height=3, bg=CONSOLE, fg=TEXT_COLOUR,
            font=("Consolas", 9), relief="flat", highlightthickness=0,
        )
        self.contacts_list.pack(fill="x", padx=12, pady=(4, 4))
        ttk.Label(
            contacts_frame,
            text="e.g. name: Jane Smith, domain: yourcompany.com. A display name matching this "
                 "but sent from anywhere else is flagged strongly.",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=12, pady=(0, 10))

        action_frame = ttk.Frame(self.root)
        action_frame.pack(fill="x", padx=24, pady=(0, 10))
        self.analyse_button = ttk.Button(action_frame, text="Analyse email", command=self.run_analysis, style="Accent.TButton")
        self.analyse_button.pack(side="left")
        self.export_button = ttk.Button(action_frame, text="Save HTML report...", command=self.export_html, state="disabled")
        self.export_button.pack(side="left", padx=(10, 0))
        self.status_label = ttk.Label(action_frame, text="", style="Muted.TLabel")
        self.status_label.pack(side="left", padx=(14, 0))

        result_frame = tk.Frame(self.root, bg=PANEL)
        result_frame.pack(fill="both", expand=True, padx=24, pady=(0, 22))

        self.risk_banner = tk.Label(
            result_frame, text="No email analysed yet",
            font=("Segoe UI", 13, "bold"), bg=PANEL, fg=TEXT_COLOUR, pady=12,
        )
        self.risk_banner.pack(fill="x")

        self.results_text = tk.Text(
            result_frame, bg=CONSOLE, fg=TEXT_COLOUR, insertbackground=TEXT_COLOUR,
            font=("Consolas", 10), wrap="word", relief="flat", padx=12, pady=12, borderwidth=0,
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.results_text.configure(state="disabled")

    # -- API key handling ---------------------------------------------

    def _load_saved_key(self):
        saved = api_key_store.load_key()
        if saved:
            self.key_var.set(saved)

    def save_key(self):
        key = self.key_var.get().strip()
        if not key:
            messagebox.showwarning("No key entered", "Type a VirusTotal API key before saving.")
            return
        api_key_store.save_key(key)
        self.status_label.configure(text="API key saved.")

    def clear_key(self):
        api_key_store.clear_key()
        self.key_var.set("")
        self.status_label.configure(text="API key cleared.")

    # -- known contacts ----------------------------------------------

    def _load_saved_contacts(self):
        self.contacts_list.delete(0, "end")
        for name, domain in sorted(contacts.load_contacts().items()):
            self.contacts_list.insert("end", f"{name}  →  {domain}")

    def add_contact(self):
        name = self.contact_name_var.get().strip()
        domain = self.contact_domain_var.get().strip()
        if not name or not domain:
            messagebox.showwarning("Missing details", "Enter both a name and the domain they send from.")
            return
        contacts.add_contact(name, domain)
        self.contact_name_var.set("")
        self.contact_domain_var.set("")
        self._load_saved_contacts()
        self.status_label.configure(text=f"Added {name}.")

    def remove_contact(self):
        selection = self.contacts_list.curselection()
        if not selection:
            messagebox.showwarning("Nothing selected", "Select a contact in the list first.")
            return
        entry = self.contacts_list.get(selection[0])
        name = entry.split("→")[0].strip()
        contacts.remove_contact(name)
        self._load_saved_contacts()
        self.status_label.configure(text=f"Removed {name}.")

    # -- file handling -------------------------------------------------

    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Choose an email file",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
        )
        if path:
            self.current_path = path
            self.file_label.configure(text=Path(path).name)

    # -- analysis --------------------------------------------------------

    def run_analysis(self):
        if not self.current_path:
            messagebox.showwarning("No file chosen", "Choose a .eml file first.")
            return

        wants_online = self.mode.get() == "online"
        typed_key = self.key_var.get().strip()

        if wants_online and not typed_key and not reputation.is_configured():
            messagebox.showwarning(
                "No API key",
                "The full check needs a VirusTotal API key. Enter and save one, "
                "or switch to the quick check.",
            )
            return

        # A key typed but not yet saved still gets used for this one run.
        if wants_online and typed_key:
            os.environ["VT_API_KEY"] = typed_key

        self.analyse_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.status_label.configure(text="Analysing, this may take a few seconds..." if wants_online else "Analysing...")
        self._clear_results()

        threading.Thread(target=self._analyse_worker, args=(wants_online,), daemon=True).start()

    def _clear_results(self):
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.configure(state="disabled")
        self.risk_banner.configure(text="Working...", bg=PANEL, fg=TEXT_COLOUR)

    def _analyse_worker(self, use_reputation):
        # Runs on a background thread, so it must never touch tkinter
        # widgets directly, everything it finds goes on the queue and the
        # main thread (via _poll_queue) is what actually updates the UI.
        try:
            msg = load_email(self.current_path)
            text_body, html_body = get_body_text_and_html(msg)
            findings, score = run_checks(msg, text_body, html_body, use_reputation=use_reputation)
            category = risk_category(score)
            subject = msg.get("Subject", "(no subject)")
            sender = msg.get("From", "(unknown sender)")
            result = (subject, sender, findings, score, category)
            self.result_queue.put(("result", result, use_reputation))
        except Exception as error:  # a bad file shouldn't crash the app
            self.result_queue.put(("error", error, use_reputation))

    def _poll_queue(self):
        # Runs on the main thread only, scheduled via root.after so it's
        # safe to touch widgets here.
        try:
            while True:
                kind, payload, used_reputation = self.result_queue.get_nowait()
                if kind == "result":
                    self.last_result = payload
                    self._show_result(used_reputation)
                else:
                    self._show_error(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _show_result(self, used_reputation):
        subject, sender, findings, score, category = self.last_result
        colour = RISK_COLOURS[category]
        self.risk_banner.configure(text=f"{category} risk   —   {score}/100", bg=colour, fg="white")

        self.results_text.configure(state="normal")
        self.results_text.insert("end", f"Subject: {subject}\n")
        self.results_text.insert("end", f"From: {sender}\n\n")

        if not findings:
            self.results_text.insert("end", "No red flags found by these checks.\n")
            self.results_text.insert("end", "That's not the same as safe, it just means nothing here tripped a rule.\n")
        else:
            for description, weight in sorted(findings, key=lambda f: -f[1]):
                self.results_text.insert("end", f"[+{weight:>2}]   {description}\n")

        if used_reputation and not reputation.is_configured():
            self.results_text.insert("end", "\n(VirusTotal lookups skipped, no API key available)\n")

        self.results_text.configure(state="disabled")
        self.analyse_button.configure(state="normal")
        self.export_button.configure(state="normal")
        self.status_label.configure(text="Done.")

    def _show_error(self, error):
        messagebox.showerror("Something went wrong", str(error))
        self.risk_banner.configure(text="No email analysed yet", bg=PANEL, fg=TEXT_COLOUR)
        self.analyse_button.configure(state="normal")
        self.status_label.configure(text="Failed, see the error message.")

    # -- export -----------------------------------------------------------

    def export_html(self):
        if not self.last_result:
            return
        subject, sender, findings, score, category = self.last_result
        path = filedialog.asksaveasfilename(
            title="Save HTML report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
            initialfile="phishing_report.html",
        )
        if path:
            write_html_report(path, subject, sender, findings, score, category)
            self.status_label.configure(text=f"Report saved to {Path(path).name}")


def main():
    root = tk.Tk()
    PhishingAnalyserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
