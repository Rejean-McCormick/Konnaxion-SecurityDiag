from __future__ import annotations

import queue
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from securitydiag_recovery.core import (
    ATTESTATION_KEYS,
    RecoveryError,
    create_backup,
    current_release_attestations,
    default_offsite_dir,
    isolated_restore_drill,
    preflight,
    record_release_attestations,
    run_securitydiag_release,
)

TOOL_ROOT = Path(__file__).resolve().parent
LABELS = {
    "fresh_vps": "Fresh VPS created from a trusted provider image",
    "old_disk_not_cloned": "Old compromised disk/snapshot was not cloned",
    "all_compromised_secrets_rotated": "All potentially compromised secrets were rotated",
    "clean_git_source_only": "Deployment used clean Git source only",
    "cloud_firewall_verified": "Cloud/provider firewall was independently verified",
    "old_vps_retired_or_isolated": "Old VPS was retired or isolated",
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Konnaxion Recovery Drill Assistant")
        self.geometry("980x720")
        self.minsize(860, 620)
        self.q: queue.Queue[tuple[str, object]] = queue.Queue()
        self.busy = False
        self.offsite = tk.StringVar(value=str(default_offsite_dir()))
        self.status = tk.StringVar(value="Ready")
        self._build()
        self.after(100, self._pump)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Off-server backup destination:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.offsite, width=78).grid(row=0, column=1, padx=8, sticky="ew")
        ttk.Button(top, text="Browse...", command=self._browse).grid(row=0, column=2)
        top.columnconfigure(1, weight=1)

        actions = ttk.Frame(self, padding=(10, 0, 10, 10))
        actions.pack(fill="x")
        self.buttons = []
        for text, fn in [
            ("1. Preflight", self.do_preflight),
            ("2. Backup + off-server copy", self.do_backup),
            ("3. Isolated restore drill", self.do_restore),
            ("4. Human release attestations", self.open_attestations),
            ("5. Run SecurityDiag Release", self.do_release),
        ]:
            b = ttk.Button(actions, text=text, command=fn)
            b.pack(side="left", padx=(0, 7))
            self.buttons.append(b)

        note = (
            "Operational safety: the drill uses temporary Docker resources on an internal-only network and never restores into the production database. "
            "Production backup data copied off-server is sensitive; choose a protected destination outside both Git repositories."
        )
        ttk.Label(self, text=note, wraplength=930, padding=(10, 0, 10, 8)).pack(fill="x")

        self.log = ScrolledText(self, height=28, wrap="word")
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=5).pack(fill="x")

    def _browse(self):
        path = filedialog.askdirectory(initialdir=self.offsite.get() or str(Path.home()))
        if path:
            self.offsite.set(path)

    def _set_busy(self, value: bool):
        self.busy = value
        for b in self.buttons:
            b.configure(state="disabled" if value else "normal")

    def _log(self, message: str):
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")

    def _worker(self, label, fn):
        if self.busy:
            return
        self._set_busy(True)
        self.status.set(label)
        self._log(f"\n=== {label} ===")

        def run():
            try:
                result = fn(lambda m: self.q.put(("log", m)))
                self.q.put(("done", (label, result)))
            except Exception as exc:
                self.q.put(("error", (label, exc, traceback.format_exc())))

        threading.Thread(target=run, daemon=True).start()

    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._log(str(payload))
                elif kind == "done":
                    label, _ = payload
                    self._log(f"PASS: {label}")
                    self.status.set("Ready")
                    self._set_busy(False)
                elif kind == "error":
                    label, exc, tb = payload
                    self._log(f"FAIL: {label}: {type(exc).__name__}: {exc}")
                    self._log(tb)
                    self.status.set("Failed")
                    self._set_busy(False)
                    messagebox.showerror("Recovery Assistant", f"{label} failed:\n\n{exc}")
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def do_preflight(self):
        dest = Path(self.offsite.get()).expanduser()
        self._worker("Preflight", lambda p: preflight(TOOL_ROOT, dest, p))

    def do_backup(self):
        dest = Path(self.offsite.get()).expanduser()
        if not messagebox.askyesno(
            "Create production backup",
            "This will run pg_dump against production and archive production media, then copy both to the selected off-server destination.\n\nContinue?",
        ):
            return
        self._worker("Backup + off-server copy", lambda p: create_backup(TOOL_ROOT, dest, p))

    def do_restore(self):
        if not messagebox.askyesno(
            "Run isolated restore drill",
            "This will upload the verified off-server copy to temporary VPS staging and restore it into temporary Docker containers on an internal-only network. Production containers, volumes and database are not modified.\n\nContinue?",
        ):
            return
        self._worker("Isolated restore drill", lambda p: isolated_restore_drill(TOOL_ROOT, p))

    def open_attestations(self):
        win = tk.Toplevel(self)
        win.title("Human incident-recovery attestations")
        win.geometry("760x430")
        ttk.Label(
            win,
            text=(
                "These six statements are intentionally human-controlled. The assistant will NOT infer them from technical tests. "
                "Check a statement only after you personally verified it from provider/deployment records."
            ),
            wraplength=720,
            padding=12,
        ).pack(fill="x")
        current = current_release_attestations(TOOL_ROOT)
        vars_: dict[str, tk.BooleanVar] = {}
        body = ttk.Frame(win, padding=(12, 0, 12, 12))
        body.pack(fill="both", expand=True)
        for key in ATTESTATION_KEYS:
            v = tk.BooleanVar(value=current.get(key, False))
            vars_[key] = v
            ttk.Checkbutton(body, text=LABELS[key], variable=v).pack(anchor="w", pady=5)

        def save():
            values = {k: v.get() for k, v in vars_.items()}
            if not all(values.values()):
                messagebox.showwarning("Incomplete", "All six conditions must be genuinely verified before SecurityDiag can record the release attestations.")
                return
            if not messagebox.askyesno(
                "Confirm human attestations",
                "You are asserting that all six incident-recovery conditions are true. These are not technical auto-checks.\n\nRecord them in securitydiag.config.local.json?",
            ):
                return
            try:
                path = record_release_attestations(TOOL_ROOT, values)
            except Exception as exc:
                messagebox.showerror("Attestations", str(exc))
                return
            self._log(f"Recorded human release attestations in {path}")
            win.destroy()

        ttk.Button(body, text="Record verified attestations", command=save).pack(anchor="e", pady=(18, 0))

    def do_release(self):
        self._worker("SecurityDiag Release", lambda p: run_securitydiag_release(TOOL_ROOT, p))


if __name__ == "__main__":
    App().mainloop()
