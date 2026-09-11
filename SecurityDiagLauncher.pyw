from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

TOOL_ROOT = Path(__file__).resolve().parent
CLI = TOOL_ROOT / "securitydiag.py"
LOCAL_CONFIG = TOOL_ROOT / "securitydiag.config.local.json"

CAMPAIGNS = (
    ("Host VPS", "host"),
    ("External TLS / ports", "external"),
    ("Repository", "repo"),
    ("Incident", "incident"),
    ("Predeploy", "predeploy"),
    ("Release S00-S14", "release"),
)
LABEL_TO_CAMPAIGN = dict(CAMPAIGNS)
EVIDENCE_RE = re.compile(r"^Evidence:\s*(.+?)\s*$", re.MULTILINE)


def _python_executable() -> str:
    """Prefer python.exe beside pythonw.exe so child output can be captured."""
    current = Path(sys.executable)
    if os.name == "nt" and current.name.lower() == "pythonw.exe":
        console_python = current.with_name("python.exe")
        if console_python.exists():
            return str(console_python)
    return str(current)


def build_command(action: str, selection: str | None = None, fail_fast: bool = False) -> list[str]:
    command = [_python_executable(), str(CLI)]
    if action == "run":
        if not selection:
            raise ValueError("A campaign is required.")
        command += ["run", selection]
        if fail_fast:
            command.append("--fail-fast")
    elif action in {"doctor", "show-config", "list"}:
        command.append(action)
    else:
        raise ValueError(f"Unsupported action: {action}")
    return command


def creation_flags() -> int:
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


class SecurityDiagLauncher(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Konnaxion SecurityDiag")
        self.geometry("940x680")
        self.minsize(760, 520)

        self._messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self._process: subprocess.Popen[str] | None = None
        self._last_evidence: Path | None = None

        self.campaign_var = tk.StringVar(value="Host VPS")
        self.fail_fast_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self.after(80, self._drain_messages)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        title = ttk.Label(outer, text="Konnaxion SecurityDiag", font=("Segoe UI", 15, "bold"))
        title.pack(anchor="w")
        ttk.Label(
            outer,
            text="Read-only security diagnostics — double-click launcher",
        ).pack(anchor="w", pady=(0, 10))

        controls = ttk.Frame(outer)
        controls.pack(fill="x")

        ttk.Label(controls, text="Campaign:").pack(side="left")
        chooser = ttk.Combobox(
            controls,
            textvariable=self.campaign_var,
            values=[label for label, _ in CAMPAIGNS],
            state="readonly",
            width=24,
        )
        chooser.pack(side="left", padx=(6, 10))

        self.run_button = ttk.Button(controls, text="Run", command=self._run_campaign)
        self.run_button.pack(side="left")
        self.doctor_button = ttk.Button(controls, text="Doctor", command=lambda: self._start("doctor"))
        self.doctor_button.pack(side="left", padx=(6, 0))
        self.config_button = ttk.Button(controls, text="Show config", command=lambda: self._start("show-config"))
        self.config_button.pack(side="left", padx=(6, 0))
        self.list_button = ttk.Button(controls, text="List", command=lambda: self._start("list"))
        self.list_button.pack(side="left", padx=(6, 0))

        ttk.Checkbutton(controls, text="Fail fast", variable=self.fail_fast_var).pack(side="right")

        status_row = ttk.Frame(outer)
        status_row.pack(fill="x", pady=(10, 6))
        ttk.Label(status_row, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(status_row, mode="indeterminate", length=180)
        self.progress.pack(side="right")

        self.output = ScrolledText(
            outer,
            wrap="word",
            font=("Consolas", 10),
            undo=False,
            padx=8,
            pady=8,
        )
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "Select a campaign and click Run.\n")
        self.output.configure(state="disabled")

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(8, 0))
        self.evidence_button = ttk.Button(bottom, text="Open evidence", command=self._open_evidence, state="disabled")
        self.evidence_button.pack(side="left")
        ttk.Button(bottom, text="Open config", command=self._open_config).pack(side="left", padx=(6, 0))
        ttk.Button(bottom, text="Copy output", command=self._copy_output).pack(side="left", padx=(6, 0))
        ttk.Button(bottom, text="Clear", command=self._clear_output).pack(side="left", padx=(6, 0))

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for button in (self.run_button, self.doctor_button, self.config_button, self.list_button):
            button.configure(state=state)
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _append(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _run_campaign(self) -> None:
        label = self.campaign_var.get()
        selection = LABEL_TO_CAMPAIGN.get(label)
        if not selection:
            messagebox.showerror("SecurityDiag", "Unknown campaign selection.")
            return
        if selection == "release":
            if not messagebox.askyesno(
                "Release qualification",
                "Run the complete S00-S14 release qualification now?\n\n"
                "This remains read-only, but it may fail until host hardening and restore attestations are complete.",
            ):
                return
        self._start("run", selection)

    def _start(self, action: str, selection: str | None = None) -> None:
        if self._process is not None:
            return
        self._last_evidence = None
        self.evidence_button.configure(state="disabled")
        self._set_busy(True)
        description = selection or action
        self.status_var.set(f"Running: {description}")
        self._append(f"\n===== {description} =====\n")
        thread = threading.Thread(
            target=self._worker,
            args=(action, selection, bool(self.fail_fast_var.get())),
            daemon=True,
        )
        thread.start()

    def _worker(self, action: str, selection: str | None, fail_fast: bool) -> None:
        try:
            command = build_command(action, selection, fail_fast)
            env = os.environ.copy()
            env.setdefault("PYTHONUTF8", "1")
            process = subprocess.Popen(
                command,
                cwd=str(TOOL_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                creationflags=creation_flags(),
            )
            self._process = process
            captured: list[str] = []
            assert process.stdout is not None
            for line in process.stdout:
                captured.append(line)
                self._messages.put(("output", line))
            code = process.wait()
            text = "".join(captured)
            match = EVIDENCE_RE.search(text)
            evidence = Path(match.group(1).strip()) if match else None
            self._messages.put(("done", (code, evidence)))
        except Exception as exc:
            self._messages.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            self._process = None

    def _drain_messages(self) -> None:
        try:
            while True:
                kind, payload = self._messages.get_nowait()
                if kind == "output":
                    self._append(str(payload))
                elif kind == "done":
                    code, evidence = payload  # type: ignore[misc]
                    self._set_busy(False)
                    self.status_var.set(f"Finished — exit code {code}")
                    if evidence is not None and Path(evidence).exists():
                        self._last_evidence = Path(evidence)
                        self.evidence_button.configure(state="normal")
                elif kind == "error":
                    self._set_busy(False)
                    self.status_var.set("Launcher error")
                    self._append(f"\nLauncher error: {payload}\n")
                    messagebox.showerror("SecurityDiag launcher", str(payload))
        except queue.Empty:
            pass
        self.after(80, self._drain_messages)

    def _open_evidence(self) -> None:
        if self._last_evidence and self._last_evidence.exists():
            self._open_path(self._last_evidence)

    def _open_config(self) -> None:
        path = LOCAL_CONFIG if LOCAL_CONFIG.exists() else TOOL_ROOT / "securitydiag.config.json"
        self._open_path(path)

    def _open_path(self, path: Path) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("SecurityDiag", f"Unable to open:\n{path}\n\n{exc}")

    def _copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Output copied")

    def _clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")


def main() -> int:
    if not CLI.exists():
        messagebox.showerror("SecurityDiag", f"Missing CLI: {CLI}")
        return 2
    app = SecurityDiagLauncher()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
