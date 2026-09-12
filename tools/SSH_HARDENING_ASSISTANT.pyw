from __future__ import annotations

import queue
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from ssh_hardening_core import (
    DEFAULT_ADMIN_USER,
    DEFAULT_EXPECTED_FINGERPRINT,
    HardeningError,
    apply_hardening_with_rollback,
    bootstrap_admin,
    cancel_rollback,
    load_json,
    preflight,
    remote_spec_from_config,
    repo_root_from_script,
    run_host_campaign,
    update_securitydiag_config,
    validate_admin_user,
    validate_expected_fingerprint,
    verify_hardened_login,
    wait_for_rollback_recovery,
)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SecurityDiag - Safe SSH Hardening")
        self.geometry("920x700")
        self.minsize(820, 620)
        self.repo_root = repo_root_from_script(Path(__file__))
        self.config_path = self.repo_root / "securitydiag.config.local.json"
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.busy = False
        self._build()
        self._load_defaults()
        self.after(100, self._drain_events)

    def _build(self) -> None:
        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Safe SSH hardening for Konnaxion VPS", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                "Creates/tests a non-root admin first, arms a VPS-side automatic rollback, then disables root/password SSH. "
                "The rollback is cancelled only after a fresh kx-admin login succeeds."
            ),
            wraplength=870,
        ).pack(anchor="w", pady=(4, 12))

        form = ttk.Frame(outer)
        form.pack(fill="x")
        self.config_var = tk.StringVar(value=str(self.config_path))
        self.admin_var = tk.StringVar(value=DEFAULT_ADMIN_USER)
        self.fp_var = tk.StringVar(value=DEFAULT_EXPECTED_FINGERPRINT)
        rows = [
            ("SecurityDiag config", self.config_var),
            ("New admin user", self.admin_var),
            ("Expected SSH fingerprint", self.fp_var),
        ]
        for i, (label, var) in enumerate(rows):
            ttk.Label(form, text=label, width=25).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(form, textvariable=var).grid(row=i, column=1, sticky="ew", pady=3)
        form.columnconfigure(1, weight=1)

        self.summary_var = tk.StringVar(value="Config not loaded yet.")
        ttk.Label(outer, textvariable=self.summary_var, wraplength=870).pack(anchor="w", pady=(10, 8))

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(4, 8))
        self.preflight_btn = ttk.Button(buttons, text="1. Preflight only", command=self.preflight_clicked)
        self.preflight_btn.pack(side="left", padx=(0, 8))
        self.apply_btn = ttk.Button(buttons, text="2. Apply safe hardening", command=self.apply_clicked)
        self.apply_btn.pack(side="left", padx=(0, 8))
        self.host_btn = ttk.Button(buttons, text="3. Run SecurityDiag Host", command=self.host_clicked)
        self.host_btn.pack(side="left")

        ttk.Label(outer, text="Log").pack(anchor="w")
        log_frame = ttk.Frame(outer)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, wrap="word", height=25, state="disabled", font=("Consolas", 10))
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        ttk.Label(
            outer,
            text="No password or private-key material is copied into SecurityDiag config. The helper uses the existing OpenSSH key path.",
            wraplength=870,
        ).pack(anchor="w", pady=(8, 0))

    def _load_defaults(self) -> None:
        try:
            cfg = load_json(self.config_path)
            r = cfg.get("remote", {})
            self.summary_var.set(
                f"Current SSH target: {r.get('user', '?')}@{r.get('host', '?')}:{r.get('port', 22)} | key: {r.get('identity_file', '?')}"
            )
            fps = r.get("allowed_ssh_key_fingerprints") or []
            if len(fps) == 1 and isinstance(fps[0], str) and fps[0].startswith("SHA256:"):
                self.fp_var.set(fps[0])
        except Exception as exc:
            self.summary_var.set(f"Could not load config: {exc}")

    def _log(self, text: str) -> None:
        self.events.put(("log", text))

    def _finish(self, text: str) -> None:
        self.events.put(("done", text))

    def _fail(self, text: str) -> None:
        self.events.put(("error", text))

    def _drain_events(self) -> None:
        while True:
            try:
                kind, text = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log_text.configure(state="normal")
                self.log_text.insert("end", text.rstrip() + "\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            elif kind == "done":
                self._set_busy(False)
                messagebox.showinfo("SecurityDiag SSH hardening", text)
            elif kind == "error":
                self._set_busy(False)
                messagebox.showerror("SecurityDiag SSH hardening", text)
        self.after(100, self._drain_events)

    def _set_busy(self, value: bool) -> None:
        self.busy = value
        state = "disabled" if value else "normal"
        self.preflight_btn.configure(state=state)
        self.apply_btn.configure(state=state)
        self.host_btn.configure(state=state)

    def _start(self, fn) -> None:
        if self.busy:
            return
        self._set_busy(True)
        threading.Thread(target=self._worker, args=(fn,), daemon=True).start()

    def _worker(self, fn) -> None:
        try:
            fn()
        except HardeningError as exc:
            self._fail(str(exc))
        except Exception as exc:
            self._log(traceback.format_exc())
            self._fail(f"Unexpected error: {type(exc).__name__}: {exc}")

    def _inputs(self):
        config_path = Path(self.config_var.get().strip())
        cfg = load_json(config_path)
        spec = remote_spec_from_config(cfg)
        admin = validate_admin_user(self.admin_var.get())
        fp = validate_expected_fingerprint(self.fp_var.get())
        return config_path, cfg, spec, admin, fp

    def preflight_clicked(self) -> None:
        self._start(self._preflight)

    def _preflight(self) -> None:
        _, _, spec, _, fp = self._inputs()
        self._log("=== PRECHECK ===")
        self._log(f"Target: {spec.user}@{spec.host}:{spec.port}")
        preflight(spec, fp, self._log)
        self._finish("Preflight passed. No remote configuration was changed.")

    def apply_clicked(self) -> None:
        if not messagebox.askyesno(
            "Confirm safe SSH hardening",
            "This will create/test kx-admin, install a NOPASSWD administrative sudo policy required by SecurityDiag, "
            "then disable root/password SSH with an automatic rollback guard. Continue?",
        ):
            return
        self._start(self._apply)

    def _apply(self) -> None:
        config_path, _, spec, admin, fp = self._inputs()
        self._log("=== SAFE HARDENING START ===")
        public_key, actual_fp = preflight(spec, fp, self._log)
        bootstrap_admin(spec, admin, public_key, actual_fp, self._log)
        backup_dir = apply_hardening_with_rollback(spec, admin, self._log)
        self._log(f"Remote SSH backup: {backup_dir}")
        try:
            verify_hardened_login(spec, admin, self._log)
        except HardeningError:
            wait_for_rollback_recovery(spec, self._log)
            raise
        cancel_rollback(spec, admin, self._log)
        backup = update_securitydiag_config(config_path, admin, actual_fp)
        self._log(f"Updated SecurityDiag config: {config_path}")
        self._log(f"Local config backup: {backup}")
        self._finish(
            "SSH hardening succeeded. SecurityDiag now uses the non-root admin account and the verified SSH fingerprint. "
            "Run the Host campaign next."
        )

    def host_clicked(self) -> None:
        self._start(self._run_host)

    def _run_host(self) -> None:
        self._log("=== SECURITYDIAG HOST CAMPAIGN ===")
        result = run_host_campaign(self.repo_root)
        if result.stdout:
            self._log(result.stdout)
        if result.stderr:
            self._log("STDERR:\n" + result.stderr)
        if result.exit_code not in (0, 10):
            raise HardeningError(f"SecurityDiag Host exited with code {result.exit_code}.")
        self._finish(f"SecurityDiag Host finished with exit code {result.exit_code}. Review the log/evidence for PASS/WARN details.")


if __name__ == "__main__":
    App().mainloop()
