# SecurityDiag 1.1.2 — Windows .pyw launcher

- Added `SecurityDiagLauncher.pyw` for double-click Windows use without a console window.
- GUI exposes the existing read-only campaigns plus Doctor, Show config, List, Copy output and Open evidence.
- `host` is the default campaign; `release` requires an explicit confirmation in the launcher.
- Child CLI output is captured live and the evidence directory can be opened after a run.
- Core diagnostic behavior and remote transport remain unchanged from 1.1.1.
