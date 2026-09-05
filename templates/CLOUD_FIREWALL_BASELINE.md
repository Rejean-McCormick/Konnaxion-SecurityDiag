# Cloud firewall baseline

Before installing Konnaxion:

| Source | Port | Action |
|---|---:|---|
| administrator public IP / VPN | 22/tcp | allow |
| world | 80/tcp | allow |
| world | 443/tcp | allow |
| world | all other inbound ports | deny |

Do not rely on host UFW alone for Docker-published ports. Keep a provider-level firewall/security group as the first control plane.
