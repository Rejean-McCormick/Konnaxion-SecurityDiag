# Docker baseline

SecurityDiag expects the production posture to converge on:

- routine `deploy` user is not a member of the `docker` group;
- no Docker daemon TCP listener (`2375`/`2376`);
- no container mounts `/var/run/docker.sock`;
- no privileged production containers without an explicit documented exception;
- no public mapping for Next.js `3000`, Django `8000`, PostgreSQL `5432`, Redis `6379`, or Flower `5555`;
- only reviewed images are running;
- Konnaxion containers use private Docker networks behind the public reverse proxy.

Docker documents that membership in the `docker` group grants root-level privileges. Rootless Docker can reduce daemon/runtime privilege, but adoption should be separately qualified.
