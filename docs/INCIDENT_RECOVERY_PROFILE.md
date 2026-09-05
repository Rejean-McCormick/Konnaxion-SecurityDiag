# Konnaxion incident-recovery profile

The prior incident evidence described compromise of the deployment account, malicious Docker containers, cron persistence, attempted sudo persistence, a `/tmp/sshd` artifact, and exposed credentials.

SecurityDiag therefore ships with configurable default indicators including:

```text
negoroo/amco
amco_
supportxmr
xmrig
/tmp/sshd
pakchoi
```

These indicators are checked across:

- running Docker containers/images;
- running process/service state;
- usernames;
- executable files in `/tmp` and `/dev/shm`;
- cron/persistence locations;
- custom systemd persistence locations.

A clean result does not prove the old host is safe. The release policy is:

1. fresh VPS from provider image;
2. no cloned old disk;
3. rotate compromised secrets;
4. deploy only clean Git source;
5. restore only verified DB/media;
6. verify cloud firewall;
7. retire or isolate the old VPS.
