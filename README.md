# security-automation-scripts

Example incident-response automation (generic, vendor-neutral).

| Script | Purpose |
|---|---|
| `isolate_host.py` | Network-contain / release a host via EDR API |
| `block_ip.sh` | Add an IP to a firewall blocklist |

## Setup
```bash
pip install -r requirements.txt
export EDR_BASE_URL=... EDR_API_TOKEN=...
python isolate_host.py --host-id <id> --reason "IOC match" --dry-run
```

Secrets are only read from environment variables. Never commit tokens.
Always test with `--dry-run` first. Use only on systems you are authorized to manage.

License: MIT
