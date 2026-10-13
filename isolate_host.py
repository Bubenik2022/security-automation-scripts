#!/usr/bin/env python3
"""Isolate (network-contain) a compromised host through an EDR REST API.

Generic example: endpoints and payloads follow a typical EDR "contain host"
pattern. Adapt URLs/fields to your vendor (CrowdStrike, Defender, etc.).

Credentials are read ONLY from environment variables:
    EDR_BASE_URL   e.g. https://api.edr.example.com
    EDR_API_TOKEN  bearer token with containment permission

Usage:
    python isolate_host.py --host-id abc123 --reason "Ransomware IOC" --dry-run
    python isolate_host.py --host-id abc123 --reason "Ransomware IOC"
    python isolate_host.py --host-id abc123 --release
"""
import argparse
import logging
import os
import sys

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("isolate_host")


def build_session() -> tuple[requests.Session, str]:
    base = os.environ.get("EDR_BASE_URL")
    token = os.environ.get("EDR_API_TOKEN")
    if not base or not token:
        sys.exit("Set EDR_BASE_URL and EDR_API_TOKEN environment variables.")
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return s, base.rstrip("/")


def set_containment(host_id: str, isolate: bool, reason: str, dry_run: bool) -> None:
    action = "contain" if isolate else "lift_containment"
    if dry_run:
        log.info("[DRY-RUN] would %s host %s (reason=%r)", action, host_id, reason)
        return
    session, base = build_session()
    resp = session.post(
        f"{base}/hosts/actions/{action}",
        json={"ids": [host_id], "comment": reason},
        timeout=15,
    )
    resp.raise_for_status()
    log.info("Action %s applied to host %s (HTTP %s)", action, host_id, resp.status_code)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host-id", required=True)
    p.add_argument("--reason", default="Isolated by automation")
    p.add_argument("--release", action="store_true", help="Lift isolation instead")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    set_containment(a.host_id, not a.release, a.reason, a.dry_run)


if __name__ == "__main__":
    main()
