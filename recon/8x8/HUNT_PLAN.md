# 8x8 Bug Bounty — JaaS Hunt Plan

Account A (attacker): cid `9e3cb0a654024417bbaea7c797ed8062`, user `auth0|6a096f705a67ac86f5447b96`, name "attacker"
Account B (victim):   cid `13dc8996cd274aab896fab41a75e97af`, user `auth0|6a09717b9ec6a906eede46ad`, name "victim"

Compliance:
- Email alias: `blackboxops+1/+2@wearehackerone.com` ✓
- Add header `X-HackerOne: blackboxops` to every request and append to UA. ✓
- Low volume only. No DoS. No automation that hammers endpoints.

## Priority queue

### P0 — Highest payout potential
1. **Webhook SSRF** (`target-manager/v1/targets`) → `webhook_ssrf.py`
2. **Cross-tenant key upload** (`key-uploader/v1/tenants/.../publickey`) — manual PUT/POST tests
3. **JWT alg confusion** on invite token + passcode token → `jwt_attacks.md`

### P1 — High probability, medium payout
4. **Reserved tenant `quicksight`** — read/write tests via every config endpoint
5. **Branding upload SVG XSS** + cross-tenant write via presigned URL swap
6. **Invite flow email mismatch** — accept signup with email different from JWT claim
7. **password-change** auth bypass — does it require current password? CSRF?

### P2 — Worth a try
8. **Recording cross-tenant access** via path manipulation
9. **email_verified=false** but admin actions succeed → privilege issue
10. **`/customer-configs/v1/customers/config/options`** — global config write attempts

## Day 1 checklist
- [ ] Capture fresh tokens for A and B (they expire ~10min)
- [ ] Run `idor_replay.py` — log everything not 401/403/404
- [ ] Set up Burp Collaborator + run `webhook_ssrf.py`
- [ ] Trigger recording in tenant A → check collaborator hits
- [ ] Manually probe key-uploader cross-tenant PUT/POST
- [ ] Probe `customers/quicksight` reads + writes

## Day 2 checklist
- [ ] Fetch JWKS, run `jwt_tool.py -X k` on every token
- [ ] Branding: upload SVG with `<script>alert(document.domain)</script>`, fetch via public branding URL
- [ ] Invite flow: invite C from tenant A, copy invite_id, finish signup with email D ≠ C
- [ ] password-change: try without current password, with wrong cid in body
- [ ] Test `meet-external/customer-configs/v1/customers/quicksight` writes

## Reporting template (use HackerOne Report Assistant)
- Title: `[JaaS] <issue> — <impact one-liner>`
- Asset: `jaas.8x8.vc` 
- CWE
- Steps: numbered, copy-pasteable, full HTTP requests/responses
- PoC video: 60s max, narrate exploit path
- Impact: business impact, not technical
- Mitigation: optional, signals seniority
