# Argonaut × Arena Tunnel — Integration Hand-off

**Audience:** the `arena-manager` / `arena-tunnel` maintainer.
**Goal:** let **Argonaut** (PRISM's autonomous red-team agent) connect to Adversario
Arena the *real* way — through `arena-tunnel` (WireGuard-over-WebSocket via the
`arena-tunnel-client` binary), exactly like a student — so it can play scenarios.
**Status:** Arena side **shipped** on branch `feat/byoc2-service-enroll-argonaut`
(rtaas monorepo, 2026-08-02). PRISM side is already deployed. Argonaut now runs
**fully autonomously** — no human minting or pasting tokens.

Historical: `arena-byoc` was the pre-2026-07 CLI name; the binary is now
`arena-tunnel-client`. Install path (`/usr/local/bin/arena-byoc`), TUN
interface name (`arena-byoc`), config dir (`~/.config/arena-byoc/`) still
carry the legacy string internally — full rename is a separate follow-up PR
(non-blocking).

---

## TL;DR (post-implementation)

- PRISM stores `ARENA_POA_API_KEY` in its vault as `PRISM_ARENA_SERVICE_KEY`.
- At engagement launch, PRISM calls **one endpoint** and receives durable WG
  creds + a redirector slot in a single round-trip.
- PRISM writes the creds to `~/.config/arena-byoc/config.json` (existing
  schema — no client changes) and runs `arena-tunnel-client --portable
  --config <path>` inside its Exegol container.
- Argonaut is an ArenaUser with `role='bot'` — audit-clean, `isBot` UI
  branches route it away from student-only surfaces automatically.

---

## What Arena shipped (on `feat/byoc2-service-enroll-argonaut`)

### 1. `POST /api/byoc2/service-enroll` — durable creds in one call

```
POST /api/byoc2/service-enroll
Headers:
  x-agent-api-key: <ARENA_POA_API_KEY>
  Content-Type:    application/json
Body:
  {
    "botUserEmail":       "argonaut@adversario.cl",
    "framework":          "adaptix",       // optional
    "replaceActivePeer":  true             // optional — default true
  }
Response 200:
  {
    "ok":              true,
    "peerId":          "clz…",
    "tunnelIp":        "10.201.0.42",
    "serverHost":      "wg-byoc.adversario.cl",
    "serverPubKey":    "yA5R…",
    "privateKey":      "aRd6…",           // returned ONCE — persist immediately
    "revocationToken": "…",                // bearer for /peer/status + DELETE
    "userEmail":       "argonaut@adversario.cl",
    "redirectorSlot": {                    // byoc-edge shared vhost — REQUIRED for OPSEC
      "id":           "clz…",
      "sniHost":      "eb42ac.byoc.adversario.cl",
      "listenerPort": 443,
      "cookieName":   "__arena_tenant",
      "hmacKid":      "sec_…",
      "status":       "provisioning"       // → 'active' ~30 s after ansible run
    }
  }
```

- Auth: `x-agent-api-key` header (reuses `/api/bot/enroll`'s existing scope
  infrastructure). New scope `byoc2:enroll` in `lib/auth/agent-key.ts`.
- No download-token indirection: the browser flow needs a one-shot token
  because `/pair/poll` is unauthenticated; here we're already authenticated,
  so creds are returned inline. No 10-min TTL race.
- Rotation is automatic: `replaceActivePeer=true` revokes the extant peer
  atomically before minting the new one.
- **Auto-provisions the shared byoc-edge RedirectorSlot** (mirrors browser
  `pair/claim`). Argonaut's callbacks MUST route through the vhost so beacon
  telemetry attribution + OPSEC scoring register the engagement. A bypass
  shows up as un-scored traffic and the engagement never resolves.

### 2. Argonaut identity — `role='bot'`

- Verified: the `bot` role is **not** nukeable — the `nuke AGENTIC` commit
  (`a6b1bec9`, 2026-07-26) removed the AGENTIC bundle tier + `WatchtowerPrismBots`
  UI, but left the `bot` role, `wg100` plane, `lib/bot/*`, `/api/bot/enroll`,
  and every `isBot` UI branch intact — they're actively used by the gym
  harness, PoA agent, and validate-proof.
- Seed script: `apps/arena-manager/prisma/seeds/argonaut-bot-user.ts` creates
  `ArenaUser argonaut@adversario.cl` (role=bot) + `Organization Adversario Bots`
  (cohortPolicy allows BYOC2 + BYOC2 Pro).
- Runbook: `docs/runbooks/argonaut-service-enroll.md`.

### 3. Reaper — non-issue

- Verified `lib/byoc2/reaper.ts` **does NOT** revoke `Byoc2Peer` rows by
  heartbeat inactivity. It only purges expired `Byoc2DownloadToken` +
  `Byoc2PairingCode` rows (unused on the service-enroll path).
- No changes needed. Argonaut's `--portable` peer stays alive as long as
  the DB row says `status='active'`.

### 4. Quota / CPU-ms

- Argonaut's org (`Adversario Bots`) is provisioned with
  `cohortPolicy.allowsByoc2Pro=true` + `maxConcurrentTenants=8`.
- Actual Workers-Free CPU-ms budget is a runtime concern; monitor in
  soak. Move Argonaut to a dedicated relay if it saturates.

### 5. Durable creds — chosen path

- Selected over §1's one-shot token: service-enroll returns creds inline,
  eliminating the 10-min TTL race entirely.
- PRISM writes the bundle straight to `~/.config/arena-byoc/config.json`
  (schema-compatible with `arena-tunnel-client`'s existing loader), then
  launches the binary with `--portable --config <path>`.
- No `--token` flag path taken. No client-side changes required.

---

## PRISM launch flow (final)

```python
# 1. Mint durable creds + slot.
resp = requests.post(
    "https://arena.adversario.cl/api/byoc2/service-enroll",
    headers={"x-agent-api-key": ARENA_SERVICE_KEY},
    json={
        "botUserEmail":      "argonaut@adversario.cl",
        "framework":         "adaptix",
        "replaceActivePeer": True,
    },
    timeout=30,
).json()

# 2. Persist config.json (mode 0600) — arena-tunnel-client's existing schema.
cfg = {
    "version":         1,
    "tunnelIp":        resp["tunnelIp"],
    "privateKey":      resp["privateKey"],
    "serverPubKey":    resp["serverPubKey"],
    "serverHost":      resp["serverHost"],
    "userEmail":       resp["userEmail"],
    "arenaBaseURL":    "https://arena.adversario.cl",
    "revocationToken": resp["revocationToken"],
    "pairedAt":        datetime.utcnow().isoformat() + "Z",
}
path = f"/etc/arena-byoc/eng-{engagement_id}.json"
Path(path).write_text(json.dumps(cfg))
Path(path).chmod(0o600)

# 3. Wire the redirector slot into Argonaut's C2 malleable profile:
#      HTTP-GET / HTTP-POST → https://{sniHost}:{listenerPort}
#      HTTP-COOKIE header  → {cookieName}
#    HMAC key material is fetched from arena-manager's EncryptedSecret at
#    runtime; hmacKid identifies the current version.
slot = resp["redirectorSlot"]

# 4. Launch inside Exegol (host NetworkMode — --portable is mandatory).
subprocess.Popen([
    "arena-tunnel-client",
    "--portable",
    "--config", path,
])
```

---

## Follow-ups (non-blocking, tracked in rtaas repo)

1. **Per-key ApiKey DB scopes** — `lib/auth/agent-key.ts:67-71` is a TODO.
   Today `ARENA_POA_API_KEY` is a shared secret with every scope. Landing
   per-key DB scopes lets us give Argonaut a key with only `byoc2:enroll`
   without inheriting `bot:enroll` / `play:validate` / etc.
2. **Rename `arena-byoc` → `arena-tunnel`** — cosmetic (TUN name, install
   path, config dir, PID file). Separate PR to keep this diff focused.
3. **Update this doc** ← done (2026-08-02).

---

## References

Arena side (`rtaas/apps/arena-manager`):
- `app/(platform)/api/byoc2/service-enroll/route.ts` — new endpoint.
- `lib/auth/agent-key.ts` — `BOT_SCOPES.BYOC2_ENROLL` scope.
- `prisma/seeds/argonaut-bot-user.ts` — idempotent seed.
- `lib/byoc2/auto-provision-slot.ts` — reused verbatim; no bot-specific path.
- `docs/runbooks/argonaut-service-enroll.md` — bootstrap + rotation + revoke.

Client (`arena-tunnel/client`):
- `config.go` — schema for `~/.config/arena-byoc/config.json`.
- `main.go` — `--portable` + `--config` flags (unchanged).
