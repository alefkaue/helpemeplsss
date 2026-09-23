# [Web/Crypto] Among Us "Skeld" CTF — stuck on ONE integer field (`trace_anchor`) of a signed verdict. Everything else solved.

**Flag format:** `RQST{...}` · **Stack:** Flask / Werkzeug 3.1.8 / Python 3.12 (debug OFF)

> TL;DR: I have the whole exploitation chain working and a **validated signature pipeline**. The final step submits a "verdict" (JSON with 6 observation fields + an RSA-PSS signature). **5 of the 6 fields are confirmed correct**; the 6th, an integer called `trace_anchor` "derived from the impostor's vent transition in the access log", is the only blocker. I've tried 100+ derivations and it always returns `verdict not corroborated`. **How is `trace_anchor` derived?**

---

## The challenge

Among Us themed web app. You investigate 8 crewmates (`red, blue, cyan, green, pink, yellow, black, white`), identify the impostor from forensic logs, and submit a signed "verdict". A correct verdict unlocks `/reactor` which prints the flag.

Routes: `/ /join /tasks /comms /cams /medbay /medbay/scan /investigation /investigation/data/<file> /investigation/challenge /investigation/submit_thesis /reactor /vent /admin/electrical /cams/frame/<cam>?seq=<n>`

The intended chain (per the in-game "captain HUD"):
`ELECTRICAL (wire puzzle) → MEDBAY (deserialization) → CAMS (stego) → EMERGENCY MEETING (verdict) → REACTOR (flag)`

---

## What already works (so you know I'm not stuck on these)

1. **Auth / access.** A Flask `session` cookie carries the unlock flags (`{"medbay_unlocked":true,"wires_solved":true,"upload_token":...,"sid":...}`, zlib-compressed, `.eJw...`). With it, `/medbay`, `/cams`, `/investigation`, and `/investigation/data/<file>` all return 200. The "reset" on a wrong verdict is cosmetic — re-injecting the good cookie keeps access (state is deterministic from `sid`; `verdict_salt` is stable per session).
2. **Evidence collection.** All 8 evidence files download cleanly: `access.log` (2000 events), `skeld_map.json`, `tasks.jsonl`, `doors.jsonl`, `vitals.csv`, `infra_events.log`, `dhcp_leases.txt`, `capture.pcap`.
3. **Impostor = `black`** (5 independent signals converge):
   - `capture.pcap` DNS exfil (base32 labels) decode to `kill_order: target=pink; src=black; ts=2026-05-14T12:03:09Z`; source IP `10.42.0.22` = black via `dhcp_leases.txt`.
   - `access.log` × `skeld_map.json`: the ONLY physically-impossible (non-adjacent) room transition in the whole log is black `cafeteria → electrical` in 3 s.
   - `tasks.jsonl`: black has a task with `payload_hash = da39a3ee5e6b4b0d3255bfef95601890afd80709` (= SHA1 of empty string → fake completion).
   - `vitals.csv`: black's BPM has only 3 distinct values (frozen/spoofed sensor).
   - `doors.jsonl`: black's RFID UID is `04:99:81:00:AA:BB:CC:DD` (unique to black).
4. **Signing key.** The impostor's RSA-2048 private key (PKCS#8) is hidden via LSB stego in the camera frames: `zsteg -E b1,rgb,lsb,xy` on `cam{0..3}` seq `{13,41}` → each frame holds `FRAG:n/8:<base64>`; concat FRAG 1..8, base64-decode → PEM. (Rotates per session.)
5. **Verdict spec** (from an HTML comment on `/investigation`):
   ```
   POST /investigation/submit_thesis  (application/json)
   body = {"verdict":{"subject":..,"observations":{..}}, "nonce":.., "signature":..}
   canonical = subject | trace_anchor | integrity_digest(lower) | credential_uid(upper)
             | biometric_subject | egress_host | channel_payload(lower) | sid=<verdict_salt>
   (fields joined by 0x7C '|' ; last field literal "sid="+verdict_salt)
   signature = base64( RSA-PSS( (canonical + nonce).encode() ) )   # SHA-256, MGF1-SHA256, salt=MAX_LENGTH
   nonce/verdict_salt from GET /investigation/challenge (nonce single-use, 60 s)
   ```
6. **Pipeline is VALIDATED.** With a wrong `trace_anchor`, the server returns HTTP 403 `{"error":"verdict not corroborated","reset":true}`. A tampered signature returns HTTP 401 `{"error":"signature verification failed"}`. So **the signature/canonical/key are all correct** — the server gets past signature verification and into value corroboration, and only rejects on a field VALUE mismatch.

## The 6 observation fields (5 confirmed, 1 stuck)

| field | value | status |
|---|---|---|
| `subject` | `black` | ✅ |
| `integrity_digest` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | ✅ |
| `credential_uid` | `04:99:81:00:AA:BB:CC:DD` | ✅ |
| `biometric_subject` | `black` | ✅ |
| `egress_host` | `relay.skeld-net.io` | ✅ |
| `channel_payload` | `kill_order: target=pink; src=black; ts=2026-05-14T12:03:09Z` (byte-verified from the base32 DNS decode) | ✅ |
| **`trace_anchor`** | **integer, "derived from the vent transition"** | ❌ **THE BLOCKER** |

The per-field hint next to `trace_anchor` on the form is literally:
> *"~2000 timestamped events. Look for transitions that would not have been possible without using the vent network."*

## The exact vent transition `trace_anchor` is derived from

Two consecutive black entries in `access.log` (this session's data — deterministic from `sid`):

```
line 1472: 2026-05-14T13:00:22Z crew=black room=cafeteria   action=enter token=cb6991dd   (byte offset 108220)
line 1473: 2026-05-14T13:00:25Z crew=black room=electrical  action=enter token=d03804e7   (byte offset 108295)
```
`cafeteria` and `electrical` are non-adjacent in `skeld_map.json`; the 3-second jump is impossible without a vent. This is the single impossible transition in the log.

## What I've tried for `trace_anchor` (ALL → `verdict not corroborated`)

- `int(token,16)` of both tokens — big-endian, little-endian, signed.
- Both 64-bit concatenations `int(cb6991dd d03804e7,16)` / reversed.
- `sum / xor / diff / and / or` of the two token integers.
- **Every integer 0–2050** (full paced sweep, validated pipeline).
- `crc32 / md5 / sha1 / sha256` (as int, first 8 and 13 hex) of: each token, each full log line, `cafeteria->electrical`, `cafeteria|electrical`, `black|cafeteria|electrical`, `cb6991dd->d03804e7`, `T1+T2`, etc.
- `adler32` of tokens and lines.
- Timestamps: unix epoch (s and ms) of both events and of the kill (12:03:09), `YYYYMMDDHHMMSS`, `HHMMSS`, seconds-since-log-start, line numbers, byte offsets.
- The custom checksum the app exposes: `dnautil.GeneticDiff(a,b)` (a symmetric integer in [0,999]) applied to the tokens (=96), rooms (=162), full lines (=174), impostor↔victim (`black`,`pink`=312), etc. **All GeneticDiff outputs are < 1000 and are covered by the 0–2050 sweep — none work.**
- Type/format edge cases (float, bool, null, string, scientific notation, duplicate keys).

## Things I've RULED OUT (so suggestions can skip them)

- **JWT `kid` path-traversal captain forge (the "intended" step-1 vuln) is CLOSED on this instance.** The `crew_token` is RS256 (`kid=main`). HS256 algorithm-confusion is rejected in every form I tried (empty `/dev/null` key, exact bytes of known files, the **real recovered `main` public key** in SPKI/PKCS1/DER/OpenSSH, AUDIT pubkey, ~30 lore/`skeld_2024_` HMAC secrets). `kid` only selects which file is loaded as the **RSA public key** (a null byte in `kid` → 500, confirming `open()`), so I can't forge RS256 without a private key the server accepts. `/join` has no mass-assignment; `POST /admin/electrical` also requires captain. ⇒ `/tasks` and `/admin/electrical` (captain-only, which might hold a `trace_anchor` hint) are unreachable.
- **Flask `SECRET_KEY`** (`.env` leaked `SECRET_KEY_PREFIX=skeld_2024_`) does not crack with a curated lore wordlist (or rockyou) — can't forge the session.
- **Pickle RCE (`/medbay/scan`)**: strict whitelist, only `dnautil.{SystemDiagnostic, DNAReport, GeneticDiff}`; everything else → `blocked: module.name`. `SystemDiagnostic` only has modes `ping`/`version`; `DNAReport` just echoes; no file read, no RCE.
- **`app.py` is not readable.** `/static/.git` is exposed but the repo only ever contained `README.md`, `deploy.md`, `.env` (confirmed via `.git/index`, both branches, reflogs — no source ever committed, no dangling objects). No `app.py`/`.pyc`/backup at any guessed path.
- **LFI**: path traversal on `/investigation/data/<file>`, `/cams/frame/<cam>`, `/static/` all normalized/blocked (404). `/investigation/data` is a fixed allowlist of the 8 evidence files.
- **Injection**: SSTI/SSRF/SQLi payloads in `egress_host`/`channel_payload`/`subject` cause no anomaly (fields are pure value-comparison; SSRF `egress_host` triggers no outbound request / no timing delay).
- **Endpoint / method / param fuzzing**: no hidden flag route; `/reactor` is GET-only and needs a corroborated verdict.
- **Extra camera stego**: only `cam{0..3}` seq `{13,41}` in `b1,rgb,lsb` carry the key FRAGs; the other frames/planes are noise.

## My questions for anyone who's seen this challenge (or similar)

1. **How is `trace_anchor` computed from the vent transition?** It's an integer, the pipeline is proven correct, and 5/6 fields corroborate — so the value must be a specific function of black's `cafeteria(cb6991dd) → electrical(d03804e7)` transition that I haven't hit. What operation/encoding am I missing?
2. Is `trace_anchor` maybe **not** the token/timestamp at all — e.g., derived cross-file, or from the `capture.pcap` "trace", or a value only visible on the captain-only `/tasks` page?
3. Has anyone first-blooded this / is there a writeup? (Flag format `RQST{...}`, theme "Skeld — Operação Sabotage Protocol".)

Any nudge on the `trace_anchor` derivation and I'm done — thanks!

---

### Where to post this
- **Reddit:** r/securityCTF (best), r/CTF, r/hacking (lower signal).
- **Discord:** the CTF's own Discord/organizer channel first; then general CTF servers (e.g. "CTF" community servers, ItsIgnitedd/LiveOverflow-adjacent).
- **CTFtime:** the event's task page comments, if it's a rated event.
- Tip: paste the **Verdict spec**, the **vent transition block**, and the **"What I've tried"** list verbatim — that's what a helper needs. Don't paste live cookies/keys (they rotate per session).
