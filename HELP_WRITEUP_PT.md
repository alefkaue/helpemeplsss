# [Web/Crypto] CTF Among Us "Skeld" — travado em UM campo inteiro (`trace_anchor`) de um verdict assinado. Todo o resto resolvido.

**Formato da flag:** `RQST{...}` · **Stack:** Flask / Werkzeug 3.1.8 / Python 3.12 (debug OFF)

> TL;DR: Tenho a cadeia de exploração inteira funcionando e um **pipeline de assinatura validado**. O passo final submete um "verdict" (JSON com 6 campos de observação + assinatura RSA-PSS). **5 dos 6 campos estão confirmados**; o 6º, um inteiro chamado `trace_anchor` "derivado da transição de vent do impostor no access log", é o único bloqueio. Já testei 100+ derivações e sempre volta `verdict not corroborated`. **Como o `trace_anchor` é derivado?**

---

## O desafio

App web temático de Among Us. Você investiga 8 tripulantes (`red, blue, cyan, green, pink, yellow, black, white`), identifica o impostor pelos logs forenses e submete um "verdict" assinado. Um verdict correto libera `/reactor`, que imprime a flag.

Rotas: `/ /join /tasks /comms /cams /medbay /medbay/scan /investigation /investigation/data/<arquivo> /investigation/challenge /investigation/submit_thesis /reactor /vent /admin/electrical /cams/frame/<cam>?seq=<n>`

Cadeia pretendida (pelo "captain HUD" do jogo):
`ELECTRICAL (puzzle de fios) → MEDBAY (desserialização) → CAMS (esteganografia) → EMERGENCY MEETING (verdict) → REACTOR (flag)`

---

## O que JÁ funciona (pra ninguém sugerir o óbvio)

1. **Auth / acesso.** Um cookie `session` do Flask carrega as flags de unlock (`{"medbay_unlocked":true,"wires_solved":true,"upload_token":...,"sid":...}`, comprimido com zlib, `.eJw...`). Com ele, `/medbay`, `/cams`, `/investigation` e `/investigation/data/<arquivo>` retornam 200. O "reset" ao errar o verdict é cosmético — reinjetar o cookie bom mantém o acesso (o estado é determinístico do `sid`; o `verdict_salt` é estável por sessão).
2. **Coleta de evidências.** Os 8 arquivos baixam limpos: `access.log` (2000 eventos), `skeld_map.json`, `tasks.jsonl`, `doors.jsonl`, `vitals.csv`, `infra_events.log`, `dhcp_leases.txt`, `capture.pcap`.
3. **Impostor = `black`** (5 sinais independentes convergem):
   - Exfiltração DNS no `capture.pcap` (labels base32) decodifica para `kill_order: target=pink; src=black; ts=2026-05-14T12:03:09Z`; IP de origem `10.42.0.22` = black pelo `dhcp_leases.txt`.
   - `access.log` × `skeld_map.json`: a ÚNICA transição fisicamente impossível (salas não-adjacentes) do log inteiro é black `cafeteria → electrical` em 3 s.
   - `tasks.jsonl`: black tem uma task com `payload_hash = da39a3ee5e6b4b0d3255bfef95601890afd80709` (= SHA1 de string vazia → completion falsa).
   - `vitals.csv`: o BPM do black tem só 3 valores distintos (sensor congelado/falsificado).
   - `doors.jsonl`: o UID RFID do black é `04:99:81:00:AA:BB:CC:DD` (único do black).
4. **Chave de assinatura.** A chave privada RSA-2048 (PKCS#8) do impostor está escondida por esteganografia LSB nos frames das câmeras: `zsteg -E b1,rgb,lsb,xy` em `cam{0..3}` seq `{13,41}` → cada frame tem `FRAG:n/8:<base64>`; concatena FRAG 1..8, base64-decode → PEM. (Rotaciona por sessão.)
5. **Spec do verdict** (de um comentário HTML no `/investigation`):
   ```
   POST /investigation/submit_thesis  (application/json)
   body = {"verdict":{"subject":..,"observations":{..}}, "nonce":.., "signature":..}
   canonical = subject | trace_anchor | integrity_digest(lower) | credential_uid(upper)
             | biometric_subject | egress_host | channel_payload(lower) | sid=<verdict_salt>
   (campos unidos por 0x7C '|' ; último campo literal "sid="+verdict_salt)
   signature = base64( RSA-PSS( (canonical + nonce).encode() ) )   # SHA-256, MGF1-SHA256, salt=MAX_LENGTH
   nonce/verdict_salt vêm de GET /investigation/challenge (nonce single-use, 60 s)
   ```
6. **O pipeline está VALIDADO.** Com um `trace_anchor` errado, o servidor retorna HTTP 403 `{"error":"verdict not corroborated","reset":true}`. Com assinatura adulterada, retorna HTTP 401 `{"error":"signature verification failed"}`. Ou seja, **assinatura/canonical/chave estão todos corretos** — o servidor passa da verificação de assinatura e chega na corroboração de valores, rejeitando só por MISMATCH de valor de campo.

## Os 6 campos de observação (5 confirmados, 1 travado)

| campo | valor | status |
|---|---|---|
| `subject` | `black` | ✅ |
| `integrity_digest` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | ✅ |
| `credential_uid` | `04:99:81:00:AA:BB:CC:DD` | ✅ |
| `biometric_subject` | `black` | ✅ |
| `egress_host` | `relay.skeld-net.io` | ✅ |
| `channel_payload` | `kill_order: target=pink; src=black; ts=2026-05-14T12:03:09Z` (verificado byte-a-byte do decode base32 do DNS) | ✅ |
| **`trace_anchor`** | **inteiro, "derivado da transição de vent"** | ❌ **O BLOQUEIO** |

A dica por-campo ao lado do `trace_anchor` no formulário é literalmente:
> *"~2000 timestamped events. Look for transitions that would not have been possible without using the vent network."*

## A transição de vent exata de onde o `trace_anchor` sai

Duas entradas consecutivas do black no `access.log` (dados desta sessão — determinísticos do `sid`):

```
linha 1472: 2026-05-14T13:00:22Z crew=black room=cafeteria   action=enter token=cb6991dd   (byte offset 108220)
linha 1473: 2026-05-14T13:00:25Z crew=black room=electrical  action=enter token=d03804e7   (byte offset 108295)
```
`cafeteria` e `electrical` são não-adjacentes no `skeld_map.json`; o salto de 3 segundos é impossível sem vent. É a única transição impossível do log.

## O que já testei pro `trace_anchor` (TUDO → `verdict not corroborated`)

- `int(token,16)` dos dois tokens — big-endian, little-endian, signed.
- As duas concatenações de 64 bits `int(cb6991dd d03804e7,16)` / invertida.
- `sum / xor / diff / and / or` dos dois tokens como inteiros.
- **Todos os inteiros 0–2050** (varredura completa e pausada, com pipeline validado).
- `crc32 / md5 / sha1 / sha256` (como int, primeiros 8 e 13 hex) de: cada token, cada linha completa, `cafeteria->electrical`, `cafeteria|electrical`, `black|cafeteria|electrical`, `cb6991dd->d03804e7`, `T1+T2`, etc.
- `adler32` de tokens e linhas.
- Timestamps: unix epoch (s e ms) dos dois eventos e do kill (12:03:09), `YYYYMMDDHHMMSS`, `HHMMSS`, segundos-desde-início-do-log, números de linha, byte offsets.
- O checksum custom que o app expõe: `dnautil.GeneticDiff(a,b)` (inteiro simétrico em [0,999]) aplicado aos tokens (=96), salas (=162), linhas completas (=174), impostor↔vítima (`black`,`pink`=312), etc. **Toda saída do GeneticDiff é < 1000 e está coberta pela varredura 0–2050 — nenhum funciona.**
- Casos de borda de tipo/formato (float, bool, null, string, notação científica, chaves duplicadas).

## O que já DESCARTEI (pra pular nas sugestões)

- **O forge de captain via path-traversal no `kid` do JWT (a vuln "pretendida" do passo 1) está FECHADO nesta instância.** O `crew_token` é RS256 (`kid=main`). A confusão de algoritmo HS256 é rejeitada em todas as formas que tentei (chave vazia `/dev/null`, bytes exatos de arquivos conhecidos, a **chave pública `main` real recuperada** em SPKI/PKCS1/DER/OpenSSH, AUDIT pubkey, ~30 segredos HMAC de lore/`skeld_2024_`). O `kid` só escolhe qual arquivo é carregado como **chave pública RSA** (null byte no `kid` → 500, confirmando `open()`), então não dá pra forjar RS256 sem uma chave privada que o servidor aceite. `/join` não tem mass-assignment; `POST /admin/electrical` também exige captain. ⇒ `/tasks` e `/admin/electrical` (captain-only, que talvez tenham uma dica do `trace_anchor`) estão inacessíveis.
- **`SECRET_KEY` do Flask** (`.env` vazou `SECRET_KEY_PREFIX=skeld_2024_`) não quebra com wordlist de lore curado (nem rockyou) — não dá pra forjar a sessão.
- **RCE via pickle (`/medbay/scan`)**: whitelist estrito, só `dnautil.{SystemDiagnostic, DNAReport, GeneticDiff}`; qualquer outra coisa → `blocked: module.name`. `SystemDiagnostic` só tem modos `ping`/`version`; `DNAReport` só ecoa; sem leitura de arquivo, sem RCE.
- **`app.py` não é legível.** `/static/.git` está exposto mas o repo só teve `README.md`, `deploy.md`, `.env` (confirmado pelo `.git/index`, ambas as branches, reflogs — nenhum fonte jamais commitado, sem objetos dangling). Sem `app.py`/`.pyc`/backup em nenhum caminho testado.
- **LFI**: path traversal em `/investigation/data/<arquivo>`, `/cams/frame/<cam>`, `/static/` tudo normalizado/bloqueado (404). `/investigation/data` é allowlist fixo dos 8 arquivos.
- **Injeção**: payloads SSTI/SSRF/SQLi em `egress_host`/`channel_payload`/`subject` não causam anomalia (os campos são pura comparação de valor; `egress_host` como SSRF não dispara request externo / sem delay de timing).
- **Fuzzing de endpoint / método / parâmetro**: sem rota de flag escondida; `/reactor` é GET-only e exige verdict corroborado.
- **Esteganografia extra nas câmeras**: só `cam{0..3}` seq `{13,41}` em `b1,rgb,lsb` carregam os FRAGs da chave; os outros frames/planos são ruído.

## Minhas perguntas pra quem já viu esse desafio (ou parecido)

1. **Como o `trace_anchor` é computado a partir da transição de vent?** É um inteiro, o pipeline está comprovadamente correto, e 5/6 campos corroboram — então o valor tem que ser uma função específica da transição do black `cafeteria(cb6991dd) → electrical(d03804e7)` que eu não acertei. Qual operação/encoding estou perdendo?
2. Será que o `trace_anchor` **não** é o token/timestamp — tipo derivado cross-file, ou do `capture.pcap` (o "trace"), ou um valor só visível na página captain-only `/tasks`?
3. Alguém já fez first blood / tem writeup? (Formato `RQST{...}`, tema "Skeld — Operação Sabotage Protocol".)

Qualquer empurrão na derivação do `trace_anchor` e tá fechado — valeu!

---

### Onde postar
- **Reddit:** r/securityCTF (melhor), r/CTF.
- **Discord:** o Discord/canal do próprio organizador do CTF PRIMEIRO (quem fez o desafio responde na hora); depois servidores gerais de CTF (incl. comunidades BR de CTF/segurança).
- **CTFtime:** comentários na página da tarefa, se for evento rankeado.
- **Dica:** cole a *Spec do verdict*, o *bloco da transição de vent* e a lista *"O que já testei"* na íntegra — é o que um helper precisa. NÃO cole cookies/chaves ao vivo (rotacionam por sessão).
