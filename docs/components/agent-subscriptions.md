# Agent Subscriptions

**Status: implemented.** Both transports ship behind
`type = "claude_subscription"` / `type = "codex_subscription"`. What has
been verified against live backends, and what has not, is stated
explicitly in §2 — read that before turning either on.

Serving LLM traffic from *subscription* seats — Claude Code (Max/Team) and
Codex (ChatGPT Plus/Pro/Business) — instead of metered API keys. A seat is a
flat monthly cost with a rolling quota; a key is per-token billing. For
workloads that fit inside the quota windows, the seat is dramatically
cheaper, and a pool of seats behaves like one large rate-limited provider.

This design is drawn from two places: **AGI Gateway**
(`rapid-mono/services/agi-gateway`), a Python gateway that has run exactly
this in production against ~70 seats; and rapid-router's own router, which
already owns most of the machinery AGI Gateway had to invent.

---

## 1 · What AGI Gateway does

One OpenAI-compatible `/v1` surface over a pool of subscription accounts
("seats"). Three provider paths, two of which matter to us.

### Claude — through the agent CLI

AGI Gateway drives `claude_agent_sdk.query()`, which spawns the Claude Code
CLI as a subprocess with `CLAUDE_CODE_OAUTH_TOKEN` in its environment (from
`claude setup-token`). Everything it does follows from the transport being an
*agent*, not a model API:

| Consequence | Their handling |
|---|---|
| No `tools` parameter exists | A per-request **in-process MCP server** carries the caller's JSON Schemas; the CLI exposes them as `mcp__caller__<name>`; calls are scraped from the assistant stream and mapped back to OpenAI `tool_calls`. Every handler is an inert stub — the gateway holds the caller's schema, never their code. |
| No sampling controls | `temperature`, `max_tokens`, `stop` are silently unavailable; the request validator warns instead of forwarding. |
| No schema-less JSON mode | `json_schema` maps to the CLI's `--json-schema` and is delivered via a synthetic `StructuredOutput` tool call — with the model's ordinary prose **suppressed**, or callers get `"42\n\nThis is a simple arithmetic question…"` where they contracted for `{"answer": 42}`. `json_object` degrades to a prompt hint. |
| Multi-turn tool history | Flattened and replayed as `[tool_call id=…]` / `[tool_result for=…]` text lines. Replaying native `tool_use`/`tool_result` blocks on stdin is silently ignored by the CLI. |
| A tool-call turn "fails" | `max_turns=1` + `stop_reason=tool_use` terminates as `error_max_turns`. That is the normal terminal state for a tool call, reported as success with `finish_reason: "tool_calls"`. |
| The agent can touch the machine | Isolation is `tools=[]` (→ `--tools ""`, removes every built-in from the model's context in *every* permission mode — the load-bearing control), plus `disallowed_tools`, `strict_mcp_config=True`, `setting_sources=[]`, and no `can_use_tool` callback so anything needing approval is denied rather than prompted. Verified adversarially with unforgeable canaries. `permission_mode` is deliberately `"default"`, **not** `"plan"` — plan mode leaks Claude Code's planning persona into answers on what is meant to be a general-purpose API. |
| A generator holding a subprocess | `aclosing()` around `query()` is mandatory: a bare `break` leaves the generator suspended and the CLI subprocess is only reaped at GC time — a process leak under load. |

**The cost of this path is high** and none of it is essential — see §2.

### Codex — plain HTTP, no CLI

The Codex path never runs a subprocess. It POSTs the OpenAI **Responses API**
body to `https://chatgpt.com/backend-api/codex/responses` with the header
set the Codex CLI sends. Captured 2026-09-17 from codex-cli 0.154.0 driving
a recording endpoint (`chatgpt_base_url` plus a `requires_openai_auth`
provider), and cross-checked against `codex-rs/core/src/client.rs` at
`rust-v0.154.0`:

```
Authorization: Bearer <access_token from auth.json>
ChatGPT-Account-Id: <account_id | chatgpt_account_id from the id_token>
Version: 0.154.0
User-Agent: codex_cli_rs/0.154.0 (Linux 6.8.0; x86_64) unknown
Originator: codex_cli_rs
Session-Id: <uuid v7, one per request>
Thread-Id: <the same uuid>
X-Client-Request-Id: <the same uuid>
X-Codex-Window-Id: <the same uuid>:0
X-Codex-Routing-Hint: model=<model>
X-Codex-Turn-Metadata: {"installation_id":…,"session_id":…,"turn_id":…,"request_kind":"turn",…}
Accept: text/event-stream
Accept-Encoding: identity
```

What changed since 0.146, and why it matters: `Session_id` became
`Session-Id` and gained `Thread-Id` and `X-Client-Request-Id` carrying the
same value; `Openai-Beta: responses=experimental` is no longer sent over
HTTP (0.154 sends it only on its WebSocket transport, as
`responses_websockets=2026-02-06`); the user agent carries the platform;
and the body repeats the turn identity under `client_metadata`. `Version`
is still the model gate. The CLI's default transport against
`chatgpt.com` is now Responses-over-WebSocket with HTTP as its fallback;
the gateway speaks the HTTP path, which the backend serves unchanged.

Sent by the CLI and deliberately *not* by the gateway: `include:
["reasoning.encrypted_content"]` (asks for encrypted reasoning items to
replay next turn; a gateway replays nothing, so it would be bytes on every
response nobody reads), `x-codex-beta-features: remote_compaction_v2`
(advertises a compaction flow we do not consume), `x-codex-turn-state`
(the backend's sticky-routing token for a multi-request turn; a gateway
request is one request), and `x-openai-internal-codex-responses-lite`
with its `additional_tools` body shape (the CLI's own prompt layout;
`instructions` + `input` is still accepted, verified live).

Hard-won details, all measured against the live backend:

- **The `Version` header is a gate, not decoration.** The backend rejects an
  under-version client with `400 "The '<model>' model requires a newer
  version of Codex."` The `gpt-5.6` family needs ≥ 0.144.0.
- **`max_output_tokens` is rejected outright** (`400 Unsupported parameter`)
  despite the public Responses API accepting it. The caller's `max_tokens`
  cannot be honoured on this path.
- **Reasoning is pinned.** Left to the backend's per-model default,
  `gpt-5.6-luna` spent 35% of output tokens on reasoning and ran p50 14.5 s
  against `gpt-5.4`'s 2.1 s on the same single-turn extraction workload. They
  pin `reasoning.effort` and `text.verbosity` to `low` and let a caller raise
  the floor per request.
- **`prompt_cache_key` is how a cache is found.** The backend caches a
  request's prefix and routes on this key; two requests sharing a prefix only
  share its cache if they carry the same key, and the CLI always sends one.
  A gateway has no conversation id to send, so the key is derived instead —
  from the model, the `instructions` and the tool names, and *deliberately
  not* from `input`. Hashing the input too would mint a fresh key per chart
  and per turn, which is the one shape guaranteed to miss. Two unrelated
  conversations landing on one key is the mechanism, not a collision: they
  share the prefix that key stands for. A caller keeping its own conversation
  ids overrides it with `prompt_cache_key` in the request. Whether it is
  working is observable — `input_tokens_details.cached_tokens` is carried
  through to the usage record's cached-token column.
- **Tool calls come from `response.output_item.done`**, not from the terminal
  `response.completed` — on this backend that final event carries an *empty*
  `output` array. Reading only `response.completed` yields a 200 with no tool
  calls: a silent failure, worse than an error.
- **A refusal arrives inside a `200`.** When the backend will not serve a
  turn it still answers `200 OK`, then streams an `error` event
  (`{"type":"error","error":{"type":"service_unavailable_error","code":
  "server_is_overloaded"}}` — or `server_error` on some models) and a
  `response.failed`, then closes. Measured 2026-09-17 on 56 of 65 seats,
  every time, while the seats beside them served: the throttle is per
  account, follows the accounts driven hardest, and ignores the `Version`
  header, the reasoning knobs and the model. Read as a normal terminal
  event that stream folds to a completion with `"content": ""` and
  `finish_reason: "stop"`, which is what callers were served 92,000 times
  in one day with nothing in any log. The gateway now treats it as a `5xx`
  from that seat: the seat is benched for two minutes, the request moves
  to the next seat, and only when no seat is left does the caller see it —
  as a `503` carrying the backend's own message, never as an empty answer.
  The seats it throttled were the ones carrying the most requests at
  once, so the pool now takes a per-seat ceiling — `key_limits = {
  max_concurrency = N, rpm = M }` on the provider, overridable per seat —
  and a request past a seat's ceiling goes to the next seat rather than
  onto that one.
- **There is no document part.** The backend's content vocabulary is
  `input_text` and `input_image` and nothing else — the Codex client's own
  `ContentItem` enum has three variants and none of them is a file, so a PDF
  has no representation on this wire at all. An attached document is
  rendered to one image per page before translation (`router-media`, pure
  Rust so the release build stays a static musl binary), at
  `codex.pdf_dpi` (default 150) and capped at `codex.pdf_max_pages`
  (default 50). Pages beyond the cap are logged and counted, never silently
  cut. Anthropic and Gemini take a PDF natively and are *not* pre-rendered:
  rasterizing would throw away the text layer those APIs read.
- **`json_object` requires the word "json" in `input`**, and the backend
  checks `input` only — never `instructions`. Since a caller's "return JSON"
  wording usually lives in the system prompt (which maps to `instructions`),
  they append a short neutral hint to `input` when it is missing.
- **The reset window is nested and header-less.** `429`s arrive as
  `{"error": {"type": "usage_limit_reached", "resets_in_seconds": 562410}}`
  with no `retry-after` header at all. Reading only the top level meant every
  exhausted seat fell back to a 300 s cooldown: a seat out of *weekly* quota
  was re-probed every 5 minutes, 429'd, and re-benched — 3,947 wasted
  attempts in 24 h with 55 of 70 seats benched.
- **Refresh** is a form POST to `https://auth.openai.com/oauth/token` with
  `grant_type=refresh_token` and the Codex CLI's public client id
  (`app_EMoamEEZ73f0CkXaXp7hrann`), reactively on a `401` and proactively
  on-lease; the merged credential is written back to `auth.json` atomically.

### Seat pool mechanics

Worth stealing wholesale, because every line of it was paid for in
production:

- **Cooldown is the window the provider reported**, capped at 24 h, never a
  fixed guess.
- **Every cooldown gets 0–10% one-sided jitter.** Production showed 57 seats
  whose cooldowns all expired inside a 72-second band — they came back
  together, all 429'd, all benched together. Jitter only ever pads; returning
  early just earns another 429.
- **Lease ordering is `(needs_refresh, -priority, active, last_used, id)`** —
  a seat needing an OAuth round trip is only reached after every ready
  candidate, so a request never waits on a refresh while a healthy seat idles.
  Skipped expired seats are healed in the *background*, single-flight per seat.
- **Only a caller-visible failure marks a seat unhealthy.** A retryable error
  the router absorbed by rotating does not: transport blips hit every seat
  alike (~502 in 12 h spread evenly across 78 seats, against 74,967 `200`s),
  and reporting those as seat errors painted a rolling handful of false alarms.
- **Usage accounting has a drift guard.** Anthropic reports `input_tokens` as
  the *uncached* input only, so total prompt tokens = `input_tokens +
  cache_read_input_tokens + cache_creation_input_tokens`. If a usage payload
  arrives carrying none of the known field names, they log and fall back to an
  estimate rather than silently emitting a `$0`, `estimated=false` row.
- **Live quota is observable**: Codex via the `x-codex-*` response headers,
  Claude via `anthropic-ratelimit-unified-{5h,7d}-*`, normalized to one shape
  and TTL-cached with per-account single-flight so a public endpoint cannot
  multiply upstream quota use.

---

## 2 · What was verified live

Spiked 2026-08-15 against real credentials, before any of this was built.

### Claude — the finding the design turns on

**A Claude Code OAuth token authenticates directly against
`https://api.anthropic.com/v1/messages`.** No CLI, no Agent SDK, no
subprocess:

```
authorization: Bearer <sk-ant-oat01-…>
anthropic-version: 2023-06-01
anthropic-beta: oauth-2025-04-20
```

**Confirmed, end to end.** Once the account's quota window rolled, the
full matrix passed through the built gateway against the live backend on
`claude-sonnet-4-5`: text completions with real usage counts, streaming
(`chat.completion.chunk` frames terminating in `[DONE]`), tool calls with
parseable arguments, and the caller's own system prompt still steering the
answer. Everything the design claimed would keep working, does.

**The identity block is load-bearing — and this is the finding to
remember.** Measured 2026-08-16, on an account with a completely fresh
quota window:

| Model | With the Claude Code identity | Without it |
|---|---|---|
| `claude-sonnet-4-5` | `200` | **`429`** |
| `claude-haiku-4-5` | `200` | `200` |

The refusal arrives as `{"type":"rate_limit_error","message":"Error"}` — a
rejection wearing a rate limit's clothes, on an account using 0% of its
window. Two consequences worth internalizing:

1. **A gateway tested only on Haiku would look correct and then fail on the
   model people actually use.** Haiku serves identity-less requests
   happily.
2. **A naive implementation would bench a perfectly healthy seat** on that
   `429` and conclude the pool was exhausted. Ours does not, because the
   fake `429` carries **no `anthropic-ratelimit-unified-*` headers at
   all** while a real one carries twelve — and the bench only fires on a
   window the provider actually reported. That defensive choice was made
   for a different reason and happens to be exactly what saves this case.

**The `anthropic-beta: oauth-2025-04-20` header is not required.** It was
assumed to be what admits the token; measured across the identity × beta ×
model matrix, it changes nothing in any cell. The gateway still sends it —
matching the vendor's client is the whole strategy, and an inert flag today
may gate something tomorrow — but it is not what makes this work. The
identity block is.

**Prepending, not substituting, is correct.** With the identity block
leading and a pirate persona second, "what is 2+2" came back as *"Ahoy
there! 2+2 be 4, as sure as the sea be salty!"* — the caller's instructions
survive intact.

The rate-limit headers were captured in full and are what the bench logic
reads:

```
retry-after: 3311
anthropic-ratelimit-unified-5h-utilization: 1.01
anthropic-ratelimit-unified-5h-status: rejected
anthropic-ratelimit-unified-5h-reset: 1786819200      (absolute epoch)
anthropic-ratelimit-unified-7d-utilization: 0.22
anthropic-ratelimit-unified-representative-claim: five_hour
```

Note `retry-after` **is** present on this path — the design assumed it
would have to be derived from `-reset`.

### Claude — credentials do expire

The stored credential carries `accessToken`, `refreshToken`, `expiresAt`
(milliseconds) and `refreshTokenExpiresAt`. The access token observed had
**~3 hours** left and the refresh token **~28 days**. So a Claude seat is
not the long-lived static token the design assumed: it needs renewal, and
the gateway does not yet implement that flow (§5).

### Codex — the whole loop works

- **Request:** the CLI header set against
  `https://chatgpt.com/backend-api/codex/responses` is accepted.
- **Rate limiting confirmed exactly as documented.** An exhausted seat
  answers **with no `retry-after` header at all** and the window nested in
  the body:
  ```json
  {"error": {"type": "usage_limit_reached", "plan_type": "pro",
             "resets_at": 1787196530, "resets_in_seconds": 380612}}
  ```
  The same window is *also* in `x-codex-primary-reset-after-seconds`, which
  is what the gateway reads — a header costs nothing to check and does not
  require buffering an upstream body on the hot path.
- **Refresh verified end to end** against a live credential: `POST
  https://auth.openai.com/oauth/token`, `grant_type=refresh_token` with the
  CLI's public client id, `200` in ~0.6s. The response rotates the refresh
  token and carries two fields nothing documents: `expires_in` (864000 —
  ten days) and `earliest_refresh_at`. The merged document was written back
  atomically and the renewed token accepted by the backend.
- **Expired seats fail closed.** Five stale credentials all answered
  `401 invalid_refresh_token` — a dead seat is dead, and no amount of
  retrying revives it.

### Through the built gateway

Re-run after implementation, with the gateway pointed at both real
backends (both seats still quota-exhausted, which is what makes this a
useful test of the *quota* path):

- **Codex.** The request reached the backend and was refused on quota, not
  auth. The reported window — 380,613s, a weekly quota — was clamped to the
  24h ceiling and jittered to **89,096s**, and the seat was benched. The
  next request was refused **in 8ms without touching upstream**, with
  `429 every seat of provider 'codex' is out of quota`.
- **Claude.** Same path, benched for **1,321s** — matching the live
  `retry-after` to the second.

That is the whole quota mechanism (header parsing → clamp → jitter → bench
→ pool-exhausted answer) verified against real responses.

**Not confirmed:** streaming text, tool calls, and the empty-`output`
`response.completed` were **not** observed live — every available Codex
seat was quota-exhausted (weekly window, ~4 days to reset). Those
behaviours are implemented against the recorded contract from AGI
Gateway's production experience and covered by a mock that reproduces
them, including the empty terminal `output` array. They are the highest
residual risk in this feature.

## 3 · How it works

### 3.1 Seats are keys

The insight that keeps this small: AGI Gateway had to build `AccountPool`
because it had no router. We already have one. A subscription seat maps onto
an existing `ApiKey` entry, so weighted selection, per-key health atomics,
circuit breakers, per-provider semaphores, fallback chains, metering, and the
virtual-key layer all apply unchanged.

Generate each Claude seat's credential with `claude setup-token` — a
long-lived token (the CLI prints "valid for 1 year"), which is what makes
the absent refresh flow a non-issue. Do **not** lift the short-lived
session token out of the Claude Code keychain entry; see §5.

```toml
[providers.claude-max]
type = "claude_subscription"
keys = [
  { name = "seat-1", value = "env.CLAUDE_CODE_OAUTH_TOKEN_1" },
  { name = "seat-2", value = "store.claude_seat_2" },
]

[providers.codex]
type = "codex_subscription"
# Both floors default to "low" — spelled out here only to show the knob.
# Raise them if you want the thinking; a caller can also raise either
# per request. Leaving them to the backend's own per-model defaults is
# what costs 14.5 s where 2.1 s would do.
codex = { version = "0.154.0", reasoning_effort = "low", verbosity = "low" }
keys = [
  { name = "seat-1", value = "file:/etc/rapid/codex/seat-1/auth.json" },
  { name = "seat-2", value = "file:/etc/rapid/codex/seat-2/auth.json" },
]

[fallbacks]
# subscription first, metered API as the overflow — the whole point
"claude-max/claude-sonnet-4-5" = ["anthropic/claude-sonnet-4-5"]
```

Because a seat is a key, a pool of seats can be *allocated*: each seat carries
the name of the service that owns it, and a request may spend only the seats
whose label matches — instead of the pool going to whoever asks first. No
borrowing and no priority: a service that has exhausted its own seats is
refused while another's sit idle ([account-pools.md](account-pools.md)).

Two new `ProviderKind`s (`ClaudeSubscription`, `CodexSubscription`) with
`wire_dialect` returning `Anthropic` and a Responses-shaped outbound
respectively. Model resolution, aliasing, and the console are unaffected.

### 3.2 What the key layer grew

Four capabilities a metered `ApiKey` never needed. This was the real
build.

1. **Credentials that change.** A key's secret is immutable today; an
   `auth.json` access token rotates. Introduce a `Credential` behind the key —
   an enum of `Static(SecretString)` and `Refreshable { … }` — read through an
   `ArcSwap` so a refresh publishes a new value without blocking readers.
2. **Refresh, proactive and reactive.** Refresh ~2 min before `exp` (decoded
   from the access token's JWT claim) and on a `401`, single-flight per key,
   off the request path where possible. Write the merged credential back
   atomically; a malformed refresh payload must leave the file untouched.
   *File-backed only* — an env/inline credential has nowhere to persist a
   refresh, so "refreshing" it would succeed upstream and change nothing on
   re-read, burning an OAuth round trip per lease.
3. **Cooldown until a deadline.** Our breaker opens for a configured duration;
   a rate-limited seat must stay out for the window the *provider* reported.
   Add `open_until(Instant)` to the breaker, fed by:
   - Codex: `retry-after` header, then body — top level **and** nested under
     `error` (`resets_in_seconds`, `retry_after`, `retry_after_seconds`).
   - Claude: `anthropic-ratelimit-unified-*-reset`.
   Clamp to `[1 s, 24 h]` and apply 0–10% one-sided jitter. Both the nesting
   and the jitter are non-obvious and both were production incidents.
4. **Fleet-safe secrets.** Seat credentials live in the store sealed under
   `RAPID_MASTER_KEY` like any other `store.*` secret, so any node can read
   what any node wrote. A refreshed token must be written through the store
   (CAS) rather than to node-local disk, or two nodes will fight over one
   `auth.json` and invalidate each other's refresh token.

### 3.3 Claude subscription provider

- **Auth**: `authorization: Bearer <oauth token>`, `anthropic-version`,
  `anthropic-beta: oauth-2025-04-20` (merged with any beta the client asked
  for). Never `x-api-key`.
- **Identity pinning**: prepend the Claude Code system block to the request's
  `system` array. Configurable, defaulted on, and *always* logged in the
  dropped/injected-params accounting so it is never invisible.
- **Everything else is the existing Anthropic path.** Translation, SSE, tool
  calls, caching headers, error mapping — unchanged code.
- **Health**: parse `anthropic-ratelimit-unified-{5h,7d}-{utilization,reset,status}`
  off every response into per-key gauges, so quota is observable without a
  probe. Probe only for the console's seat view, TTL-cached.

### 3.4 Codex subscription provider

- **Credential**: `auth.json` (`access_token`, `refresh_token`, and
  `account_id` or an `id_token` carrying `chatgpt_account_id`).
- **Headers**: the exact Codex CLI set from §1, with `version` configurable
  per provider — it is a compatibility gate that moves when OpenAI ships a
  model family, and it must not require a rapid-router release to bump.
- **Body**: our existing Responses translation, plus `store: false`,
  `stream: true`, `instructions` from the system prompt, the flattened
  Responses tool shape (`{"type":"function","name",…}`, not the Chat
  Completions nesting), `reasoning.effort` / `text.verbosity` from config with
  a per-request override, and **no `max_output_tokens`** — dropped with an
  entry in `dropped_params`, never silently.
- **Streaming is native.** AGI Gateway buffers the whole SSE body
  (`response.text`) and re-emits it; we stream it, which is the entire point
  of our SSE path. Tool calls are read from `response.output_item.done` as
  they arrive.
- **Errors**: `429` / `usage_limit_reached` → rate-limit class with the parsed
  window; `401` → auth class, one refresh, then retry once on the same key
  before rotating; transport failures (truncated SSE, read timeout) →
  **retryable**, because `store: false` makes re-issuing safe.

### 3.4a The canary

A check asks a seat for one token of "hi", which proves the credential and
little else: a seat can pass it and still stall, truncate or refuse a real
turn. The canary asks **every Codex seat** a question that needs a detailed
answer, on a fixed beat, and keeps what it learns.

```bash
rapid-router --canary-interval-secs 5      # or RAPID_CANARY_INTERVAL_SECS=5
curl -H "Authorization: Bearer $ADMIN_KEY" http://localhost:8080/admin/api/canary
```

- **Questions** are the 100 lines of
  [`canary_questions.txt`](../../crates/router-server/src/canary_questions.txt),
  one picked at random per ask. Edit the file to change them.
- **One question per seat at a time.** A seat still answering when the next
  tick lands is skipped for that tick. Starts are spread across the interval
  rather than fired together.
- **Benched seats are not asked.** They are counted as `benched` until their
  quota window rolls.
- **It is real traffic to the seat.** Each ask goes through the check's own
  path, so it settles the breaker and the seat's recorded state as a check
  does, and it spends the seat's plan quota. Every seat every five seconds
  with detailed answers is a lot of quota; widen the interval if seats start
  benching on it.
- **Per node.** Every node started with the flag runs its own canary, so in
  a fleet set it on one node.
- **What it reports:** per seat, how many asks succeeded and failed, p50/p95
  answer time over the last 50 answers, and the last question with its
  status, time to headers, total time, answer length, output tokens and the
  first 400 characters of the answer. Also as Prometheus
  `rapid_canary_total{provider,key,status}` and
  `rapid_canary_duration_seconds{provider,key}`, and one `canary answer` log
  line per ask. Canary asks are not written to request history or usage.

### 3.5 What we deliberately do not build

- **No agent CLI transport.** Not for Claude (§2 removes the need), and not
  for Codex (never needed one). No Node runtime, no subprocess supervision, no
  MCP tool emulation, no `--tools ""` sandbox to defend. If a future
  subscription is *only* reachable through a CLI, it gets a separate design
  with its own threat model — it does not get bolted onto this one.
- **No seat pool.** The router is the pool.
- **No new dialect.** Both paths reuse adapters that already ship.

---

## 4 · What this is not good for

Stated up front because the failure mode is a surprised operator:

- **Subscription terms.** Seats are licensed for interactive coding use.
  Pooling them behind a shared gateway for application traffic is a decision
  with contractual and account-suspension risk that belongs to whoever runs
  the deployment, not to the gateway. This ships **off by default** and
  documents the risk at the point of configuration.
- **Throughput.** Quota windows are rolling and per-seat; a pool of seats is a
  cheap *bulk* capacity tier, not a low-latency production tier. The right
  shape is subscription-first with a metered-API fallback chain, which is
  exactly what `[fallbacks]` already expresses.
- **Fidelity.** The Codex path cannot honour `max_tokens` and pins reasoning
  by default. Those land in `dropped_params` and the capability matrix.
- **Identity pinning is load-bearing on Claude.** A request whose system
  prompt does not lead with the Claude Code identity may be refused. That
  constraint is visible to callers, not hidden.

---

## 5 · What is not done

1. **Claude credential renewal — mostly moot, if you use a setup token.**
   The gateway implements no refresh for Claude (only Codex has one), so a
   seat serves until its token expires and then answers `401`. How much
   that matters depends entirely on which credential you configure:

   - **`claude setup-token` (recommended).** The CLI describes it as "a
     long-lived authentication token" and prints *"Your OAuth token (valid
     for 1 year)"*. Renewal becomes an annual operator task, not a
     background service, and the missing refresh flow costs nothing.
   - **A session credential lifted from the Claude Code keychain entry.**
     The one observed had **~3 hours** left. Configuring that is how you
     get a seat that dies the same afternoon.

   Implementing refresh for the session credential would mean guessing at
   an undocumented endpoint with a token that cannot be re-obtained without
   an operator, which is why it waits. With setup tokens there is little
   reason to want it.

   The gateway cannot warn you before the cliff either way: a Claude token
   is opaque, not a JWT, so it carries no readable expiry and
   `expires_at_ms` is `None` — the seat is simply healthy until the first
   `401`. Diarize the renewal.
2. **Codex behaviour is mock-verified, not live-verified.** Streaming,
   tool calls, and the empty-`output` terminal event are implemented from a
   recorded contract (§2). The mock reproduces them and the tests fail if
   the load-bearing branch is removed, but no *successful* live Codex
   response has passed through this code — every available seat was out of
   weekly quota. The credential, headers, refresh loop, and quota handling
   **are** live-verified; only the success path is not. Re-run
   `live_subscriptions` with `LIVE_CODEX_AUTH_JSON` set once a seat has
   quota. **This is the highest residual risk in the feature.**
3. **Fleet.** Seat credentials are read from local files and renewed
   locally. Two nodes pointed at one `auth.json` will rotate each other's
   refresh token into the bin. Until the credential lives in the store with
   a single-winner refresh, run subscription providers on **one node**, or
   give each node its own seats.
4. **Cost attribution.** Seat traffic is metered like key traffic, so a
   seat's requests price at the model's per-token rate rather than an
   amortized share of the subscription. The token counts are right; the
   dollars are not.
5. **Console.** No seat view yet: quota utilization and bench state are
   exported as metrics (`rapid_seat_quota_utilization`,
   `rapid_seat_bench_seconds`) but not rendered anywhere.

## 6 · Where the code is

| Piece | Where |
|---|---|
| Credential parsing, expiry, refresh merge | [`router-core/src/credential.rs`](../../crates/router-core/src/credential.rs) |
| Bench windows, jitter, rate-limit headers | [`router-core/src/quota.rs`](../../crates/router-core/src/quota.rs) |
| Deadline benching in the breaker | [`router-core/src/breaker.rs`](../../crates/router-core/src/breaker.rs) |
| Headers, request shaping, stream translation | [`router-providers/src/subscription.rs`](../../crates/router-providers/src/subscription.rs) |
| OAuth renewal, atomic write-back, single-flight | [`router-server/src/refresh.rs`](../../crates/router-server/src/refresh.rs) |
| The canary: a detailed question to every Codex seat | [`router-server/src/canary.rs`](../../crates/router-server/src/canary.rs) |
| End-to-end behaviour | [`router-server/tests/e2e_subscriptions.rs`](../../crates/router-server/tests/e2e_subscriptions.rs) |

## See also

- [provider-adapters.md](provider-adapters.md) — the `Provider` seam these plug into
- [router.md](router.md) — key selection, breakers, fallback chains
- [../operations/fleet.md](../operations/fleet.md) — the store these credentials must live in
- [../providers.md](../providers.md) — capability matrix
