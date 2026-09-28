//! Subscription seats end to end: a Claude Code credential and a Codex
//! credential serving ordinary `/v1/chat/completions` traffic.
//!
//! These assert the things that make a subscription transport different
//! from a metered one — the credential presented, the headers that admit
//! it, the identity it must carry, and what happens when a seat runs out
//! of quota — because none of that is covered by the dialect suites the
//! rest of the gateway is tested with.

use mock_provider::MockProvider;
use router_core::config::{Config, Format};
use router_server::{AppState, build_router};
use serde_json::{Value, json};

/// No ambient environment: every credential in these tests is inline or
/// file-backed, so a stray `ANTHROPIC_API_KEY` on the runner cannot
/// change what is under test.
struct NoEnv;
impl router_core::config::EnvSource for NoEnv {
    fn get(&self, _name: &str) -> Option<String> {
        None
    }
}

/// A Codex `auth.json`, with a JWT-shaped access token whose `exp` is far
/// enough out that nothing tries to renew it mid-test.
fn codex_auth_json(exp_secs: u64) -> String {
    codex_auth_json_for(exp_secs, "acct-test")
}

/// The same, for a named account — the header the backend tells seats
/// apart by, and so the one a per-seat refusal is keyed on.
fn codex_auth_json_for(exp_secs: u64, account: &str) -> String {
    use base64::Engine;
    let encode = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let jwt = |claims: Value| {
        format!(
            "{}.{}.{}",
            encode(br#"{"alg":"RS256"}"#),
            encode(claims.to_string().as_bytes()),
            encode(b"sig")
        )
    };
    json!({
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": jwt(json!({"exp": exp_secs})),
            "refresh_token": "rt.1.AAAtest",
            "id_token": jwt(json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": account}
            })),
            "account_id": account
        }
    })
    .to_string()
}

/// A Codex pool of several seats, each its own account.
async fn codex_pool(accounts: &[&str]) -> (String, MockProvider, tempfile::TempDir) {
    codex_pool_with(accounts, "").await
}

/// The same, with extra lines in the provider table — a `key_limits`,
/// say.
async fn codex_pool_with(
    accounts: &[&str],
    provider_extra: &str,
) -> (String, MockProvider, tempfile::TempDir) {
    let mock = MockProvider::spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let keys: Vec<String> = accounts
        .iter()
        .map(|account| {
            let path = dir.path().join(format!("{account}.json"));
            std::fs::write(&path, codex_auth_json_for(4_000_000_000, account)).unwrap();
            format!(
                r#"{{ name = "{account}", value = "file:{}" }}"#,
                path.display()
            )
        })
        .collect();
    let config = Config::from_str_with_env(
        &format!(
            r#"
[providers.codex]
type = "codex_subscription"
base_url = "{base}"
codex = {{ version = "0.199.0", reasoning_effort = "medium" }}
keys = [{keys}]
{provider_extra}
"#,
            base = mock.base_url(),
            keys = keys.join(", "),
        ),
        Format::Toml,
        &NoEnv,
    )
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        router_server::serve(listener, state, app, std::future::pending())
            .await
            .unwrap()
    });
    (url, mock, dir)
}

async fn gateway() -> (String, MockProvider, tempfile::TempDir) {
    let mock = MockProvider::spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(&auth_path, codex_auth_json(4_000_000_000)).unwrap();

    let config = Config::from_str_with_env(
        &format!(
            r#"
[providers.claude-max]
type = "claude_subscription"
base_url = "{base}"
keys = [{{ name = "seat-1", value = "sk-ant-oat01-test-seat" }}]

[providers.codex]
type = "codex_subscription"
base_url = "{base}"
codex = {{ version = "0.199.0", reasoning_effort = "medium" }}
keys = [{{ name = "seat-1", value = "file:{auth}" }}]

[console]
admin_keys = ["probe-test-key"]
"#,
            base = mock.base_url(),
            auth = auth_path.display(),
        ),
        Format::Toml,
        &NoEnv,
    )
    .unwrap();

    let state = AppState::new(config);
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        router_server::serve(listener, state, app, std::future::pending())
            .await
            .unwrap()
    });
    (url, mock, dir)
}

async fn chat(url: &str, body: Value) -> (reqwest::StatusCode, Value) {
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status();
    let text = res.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})),
    )
}

// ---------------------------------------------------------------------------
// Claude
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claude_seat_presents_a_bearer_token_and_the_oauth_beta() {
    let (url, mock, _dir) = gateway().await;
    let (status, body) = chat(
        &url,
        json!({"model": "claude-max/claude-sonnet-4-5",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let request = mock.last_request();
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer sk-ant-oat01-test-seat"),
        "a subscription token is a bearer, never an x-api-key",
    );
    assert_eq!(
        request.api_key, None,
        "sending x-api-key alongside would be a second, wrong credential",
    );
    assert!(
        request
            .header("anthropic-beta")
            .is_some_and(|v| v.contains("oauth-2025-04-20")),
        "without the OAuth beta the token is not accepted as an inference credential",
    );
    assert!(request.header("anthropic-version").is_some());
}

#[tokio::test]
async fn claude_seat_pins_the_claude_code_identity_ahead_of_the_caller_prompt() {
    let (url, mock, _dir) = gateway().await;
    let (status, _) = chat(
        &url,
        json!({"model": "claude-max/claude-sonnet-4-5",
               "messages": [
                   {"role": "system", "content": "You are a pirate."},
                   {"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200);

    let system = mock.last_request().body["system"].clone();
    let blocks = system.as_array().expect("system is a block array");
    assert_eq!(
        blocks[0]["text"], "You are Claude Code, Anthropic's official CLI for Claude.",
        "the token is authorized for the Claude Code identity",
    );
    assert_eq!(
        blocks[1]["text"], "You are a pirate.",
        "the caller's prompt survives as its own block",
    );
}

#[tokio::test]
async fn a_caller_beta_rides_along_with_the_oauth_beta() {
    let (url, mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!("{url}/anthropic/v1/messages"))
        .header("anthropic-beta", "prompt-caching-2024-07-31")
        .json(
            &json!({"model": "claude-max/claude-sonnet-4-5", "max_tokens": 16,
                      "messages": [{"role": "user", "content": "hi"}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let betas = mock
        .last_request()
        .header("anthropic-beta")
        .unwrap()
        .to_owned();
    assert!(betas.contains("oauth-2025-04-20"), "{betas}");
    assert!(
        betas.contains("prompt-caching-2024-07-31"),
        "dropping the caller's beta would silently disable their caching: {betas}",
    );
}

#[tokio::test]
async fn claude_seat_streams_like_any_other_anthropic_target() {
    let (url, _mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(
            &json!({"model": "claude-max/claude-sonnet-4-5", "stream": true,
                      "messages": [{"role": "user", "content": "hi"}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("chat.completion.chunk"), "{body}");
    assert!(body.contains("[DONE]"));
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

#[tokio::test]
async fn codex_seat_presents_the_cli_header_set() {
    let (url, mock, _dir) = gateway().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let request = mock.last_request();
    assert_eq!(request.path, "/backend-api/codex/responses");
    assert_eq!(
        request.header("chatgpt-account-id"),
        Some("acct-test"),
        "the account id is decoded from the credential, not configured",
    );
    assert_eq!(
        request.header("version"),
        Some("0.199.0"),
        "the configured version must reach the backend — it is a model gate",
    );
    let ua = request.header("user-agent").unwrap();
    assert!(
        ua.starts_with("codex_cli_rs/0.199.0 (") && ua.ends_with(") unknown"),
        "the 0.154 user agent carries the platform: {ua}"
    );
    assert_eq!(request.header("originator"), Some("codex_cli_rs"));
    // The turn's identity, as codex-cli 0.154.0 sends it: one id on
    // three headers, and the same id inside the body.
    let session = request.header("session-id").expect("session-id");
    assert!(!session.is_empty());
    assert_eq!(request.header("thread-id"), Some(session));
    assert_eq!(request.header("x-client-request-id"), Some(session));
    assert_eq!(
        request.header("x-codex-window-id").unwrap(),
        format!("{session}:0")
    );
    assert_eq!(
        request.header("x-codex-routing-hint"),
        Some("model=gpt-5.5")
    );
    let metadata: Value =
        serde_json::from_str(request.header("x-codex-turn-metadata").unwrap()).unwrap();
    assert_eq!(metadata["session_id"], session);
    assert_eq!(metadata["request_kind"], "turn");
    assert_eq!(
        request.body["client_metadata"]["session_id"], session,
        "the body names the same session the headers do"
    );
    assert_eq!(
        request.header("openai-beta"),
        None,
        "0.154 sends this only on its websocket transport"
    );
    assert_eq!(request.header("session_id"), None, "renamed to session-id");
    assert!(
        request
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("Bearer ey"),
        "the access token out of auth.json, not the document itself",
    );
}

#[tokio::test]
async fn codex_body_is_the_responses_shape_the_backend_accepts() {
    let (url, mock, _dir) = gateway().await;
    let (status, _) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "max_tokens": 100,
               "messages": [
                   {"role": "system", "content": "Be terse."},
                   {"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200);

    let body = mock.last_request().body;
    assert_eq!(body["store"], false);
    assert_eq!(
        body["stream"], true,
        "this backend has no non-streaming mode"
    );
    assert_eq!(body["instructions"], "Be terse.");
    assert_eq!(body["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(
        body["reasoning"]["effort"], "medium",
        "the configured floor, not the built-in default",
    );
    assert!(
        body.get("max_output_tokens").is_none(),
        "the backend 400s on this parameter, so max_tokens cannot be carried",
    );
}

#[tokio::test]
async fn a_codex_tool_call_survives_the_empty_completed_output() {
    // The failure this guards is silent: read only response.completed and
    // the caller gets a 200 with no tool_calls at all.
    let (url, _mock, _dir) = gateway().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5",
               "messages": [{"role": "user", "content": "weather?"}],
               "tools": [{"type": "function", "function": {
                   "name": "get_weather",
                   "parameters": {"type": "object"}}}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let call = &body["choices"][0]["message"]["tool_calls"][0];
    assert_eq!(call["id"], "call_mock", "{body}");
    assert_eq!(call["function"]["name"], "get_weather");
    assert_eq!(call["function"]["arguments"], "{\"city\":\"SF\"}");
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");
}

#[tokio::test]
async fn a_codex_stream_is_aggregated_for_a_non_streaming_caller() {
    let (url, _mock, _dir) = gateway().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["choices"][0]["message"]["content"], "Hello from Codex",
        "the caller asked for a whole response; the backend only speaks SSE",
    );
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 11);
    assert_eq!(body["usage"]["completion_tokens"], 3);
}

#[tokio::test]
async fn codex_streams_through_to_a_streaming_caller() {
    let (url, _mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(&json!({"model": "codex/gpt-5.5", "stream": true,
                      "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("chat.completion.chunk"), "{body}");
    assert!(body.contains("Hello"), "{body}");
    assert!(body.contains("[DONE]"));
}

// ---------------------------------------------------------------------------
// Refusals inside a 200
// ---------------------------------------------------------------------------
//
// The Codex backend does not refuse a turn with a status code. It answers
// `200 OK`, then streams an `error` and a `response.failed` where the
// output would be. Measured 2026-09-17 on 56 of 65 seats, every time, while
// the seats beside them served: a per-account throttle wearing a `200`.
// Read as a normal terminal event, that stream folds to a completion with
// empty content — which is what callers were served, 92,000 times in a
// day, with nothing in any log.

/// Which accounts the mock was asked to serve, in order.
fn accounts_hit(mock: &MockProvider) -> Vec<String> {
    mock.requests()
        .iter()
        .map(|r| {
            r.headers
                .get("chatgpt-account-id")
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

#[tokio::test]
async fn a_refused_stream_is_an_error_not_an_empty_completion() {
    let (url, mock, _dir) = codex_pool(&["acct-a"]).await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/refuse-all",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(
        status, 503,
        "a refusal is an error, whatever the status line said: {body}"
    );
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("server_is_overloaded") && message.contains("overloaded"),
        "the caller is told what the backend said: {body}"
    );
    assert!(
        body["choices"].is_null(),
        "and is not handed an empty assistant turn: {body}"
    );

    // The seat that was refused is held out: the next request does not
    // go upstream at all, and is refused here rather than served empty.
    let hits = mock.request_count();
    let (status, body) = chat(
        &url,
        json!({"model": "codex/refuse-all",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert_eq!(
        mock.request_count(),
        hits,
        "a benched seat is not re-probed"
    );
}

#[tokio::test]
async fn a_refused_seat_is_stepped_over_for_one_that_serves() {
    let (url, mock, _dir) = codex_pool(&["acct-a", "acct-b"]).await;
    // Only acct-a is throttled; acct-b serves the same model normally.
    for _ in 0..4 {
        let (status, body) = chat(
            &url,
            json!({"model": "codex/refuse-acct-a",
                   "messages": [{"role": "user", "content": "hi"}]}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["choices"][0]["message"]["content"], "Hello from Codex",
            "the caller gets the answer the working seat produced: {body}"
        );
    }
    let hit = accounts_hit(&mock);
    let refused = hit.iter().filter(|a| *a == "acct-a").count();
    assert!(
        refused <= 1,
        "the throttled seat is discovered once and then stepped over, not re-tried \
         on every request: {hit:?}"
    );
    assert!(
        hit.iter().filter(|a| *a == "acct-b").count() >= 4,
        "{hit:?}"
    );
}

#[tokio::test]
async fn a_refused_stream_ends_with_an_error_frame_for_a_streaming_caller() {
    let (url, mock, _dir) = codex_pool(&["acct-a"]).await;
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(&json!({"model": "codex/refuse-all", "stream": true,
                      "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    // The headers were sent before the backend refused, so the status is
    // the one honest thing that cannot change. The body can.
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(
        body.contains(r#""code":"server_is_overloaded""#),
        "the refusal reaches the caller as an OpenAI error frame: {body}"
    );
    assert!(
        !body.contains(r#""finish_reason":"stop""#),
        "and is never dressed up as a clean stop: {body}"
    );

    // Holding the seat out does not depend on the sync path having seen
    // the body.
    let hits = mock.request_count();
    let (status, _) = chat(
        &url,
        json!({"model": "codex/refuse-all",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_ne!(status, 200);
    assert_eq!(
        mock.request_count(),
        hits,
        "a seat refused mid-stream is benched too"
    );
}

// ---------------------------------------------------------------------------
// What the log records about a seat
// ---------------------------------------------------------------------------

/// A one-seat pool whose usage records land on disk, with an admin key to
/// read them back through the console API.
async fn logged_codex_pool() -> (String, MockProvider, tempfile::TempDir) {
    let mock = MockProvider::spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("acct-a.json");
    std::fs::write(&auth_path, codex_auth_json_for(4_000_000_000, "acct-a")).unwrap();
    let config = Config::from_str_with_env(
        &format!(
            r#"
[providers.codex]
type = "codex_subscription"
base_url = "{base}"
codex = {{ version = "0.199.0", reasoning_effort = "medium" }}
keys = [{{ name = "seat-alpha", value = "file:{auth}" }}]

[console]
admin_keys = ["probe-test-key"]
"#,
            base = mock.base_url(),
            auth = auth_path.display(),
        ),
        Format::Toml,
        &NoEnv,
    )
    .unwrap();
    let state = AppState::with_data_dir(config, dir.path().to_path_buf());
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        router_server::serve(listener, state, app, std::future::pending())
            .await
            .unwrap()
    });
    (url, mock, dir)
}

/// The first usage record the console API lists, once the flusher has
/// written it.
async fn first_logged_request(url: &str) -> Value {
    let client = reqwest::Client::new();
    let mut last = Value::Null;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let listing: Value = client
            .get(format!("{url}/admin/api/requests?limit=5&since_ms=0"))
            .bearer_auth("probe-test-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(first) = listing["data"].as_array().and_then(|a| a.first()) {
            return first.clone();
        }
        last = listing;
    }
    panic!("the request must appear in the log; listing was: {last}")
}

#[tokio::test]
async fn the_log_names_the_seat_and_the_reasoning_effort_that_served() {
    let (url, _mock, _dir) = logged_codex_pool().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let record = first_logged_request(&url).await;
    assert_eq!(
        record["account"], "seat-alpha",
        "the record says which seat spent this request: {record}"
    );
    assert_eq!(
        record["reasoning_effort"], "medium",
        "the effort recorded is the one that went upstream — the provider's floor, \
         which the caller's body never mentioned: {record}"
    );
}

#[tokio::test]
async fn a_callers_own_effort_is_the_one_recorded() {
    let (url, mock, _dir) = logged_codex_pool().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "reasoning_effort": "high",
               "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(mock.last_request().body["reasoning"]["effort"], "high");
    let record = first_logged_request(&url).await;
    assert_eq!(record["reasoning_effort"], "high", "{record}");
}

// ---------------------------------------------------------------------------
// What a check can see
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_check_sees_through_a_refusal_inside_a_200() {
    let (url, mock, _dir) = codex_pool_with(
        &["acct-a"],
        "\n[console]\nadmin_keys = [\"probe-test-key\"]\n",
    )
    .await;
    let result = probe(&url, "codex", "refuse-all").await;
    let seat = &result;
    assert_eq!(seat["http_status"], 200, "{result}");
    assert_eq!(
        seat["status"], "provider_error",
        "a 200 that refuses inside the stream is not a pass: {seat}"
    );
    assert!(
        seat["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("server_is_overloaded"),
        "and the console is told what the backend said: {seat}"
    );

    // The check leaves the router knowing what it learned: the seat is
    // held out, so the next request does not go upstream.
    let hits = mock.request_count();
    let (status, _) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_ne!(status, 200);
    assert_eq!(mock.request_count(), hits);
}

#[tokio::test]
async fn a_check_steps_past_a_model_the_plan_no_longer_serves() {
    let mock = MockProvider::spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("acct-a.json");
    std::fs::write(&auth_path, codex_auth_json_for(4_000_000_000, "acct-a")).unwrap();
    let config = Config::from_str_with_env(
        &format!(
            r#"
[providers.codex]
type = "codex_subscription"
base_url = "{base}"
keys = [{{ name = "seat-a", value = "file:{auth}", models = ["unsupported-model", "gpt-5.5"] }}]

[console]
admin_keys = ["probe-test-key"]
"#,
            base = mock.base_url(),
            auth = auth_path.display(),
        ),
        Format::Toml,
        &NoEnv,
    )
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        router_server::serve(listener, state, app, std::future::pending())
            .await
            .unwrap()
    });

    // First in the list is a model the backend refuses for this plan;
    // the check must not fail the seat over it.
    let result = probe(&url, "codex", "").await;
    let seat = &result;
    assert_eq!(seat["status"], "ok", "{result}");
    assert_eq!(
        seat["model"], "gpt-5.5",
        "the model that actually answered: {seat}"
    );

    // Asked for that model explicitly, the check reports the backend's
    // own words rather than a bare status line.
    let result = probe(&url, "codex", "unsupported-model").await;
    let seat = &result;
    assert_eq!(seat["status"], "rejected", "{seat}");
    assert!(
        seat["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("not supported when using Codex with a ChatGPT account"),
        "{seat}"
    );
}

// ---------------------------------------------------------------------------
// Per-seat ceilings
// ---------------------------------------------------------------------------
//
// Selection already levels requests across seats exactly. What it did not
// bound was how many requests one seat carries at once, and the provider
// throttled the seats leaned on hardest. `key_limits.max_concurrency` is
// that bound: a request past a seat's ceiling goes to another seat, and
// when every seat is at its ceiling the caller is told to try again
// shortly rather than a seat being asked to take one more.

/// Fire `n` requests for `model` at once and collect their statuses.
async fn concurrent(url: &str, model: &str, n: usize) -> Vec<reqwest::StatusCode> {
    let calls = (0..n).map(|_| {
        chat(
            url,
            json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}),
        )
    });
    futures_util::future::join_all(calls)
        .await
        .into_iter()
        .map(|(status, _)| status)
        .collect()
}

#[tokio::test]
async fn a_seat_carries_no_more_than_its_ceiling_at_once() {
    // One seat, one slot. The mock's `slow` script holds each request
    // for two seconds, so three at once cannot all fit.
    let (url, mock, _dir) =
        codex_pool_with(&["acct-a"], "key_limits = { max_concurrency = 1 }").await;
    let statuses = concurrent(&url, "codex/slow", 3).await;
    let served = statuses.iter().filter(|s| **s == 200).count();
    let refused = statuses.iter().filter(|s| **s == 503).count();
    assert_eq!((served, refused), (1, 2), "{statuses:?}");
    assert_eq!(
        mock.request_count(),
        1,
        "the seat was asked exactly once; the others were never sent upstream"
    );

    // The slot came back with the response: the next request is served.
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn requests_past_one_seats_ceiling_go_to_the_next_seat() {
    let (url, mock, _dir) = codex_pool_with(
        &["acct-a", "acct-b"],
        "key_limits = { max_concurrency = 1 }",
    )
    .await;
    let statuses = concurrent(&url, "codex/slow", 2).await;
    assert!(statuses.iter().all(|s| *s == 200), "{statuses:?}");
    let mut hit = accounts_hit(&mock);
    hit.sort();
    assert_eq!(
        hit,
        vec!["acct-a", "acct-b"],
        "two requests at once means one on each seat, never two on one"
    );
}

#[tokio::test]
async fn a_pool_at_its_ceiling_says_so() {
    let (url, _mock, _dir) =
        codex_pool_with(&["acct-a"], "key_limits = { max_concurrency = 1 }").await;
    let hold = tokio::spawn({
        let url = url.clone();
        async move {
            chat(
                &url,
                json!({"model": "codex/slow", "messages": [{"role": "user", "content": "hi"}]}),
            )
            .await
        }
    });
    // Let the holder take the slot before the second request arrives.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/slow", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 503, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("at their ceiling") && message.contains("try again shortly"),
        "busy is neither broken nor out of quota, and the caller is told which: {body}"
    );
    assert_eq!(hold.await.unwrap().0, 200);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn a_bad_codex_knob_fails_config_validation() {
    // The backend answers an unsupported value with a 400 on *every*
    // request, so a typo here must not produce a config that starts and
    // then refuses all traffic.
    let err = Config::from_str_with_env(
        r#"
[providers.codex]
type = "codex_subscription"
codex = { reasoning_effort = "ludicrous" }
keys = [{ name = "s", value = "inline" }]
"#,
        Format::Toml,
        &NoEnv,
    )
    .unwrap_err();
    let rendered = format!("{err:?}");
    assert!(rendered.contains("reasoning_effort"), "{rendered}");
}

#[test]
fn the_codex_block_is_rejected_on_other_providers() {
    let err = Config::from_str_with_env(
        r#"
[providers.openai]
codex = { version = "0.146.0" }
keys = [{ name = "s", value = "sk-test" }]
"#,
        Format::Toml,
        &NoEnv,
    )
    .unwrap_err();
    assert!(format!("{err:?}").contains("codex"));
}

#[test]
fn an_empty_reasoning_effort_means_the_backend_default() {
    let config = Config::from_str_with_env(
        r#"
[providers.codex]
type = "codex_subscription"
codex = { reasoning_effort = "", verbosity = "" }
keys = [{ name = "s", value = "inline" }]
"#,
        Format::Toml,
        &NoEnv,
    )
    .unwrap();
    let codex = config.providers["codex"].codex.as_ref().unwrap();
    assert_eq!(codex.reasoning_effort, None);
    assert_eq!(codex.verbosity, None);
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

/// A seat that is out of quota must stay out for the window the provider
/// reported, not for the breaker's configured cooldown.
///
/// The check is that the *upstream* stops being asked. Re-probing an
/// exhausted seat is not merely wasteful: each probe consumes one of the
/// caller's retry attempts and earns another 429, which is how a pool
/// spends its whole retry budget achieving nothing.
async fn seat_is_benched_after_a_429(model: &str) {
    let (url, mock, _dir) = gateway().await;
    let (status, _) = chat(
        &url,
        json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(status, 429, "the caller sees the provider's own status");
    let after_first = mock.request_count();

    for _ in 0..3 {
        let (status, _) = chat(
            &url,
            json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}),
        )
        .await;
        assert_ne!(status, 200);
    }
    assert_eq!(
        mock.request_count(),
        after_first,
        "a benched seat must not be probed again before its window rolls",
    );
}

#[tokio::test]
async fn a_codex_seat_is_benched_from_headers_alone() {
    // Codex sends no retry-after; the window is only in x-codex-*.
    seat_is_benched_after_a_429("codex/quota-codex").await;
}

#[tokio::test]
async fn a_claude_seat_is_benched_for_the_reported_window() {
    seat_is_benched_after_a_429("claude-max/quota-claude").await;
}

/// A streaming Responses request reaches a Codex seat verbatim.
///
/// The Codex backend *is* the Responses API, so the surface must not be
/// forced through the stateless chat core on the way: that round trip
/// rejected every input item the core does not model — `additional_tools`
/// among them — turning a request the backend understands perfectly into
/// a 400 from us. Relaying keeps unknown-to-us-but-known-to-them items
/// intact, which is the only way this stays compatible as OpenAI adds to
/// the surface.
#[tokio::test]
async fn codex_relays_the_responses_surface_verbatim() {
    let (url, mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/responses"))
        .json(&json!({
            "model": "codex/gpt-5.5",
            "stream": true,
            "instructions": "You are Codex.",
            "input": [
                { "type": "message", "role": "user",
                  "content": [{ "type": "input_text", "text": "hi" }] },
                { "type": "additional_tools", "tools": ["web_search"] }
            ]
        }))
        .send()
        .await
        .unwrap();
    let status = res.status();
    let text = res.text().await.unwrap();
    assert_eq!(status, 200, "{text}");

    let request = mock.last_request();
    assert_eq!(request.path, "/backend-api/codex/responses");
    let sent = &request.body;
    let items = sent["input"].as_array().expect("input relayed as sent");
    assert!(
        items.iter().any(|i| i["type"] == "additional_tools"),
        "an input item the chat core cannot model must still reach the backend: {sent}",
    );
    assert_eq!(
        sent["model"], "gpt-5.5",
        "the routed model replaces the alias"
    );
    assert_eq!(sent["stream"], true, "the backend speaks only SSE");
    assert_eq!(sent["store"], false, "the backend keeps no state for us");
}

// ---------------------------------------------------------------------------
// The console's "Check" button
// ---------------------------------------------------------------------------

/// Probe one credential through the admin API, as the console does.
/// `model` empty means "send no override", which is what the console
/// itself sends.
async fn probe(url: &str, provider: &str, model: &str) -> Value {
    let client = reqwest::Client::new();
    let token = client
        .post(format!("{url}/admin/api/session"))
        .json(&json!({"key": "probe-test-key"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .expect("a session token")
        .to_owned();
    client
        .post(format!("{url}/admin/api/providers/{provider}/probe"))
        .bearer_auth(&token)
        .json(&if model.is_empty() {
            json!({})
        } else {
            json!({ "model": model })
        })
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["results"][0]
        .clone()
}

/// The check has to ask for what the backend actually serves.
///
/// A hand-rolled `/chat/completions` body is not a request the Codex
/// backend answers — it serves its private Responses surface at its own
/// path and nothing else — so a probe built that way is refused whatever
/// the seat's real state, and every credential reads as broken.
#[tokio::test]
async fn a_codex_probe_asks_the_backend_for_what_it_serves() {
    let (url, mock, _dir) = gateway().await;
    let result = probe(&url, "codex", "gpt-5.5").await;
    assert_eq!(result["status"], "ok", "{result}");

    let request = mock.last_request();
    assert_eq!(request.path, "/backend-api/codex/responses");
    assert_eq!(request.body["model"], "gpt-5.5");
    assert_eq!(request.body["stream"], true, "the backend speaks only SSE");
    assert!(
        request.body["input"].is_array(),
        "the Responses shape, not a chat body: {}",
        request.body,
    );
}

/// The same for a Claude seat: its token is only authorized for the
/// Claude Code identity, so a probe without it is refused by the model.
#[tokio::test]
async fn a_claude_probe_carries_the_identity_its_token_is_authorized_for() {
    let (url, mock, _dir) = gateway().await;
    let result = probe(&url, "claude-max", "claude-sonnet-4-5").await;
    assert_eq!(result["status"], "ok", "{result}");

    let request = mock.last_request();
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(
        request.body["system"][0]["text"],
        "You are Claude Code, Anthropic's official CLI for Claude.",
    );
}

/// A check is also how the plan windows first get reported, and the
/// console labels each window from the length that arrives here. Codex
/// sizes its windows per plan — this one is weekly — so a gateway that
/// dropped the length would leave the console guessing, which is how a
/// weekly window ends up drawn as a five-hour one.
#[tokio::test]
async fn a_codex_probe_reports_the_window_length_the_plan_actually_has() {
    let (url, _mock, _dir) = gateway().await;
    let result = probe(&url, "codex", "quota-codex").await;
    assert_eq!(result["status"], "rate_limited", "{result}");

    let client = reqwest::Client::new();
    let token = client
        .post(format!("{url}/admin/api/session"))
        .json(&json!({"key": "probe-test-key"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let providers = client
        .get(format!("{url}/admin/api/providers"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let seat = providers["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "codex")
        .expect("the codex provider")["keys"][0]
        .clone();

    assert_eq!(
        seat["quota"]["primary"]["length_s"], 604_800,
        "the plan's window is a week, and the console names it from this: {seat}",
    );
    assert_eq!(seat["quota"]["primary"]["utilization"], 1.0);
    assert!(
        seat["quota"]["secondary"].is_null(),
        "a plan with one window must not grow a second, empty one: {seat}",
    );
}

/// A seat is checkable the moment it is added.
///
/// The console's button sends no model, and these seats declare none —
/// what a subscription serves is decided by the plan, not configured. A
/// probe that gave up here would report "no model declared" for every
/// freshly added credential, which reads as a broken seat.
#[tokio::test]
async fn a_seat_can_be_checked_before_any_model_is_declared() {
    let (url, mock, _dir) = gateway().await;
    let result = probe(&url, "codex", "").await;
    assert_eq!(result["status"], "ok", "{result}");
    assert_eq!(result["model"], "gpt-5.5", "the plan's own model: {result}");
    assert_eq!(mock.last_request().path, "/backend-api/codex/responses");

    let result = probe(&url, "claude-max", "").await;
    assert_eq!(result["status"], "ok", "{result}");
    assert_eq!(mock.last_request().path, "/v1/messages");
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

/// A one-page PDF with a line of text, built inline so the suite carries
/// no binary fixture.
fn one_page_pdf() -> Vec<u8> {
    let text = b"BT /F1 14 Tf 20 50 Td (INVOICE TOTAL 42) Tj ET";
    let objs: Vec<Vec<u8>> = vec![
        b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 100]/Contents 4 0 R\
           /Resources<</Font<</F1 5 0 R>>>>>>"
            .to_vec(),
        [
            format!("<</Length {}>>stream\n", text.len()).into_bytes(),
            text.to_vec(),
            b"\nendstream".to_vec(),
        ]
        .concat(),
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>".to_vec(),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"endobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objs.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer<</Size {}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn pdf_data_uri() -> String {
    use base64::Engine;
    format!(
        "data:application/pdf;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(one_page_pdf())
    )
}

/// The whole point of the feature: the Codex backend has no document part
/// (its own client's content vocabulary is `input_text` / `input_image`
/// and nothing else), so an attached PDF must arrive as page images. It
/// used to be dropped in silence, and the model answered confidently about
/// a document it had never been shown.
#[tokio::test]
async fn a_pdf_reaches_a_codex_seat_as_page_images() {
    let (url, mock, _dir) = gateway().await;
    let (status, _) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "messages": [{
        "role": "user",
        "content": [
            {"type": "text", "text": "what is the total?"},
            {"type": "file", "file": {
                "filename": "invoice.pdf", "file_data": pdf_data_uri()}},
        ]}]}),
    )
    .await;
    assert_eq!(status, 200);

    let body = mock.last_request().body;
    let content = &body["input"][0]["content"];
    assert_eq!(content[0]["type"], "input_text");
    assert_eq!(content[0]["text"], "what is the total?");
    assert_eq!(
        content[1]["type"], "input_image",
        "the page must arrive as an image, not vanish: {content}"
    );
    assert!(
        content[1]["image_url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,"),
        "a rendered page, inline"
    );
    assert!(
        content.get(2).is_none(),
        "a one-page document yields exactly one image"
    );
    assert!(
        !body.to_string().contains("application/pdf"),
        "no trace of the document part should survive translation"
    );
}

/// A PDF that arrives in the Anthropic dialect must reach the same place.
/// The inbound parser had no `document` arm at all, so a Claude-dialect
/// caller's attachment was lost before translation even began.
#[tokio::test]
async fn an_anthropic_dialect_document_also_becomes_images() {
    let (url, mock, _dir) = gateway().await;
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode(one_page_pdf());
    let res = reqwest::Client::new()
        .post(format!("{url}/anthropic/v1/messages"))
        .json(&json!({
            "model": "codex/gpt-5.5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "what is the total?"},
                {"type": "document", "source": {
                    "type": "base64", "media_type": "application/pdf", "data": payload}},
            ]}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body = mock.last_request().body;
    let content = &body["input"][0]["content"];
    assert_eq!(content[1]["type"], "input_image", "got {content}");
}

/// A corrupt upload is the caller's problem to fix, and must say so —
/// not 500, and not a confident answer about a document nobody could read.
#[tokio::test]
async fn a_corrupt_document_is_a_400_naming_the_problem() {
    let (url, _mock, _dir) = gateway().await;
    let (status, body) = chat(
        &url,
        json!({"model": "codex/gpt-5.5", "messages": [{
            "role": "user",
            "content": [{"type": "file", "file": {
                "file_data": "data:application/pdf;base64,bm90IGEgcGRm"}}],
        }]}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("PDF"),
        "the message must name what could not be read: {body}"
    );
}

/// Anthropic takes a PDF natively and has a text layer to work from, so
/// rasterizing for it would be a downgrade. Only the dialects that cannot
/// carry a document get one rendered.
#[tokio::test]
async fn a_native_document_target_is_not_rasterized() {
    let (url, mock, _dir) = gateway().await;
    let (status, _) = chat(
        &url,
        json!({"model": "claude-max/claude-sonnet-4-5", "max_tokens": 100,
               "messages": [{"role": "user", "content": [
                   {"type": "file", "file": {
                       "filename": "invoice.pdf", "file_data": pdf_data_uri()}}]}]}),
    )
    .await;
    assert_eq!(status, 200);

    let body = mock.last_request().body;
    let block = &body["messages"][0]["content"][0];
    assert_eq!(block["type"], "document", "forwarded natively: {body}");
    assert_eq!(block["source"]["media_type"], "application/pdf");
}

/// The Responses relay forwards a body verbatim, which is right for every
/// surface feature the core cannot model — but wrong for a document, since
/// there is nothing on this wire to relay one into. A document must pull
/// the request off the relay path and through rasterization.
#[tokio::test]
async fn a_document_takes_the_translated_path_not_the_verbatim_relay() {
    let (url, mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!("{url}/v1/responses"))
        .json(&json!({
            "model": "codex/gpt-5.5",
            "stream": true,
            "input": [{"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "what is the total?"},
                {"type": "input_file", "filename": "invoice.pdf",
                 "file_data": pdf_data_uri()},
            ]}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body = mock.last_request().body;
    let content = &body["input"][0]["content"];
    assert_eq!(
        content[1]["type"], "input_image",
        "the relay would have forwarded input_file verbatim: {content}"
    );
    assert!(
        !body.to_string().contains("input_file"),
        "no document part may survive to the backend"
    );
}

// ---------------------------------------------------------------------------
// The console's "Sign in again" button
// ---------------------------------------------------------------------------

/// An admin session, for the endpoints the console calls.
async fn admin_token(url: &str) -> String {
    reqwest::Client::new()
        .post(format!("{url}/admin/api/session"))
        .json(&json!({"key": "probe-test-key"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .expect("a session token")
        .to_owned()
}

async fn start_login(url: &str, provider: &str, key: &str) -> (reqwest::StatusCode, Value) {
    let token = admin_token(url).await;
    let res = reqwest::Client::new()
        .post(format!(
            "{url}/admin/api/providers/{provider}/keys/{key}/device-login"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = res.status();
    (status, res.json::<Value>().await.unwrap_or(Value::Null))
}

/// Every refusal happens before a code is minted.
///
/// Worth asserting as a group: each one is a case where minting would
/// have "worked" — OpenAI hands out a code for any caller — and then
/// stranded the operator entering it, because there was never a seat the
/// result could be written to.
#[tokio::test]
async fn a_login_is_refused_before_a_code_is_minted() {
    let (url, _mock, _dir) = gateway().await;

    let (status, body) = start_login(&url, "codex", "no-such-seat").await;
    assert_eq!(status, 404, "{body}");

    let (status, body) = start_login(&url, "no-such-provider", "seat-1").await;
    assert_eq!(status, 404, "{body}");

    // Claude seats are renewed by their own CLI. Codex's device endpoint
    // would mint a code for one and it could never be claimed.
    let (status, body) = start_login(&url, "claude-max", "seat-1").await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Codex"),
        "the refusal has to say why: {body}"
    );
}

/// A login id that is not being tracked is a 404 that says what to do,
/// not a hang: the console polls this, and an outcome it can never reach
/// would leave the dialog spinning forever.
#[tokio::test]
async fn an_unknown_login_is_not_left_pending() {
    let (url, _mock, _dir) = gateway().await;
    let token = admin_token(&url).await;
    let res = reqwest::Client::new()
        .get(format!(
            "{url}/admin/api/providers/codex/keys/seat-1/device-login/dl_nothing"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("start a new one"),
        "{body}"
    );
}

/// The console must not be able to read one seat's login through another
/// seat's URL — the outcome carries the account it signed in as.
#[tokio::test]
async fn a_login_is_not_readable_through_another_seats_url() {
    let (url, _mock, _dir) = gateway().await;
    let token = admin_token(&url).await;
    let res = reqwest::Client::new()
        .get(format!(
            "{url}/admin/api/providers/claude-max/keys/seat-1/device-login/dl_nothing"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

/// Device login is an admin endpoint like any other.
#[tokio::test]
async fn a_login_cannot_be_started_without_an_admin_session() {
    let (url, _mock, _dir) = gateway().await;
    let res = reqwest::Client::new()
        .post(format!(
            "{url}/admin/api/providers/codex/keys/seat-1/device-login"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

// ---------------------------------------------------------------------------
// The canary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_canary_asks_every_codex_seat_a_question_from_the_pool() {
    let mock = MockProvider::spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let keys: Vec<String> = ["acct-a", "acct-b"]
        .iter()
        .map(|account| {
            let path = dir.path().join(format!("{account}.json"));
            std::fs::write(&path, codex_auth_json_for(4_000_000_000, account)).unwrap();
            format!(
                r#"{{ name = "{account}", value = "file:{}" }}"#,
                path.display()
            )
        })
        .collect();
    let config = Config::from_str_with_env(
        &format!(
            r#"
[providers.codex]
type = "codex_subscription"
base_url = "{base}"
codex = {{ version = "0.199.0", reasoning_effort = "medium" }}
keys = [{keys}]

[console]
admin_keys = ["probe-test-key"]
"#,
            base = mock.base_url(),
            keys = keys.join(", "),
        ),
        Format::Toml,
        &NoEnv,
    )
    .unwrap();
    let state = AppState::new(config);
    state.spawn_canary(std::time::Duration::from_millis(200));
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        router_server::serve(listener, state, app, std::future::pending())
            .await
            .unwrap()
    });

    // A few ticks: every seat asked, none of them twice at once.
    tokio::time::sleep(std::time::Duration::from_millis(900)).await;

    let hit = accounts_hit(&mock);
    for account in ["acct-a", "acct-b"] {
        assert!(
            hit.iter().any(|a| a == account),
            "{account} was asked: {hit:?}"
        );
    }
    let questions = router_server::canary::questions();
    for request in mock.requests() {
        let asked = request.body.to_string();
        assert!(
            questions
                .iter()
                .any(|q| asked.contains(&q[..40.min(q.len())])),
            "every question comes from the pool: {asked}"
        );
    }

    let report: Value = reqwest::Client::new()
        .get(format!("{url}/admin/api/canary"))
        .bearer_auth("probe-test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["enabled"], true, "{report}");
    assert_eq!(report["questions"], 100, "{report}");
    assert_eq!(report["seats"], 2, "{report}");
    for row in report["results"].as_array().unwrap() {
        assert!(row["ok"].as_u64().unwrap() >= 1, "{row}");
        assert_eq!(row["failed"], 0, "{row}");
        assert_eq!(row["last"]["status"], "ok", "{row}");
        assert_eq!(row["last"]["answer_preview"], "Hello from Codex", "{row}");
        assert!(row["p50_ms"].is_u64(), "{row}");
    }
}
