//! Embedded control-plane HTTP API used by the console and CLI.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use router_core::config::{Config, Format};
use router_core::vkey::{self, Budget, RateLimit, VirtualKeyDef};
use router_store::{Command, ControlPlaneError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AppState;

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let protected = Router::new()
        .route("/config", get(get_config).put(put_config))
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/{id}", put(update_key).delete(delete_key))
        .route("/keys/{id}/rotate", post(rotate_key))
        .route("/usage", get(usage))
        .route("/requests", get(requests))
        .route("/requests/summary", get(requests_summary))
        .route("/usage/summary", get(usage_summary))
        .route("/requests/{id}/bodies", get(request_bodies))
        .route("/tenants", post(create_tenant))
        .route("/tenants/{name}", axum::routing::delete(delete_tenant))
        .route("/providers", get(providers).post(create_provider))
        .route(
            "/providers/{name}",
            put(update_provider).delete(delete_provider),
        )
        .route("/providers/{name}/keys", post(add_provider_key))
        .route(
            "/providers/{name}/keys/bulk",
            post(add_provider_keys).delete(delete_provider_keys),
        )
        .route("/providers/{name}/probe", post(probe_provider))
        .route("/canary", get(canary_report))
        .route("/providers/{name}/models", post(add_model))
        .route(
            "/providers/{name}/models/{model}",
            axum::routing::delete(delete_model),
        )
        .route(
            "/providers/{name}/keys/{key}/tenant",
            put(set_account_tenant),
        )
        .route(
            "/providers/{name}/keys/{key}",
            axum::routing::delete(delete_provider_key),
        )
        .route(
            "/providers/{name}/keys/{key}/device-login",
            post(start_device_login),
        )
        .route(
            "/providers/{name}/keys/{key}/device-login/{session}",
            get(device_login_status),
        )
        .route("/catalog", get(catalog))
        .route("/pricing/refresh", post(refresh_pricing))
        .route("/secrets", post(put_secret))
        .route("/credential-files", post(put_credential_file))
        .route("/credential-files/bulk", post(put_credential_files))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", put(update_user).delete(delete_user))
        .route("/teams", get(list_teams).post(put_team))
        .route("/teams/{id}", put(put_team_by_id).delete(delete_team))
        .route("/me", get(whoami))
        .route("/routes", get(list_routes).post(put_route))
        .route("/routes/{name}", axum::routing::delete(delete_route))
        .route("/history", get(history))
        .route("/fleet", get(fleet))
        .route("/events", get(events))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_auth,
        ));
    Router::new()
        .route("/session", post(create_session))
        .merge(protected)
}

fn api_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into() } })),
    )
        .into_response()
}

/// Control-plane writes need a control plane: a store, or a cluster.
/// Control-plane writes need a control plane, and file mode does not have
/// one: the file your deploy tool distributes is the source of truth, so
/// the console must not write over it.
#[allow(clippy::result_large_err)] // the Err *is* the response we serve
fn writable(state: &AppState) -> Result<(), Response> {
    if state.file_managed {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "file mode is read-only; edit the source file and reload",
        ));
    }
    if state.store.is_some() {
        return Ok(());
    }
    Err(api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "managed store is not configured",
    ))
}

/// Turn a commit failure into the operator-facing distinction that
/// matters: an edit that raced someone else, a store that is down, or a
/// configuration problem only a human can fix.
fn commit_error(err: ControlPlaneError) -> Response {
    let status = match err {
        ControlPlaneError::Conflict { .. } => StatusCode::CONFLICT,
        ControlPlaneError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        ControlPlaneError::Fault(_) => StatusCode::INTERNAL_SERVER_ERROR,
        // A capability this backend does not have is a configuration
        // fact, not a transient failure.
        ControlPlaneError::Unsupported(_) => StatusCode::CONFLICT,
    };
    api_error(status, err.to_string())
}

/// How many analytics reads may be in flight at once.
///
/// Queueing is a better answer than thrashing: past a point, more
/// concurrent scans only trade cache lines with each other and every one
/// of them gets slower. Half the cores, never fewer than two.
fn analytics_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 2).max(2))
        .unwrap_or(2)
}

/// Run a disk-reading query away from the async runtime.
///
/// Every analytics read decompresses partitions and parses JSON. Doing
/// that on a runtime worker parks a thread that is also proxying
/// completions, so a wide window opened in the console shows up as
/// latency on somebody else's request — the console making the gateway
/// slow is the one thing this endpoint is not allowed to do. The
/// semaphore is the other half of that promise: a handful of concurrent
/// year-wide reads must not swallow the blocking pool either.
///
/// The error is boxed, as `enforce` and `config_document` box theirs: an
/// unboxed `Response` is 128 bytes that every *successful* read would
/// carry for nothing, and the successes here are pages of records. The
/// two ways this fails — the queue closing during shutdown, and a read
/// panicking — are both rare enough to pay an allocation for.
async fn off_runtime<T, F>(work: F) -> Result<T, Box<Response>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    static SLOTS: std::sync::LazyLock<tokio::sync::Semaphore> =
        std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(analytics_concurrency()));
    // Held across the join below: the permit is the queue, and releasing
    // it before the work finishes would make the bound meaningless.
    let _permit = SLOTS.acquire().await.map_err(|_| {
        Box::new(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "analytics queue is shutting down",
        ))
    })?;
    tokio::task::spawn_blocking(work).await.map_err(|err| {
        tracing::warn!(%err, "analytics read panicked");
        Box::new(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "analytics read failed; see gateway logs",
        ))
    })
}

/// A short-lived memo of analytics answers, keyed by the exact question.
///
/// Live traffic nudges the console to refetch every few seconds, and it
/// asks the same question each time — often from several pages and
/// several tabs at once. Recomputing a window that has not moved is pure
/// waste, and for a window that ended in the past it is waste that can
/// never pay off, because those days are immutable.
///
/// Two TTLs for that reason: seconds for a window ending "now", minutes
/// for one that ended before today started. Neither is long enough to
/// show an operator something they would call stale — the flusher's own
/// interval is ten seconds, so a figure is never fresher than that
/// anyway.
struct AnalyticsMemo {
    /// Keyed by question; the instant is when the answer stops counting.
    entries: std::sync::Mutex<HashMap<String, (std::time::Instant, Arc<Value>)>>,
}

const MEMO_TTL_LIVE: Duration = Duration::from_secs(3);
const MEMO_TTL_CLOSED: Duration = Duration::from_secs(300);
/// Enough for every page and range a handful of operators can have open.
const MEMO_CAP: usize = 512;

static ANALYTICS_MEMO: std::sync::LazyLock<AnalyticsMemo> =
    std::sync::LazyLock::new(|| AnalyticsMemo {
        entries: std::sync::Mutex::new(HashMap::new()),
    });

impl AnalyticsMemo {
    fn get(&self, key: &str) -> Option<Arc<Value>> {
        let now = std::time::Instant::now();
        let entries = self.entries.lock().ok()?;
        let (expires, value) = entries.get(key)?;
        (*expires > now).then(|| value.clone())
    }

    fn put(&self, key: String, ttl: Duration, value: Arc<Value>) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = std::time::Instant::now();
        entries.retain(|_, (expires, _)| *expires > now);
        // A cap this far above the number of distinct questions a
        // console can ask means reaching it is a leak, not a workload —
        // so start over rather than evicting one at a time.
        if entries.len() >= MEMO_CAP {
            entries.clear();
        }
        entries.insert(key, (now + ttl, value));
    }
}

/// How long an answer about this window stays true enough to reuse.
///
/// A window that ended before today began covers only closed partitions,
/// and closed partitions do not change.
fn memo_ttl(until_ms: u64, now_ms: u64) -> Duration {
    if until_ms < now_ms - (now_ms % 86_400_000) {
        MEMO_TTL_CLOSED
    } else {
        MEMO_TTL_LIVE
    }
}

/// Run an analytics read off the runtime, memoised.
///
/// The memo is checked before the queue is joined, so a cached answer
/// does not wait behind an uncached one.
async fn memoised<F>(key: String, ttl: Duration, work: F) -> Response
where
    F: FnOnce() -> Result<Value, serde_json::Error> + Send + 'static,
{
    if let Some(hit) = ANALYTICS_MEMO.get(&key) {
        return Json(&*hit).into_response();
    }
    match off_runtime(work).await {
        Ok(Ok(value)) => {
            let value = Arc::new(value);
            ANALYTICS_MEMO.put(key, ttl, value.clone());
            Json(&*value).into_response()
        }
        Ok(Err(err)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        Err(response) => *response,
    }
}

#[derive(Deserialize)]
struct SessionRequest {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(input): Json<SessionRequest>,
) -> Response {
    let config = state.config.load();
    if !config.console.enabled() {
        return api_error(StatusCode::UNAUTHORIZED, "console is disabled");
    }
    let principal = match (&input.key, &input.email, &input.password) {
        (Some(key), _, _) => {
            if !config.console.admin_keys.iter().any(|k| k.verify(key)) {
                return api_error(StatusCode::UNAUTHORIZED, "invalid admin key");
            }
            crate::Principal::AdminKey
        }
        (None, Some(email), Some(password)) => {
            // The same answer for "no such user" and "wrong password":
            // login errors must not confirm which emails exist.
            let user = state.store_read().and_then(|(snapshot, _)| {
                snapshot
                    .users
                    .values()
                    .find(|u| u.email.eq_ignore_ascii_case(email))
                    .cloned()
            });
            match user {
                Some(user)
                    if router_core::access::verify_password(password, &user.password_hash) =>
                {
                    crate::Principal::User { id: user.id }
                }
                _ => return api_error(StatusCode::UNAUTHORIZED, "invalid email or password"),
            }
        }
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "send `key`, or `email` and `password`",
            );
        }
    };
    let expires_ms =
        vkey::unix_now_ms() + config.console.session_ttl.as_millis().min(u64::MAX as u128) as u64;
    // Signed rather than random: the map below is a cache that a restart
    // is allowed to lose, and the token itself is what proves the
    // session. See `crate::session`.
    let token = state.session_signer.mint(&principal, expires_ms);
    state.sessions.lock().unwrap().insert(
        token.clone(),
        crate::Session {
            expires_ms,
            principal,
        },
    );
    let mut response = Json(json!({ "token": token, "expires_ms": expires_ms })).into_response();
    if let Ok(cookie) = format!(
        "rapid_session={}; Path=/admin/api; HttpOnly; SameSite=Strict; Max-Age={}",
        token,
        config.console.session_ttl.as_secs(),
    )
    .parse()
    {
        response.headers_mut().insert(SET_COOKIE, cookie);
    }
    response
}

async fn admin_auth(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let config = state.config.load();
    if !config.console.enabled() {
        return api_error(StatusCode::NOT_FOUND, "console is disabled");
    }
    let bearer = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let cookie = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|value| value.strip_prefix("rapid_session="))
        });
    let valid_static = bearer.is_some_and(|token| {
        config
            .console
            .admin_keys
            .iter()
            .any(|key| key.verify(token))
    });
    let now = vkey::unix_now_ms();
    let principal = if valid_static {
        Some(crate::Principal::AdminKey)
    } else {
        bearer.or(cookie).and_then(|token| {
            {
                let mut sessions = state.sessions.lock().unwrap();
                sessions.retain(|_, session| session.expires_ms >= now);
                if let Some(session) = sessions.get(token) {
                    return Some(session.principal.clone());
                }
            }
            // Not in the cache. Either this node never minted it — which
            // is the normal case in a fleet — or the process restarted
            // and forgot. The token proves its own claims either way, so
            // rehydrate rather than answering 401 and making a deploy
            // look like a network fault.
            let (principal, expires_ms) = state.session_signer.verify(token, now)?;
            state.sessions.lock().unwrap().insert(
                token.to_owned(),
                crate::Session {
                    expires_ms,
                    principal: principal.clone(),
                },
            );
            Some(principal)
        })
    };
    let Some(principal) = principal else {
        return api_error(StatusCode::UNAUTHORIZED, "missing or invalid admin session");
    };

    let authz = resolve_authz(&state, &principal);
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if let Err(response) = enforce(&authz, &method, &path) {
        return *response;
    }
    let mut request = request;
    request.extensions_mut().insert(authz);
    next.run(request).await
}

/// A resolved authorization: who this is and what they were granted.
#[derive(Debug, Clone)]
pub(crate) struct Authz {
    pub user_id: Option<String>,
    pub is_admin: bool,
    pub grant: router_core::access::Grant,
}

fn resolve_authz(state: &AppState, principal: &crate::Principal) -> Authz {
    use router_core::access::{Grant, UserRole};
    match principal {
        crate::Principal::AdminKey => Authz {
            user_id: None,
            is_admin: true,
            grant: Grant::admin(),
        },
        crate::Principal::User { id } => {
            let snapshot = state.store_read().map(|(s, _)| s);
            let user = snapshot.as_ref().and_then(|s| s.users.get(id).cloned());
            let is_admin = user.as_ref().is_some_and(|u| u.role == UserRole::Admin);
            let grant = if is_admin {
                Grant::admin()
            } else {
                Grant::for_member(id, snapshot.iter().flat_map(|s| s.teams.values()))
            };
            Authz {
                user_id: Some(id.clone()),
                is_admin,
                grant,
            }
        }
    }
}

/// The coarse gate, applied to every admin route by method and path.
///
/// Reads are open to every signed-in principal — the console is an
/// observability surface first, and read-only is a real access level, not
/// a punishment. Writes need `Full`, except the virtual-key routes, which
/// need `Keys` (their model-scope check lives in the handlers, which can
/// see the body). Users and teams are admin-only: the people who can
/// grant access must be a strict superset of the people access is granted
/// to, or membership in a `Full` team would be self-escalating.
fn enforce(authz: &Authz, method: &axum::http::Method, path: &str) -> Result<(), Box<Response>> {
    use router_core::access::TeamAccess;
    if method == axum::http::Method::GET || authz.is_admin {
        return Ok(());
    }
    if path.starts_with("/users") || path.starts_with("/teams") {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            "managing users and teams needs an admin",
        )));
    }
    let needed = if path.starts_with("/keys") {
        TeamAccess::Keys
    } else {
        TeamAccess::Full
    };
    if authz.grant.access < needed {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            match needed {
                TeamAccess::Keys => "your teams do not allow managing virtual keys",
                _ => "your teams grant read-only or key access, not configuration changes",
            },
        )));
    }
    Ok(())
}

async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    let (text, version) = state
        .store_read()
        .map(|(snapshot, version)| (snapshot.config_text.unwrap_or_default(), version))
        .unwrap_or_default();
    Json(json!({
        "mode": if state.file_managed { "file" } else { "managed" },
        "read_only": state.file_managed,
        "version": version,
        "text": text,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ConfigWrite {
    version: u64,
    text: String,
}

async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ConfigWrite>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let env = |name: &str| {
        if let Some(secret) = name.strip_prefix("store.") {
            state
                .store
                .as_deref()
                .and_then(|s| s.resolve_secret(secret))
        } else {
            std::env::var(name).ok()
        }
    };
    // Validate before committing, so a bad config is rejected instead of
    // stored and then rejected by every node that reads it.
    if let Err(err) = Config::from_str_with_env(&input.text, Format::Toml, &env) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, err.to_string());
    }
    let version = match state
        .commit(Some(input.version), Command::PutConfig { text: input.text })
        .await
    {
        Ok(version) => version,
        Err(err) => return commit_error(err),
    };
    // Adopt through the same path a remote change takes, so there is one
    // place where a config becomes live on a node.
    state.adopt_store_state();
    Json(json!({ "version": version })).into_response()
}

#[derive(Debug, Deserialize)]
struct KeyInput {
    name: String,
    #[serde(default)]
    models: Vec<String>,
    /// Which service this key belongs to.
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    budget: Option<Budget>,
    #[serde(default)]
    rate: Option<RateLimit>,
    #[serde(default)]
    expires_ms: Option<u64>,
    #[serde(default)]
    tags: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize)]
struct KeyView<'a> {
    id: &'a str,
    name: &'a str,
    models: &'a [String],
    tenant: Option<&'a str>,
    budget: Option<Budget>,
    rate: Option<RateLimit>,
    expires_ms: Option<u64>,
    tags: &'a std::collections::BTreeMap<String, String>,
    enabled: bool,
    created_ms: u64,
}

fn key_view(def: &VirtualKeyDef) -> KeyView<'_> {
    KeyView {
        id: &def.id,
        name: &def.name,
        models: &def.models,
        tenant: def.tenant.as_deref(),
        budget: def.budget,
        rate: def.rate,
        expires_ms: def.expires_ms,
        tags: &def.tags,
        enabled: def.enabled,
        created_ms: def.created_ms,
    }
}

async fn list_keys(State(state): State<Arc<AppState>>) -> Response {
    let mut defs: Vec<VirtualKeyDef> = state.vkeys.load().iter().map(|rt| rt.def.clone()).collect();
    defs.sort_by(|a, b| a.name.cmp(&b.name));
    Json(json!({ "data": defs.iter().map(key_view).collect::<Vec<_>>() })).into_response()
}

/// Reject a service this gateway does not know.
///
/// A misspelled name is not a harmless label: the key would own no account
/// in any labelled pool, which looks like a working key right up until the
/// pool is busy.
fn check_tenant(state: &AppState, tenant: Option<&str>) -> Result<(), String> {
    let Some(tenant) = tenant else {
        return Ok(());
    };
    if state.config.load().tenants.contains(tenant) {
        Ok(())
    } else {
        Err(format!("no service named `{tenant}` is declared"))
    }
}

async fn create_key(
    State(state): State<Arc<AppState>>,
    axum::Extension(authz): axum::Extension<Authz>,
    Json(input): Json<KeyInput>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if input.name.trim().is_empty() {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "name must not be empty");
    }
    // A scoped member may only mint keys inside their teams' models — and
    // an unscoped key (empty list = every model) would be the widest key
    // of all, so it needs an unscoped grant.
    if authz.grant.models.is_some() {
        if input.models.is_empty() {
            return api_error(
                StatusCode::FORBIDDEN,
                "your teams are scoped to specific models; pick which ones this key may use",
            );
        }
        if !authz
            .grant
            .allows_models(input.models.iter().map(String::as_str))
        {
            return api_error(
                StatusCode::FORBIDDEN,
                "one or more models are outside your teams' access",
            );
        }
    }
    if let Err(message) = check_tenant(&state, input.tenant.as_deref()) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let mut tags = input.tags;
    if let Some(team) = authz.grant.teams.first() {
        // Recorded, not user-supplied: this is what scopes later edits.
        tags.insert("team".into(), team.clone());
    }
    if let Some(user) = &authz.user_id {
        tags.insert("created_by".into(), user.clone());
    }
    let generated = vkey::generate();
    let def = VirtualKeyDef {
        id: generated.id.clone(),
        name: input.name,
        secret_hash: vkey::hash_secret(&generated.secret),
        prev_secret: None,
        models: input.models,
        tenant: input.tenant,
        budget: input.budget,
        rate: input.rate,
        expires_ms: input.expires_ms,
        tags,
        enabled: true,
        created_ms: vkey::unix_now_ms(),
    };
    let version = match state
        .commit(None, Command::PutVirtualKey { def: def.clone() })
        .await
    {
        Ok(version) => version,
        Err(err) => return commit_error(err),
    };
    state.refresh_vkeys();
    Json(json!({
        "key": generated.full(),
        "version": version,
        "data": key_view(&def),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct KeyUpdate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    models: Option<Vec<String>>,
    /// `Some(None)` moves the key off every service; absent leaves it alone.
    #[serde(default)]
    tenant: Option<Option<String>>,
    #[serde(default)]
    budget: Option<Option<Budget>>,
    #[serde(default)]
    rate: Option<Option<RateLimit>>,
    #[serde(default)]
    expires_ms: Option<Option<u64>>,
    #[serde(default)]
    tags: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn update_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(input): Json<KeyUpdate>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let Some((snapshot, version)) = state.store_read() else {
        return api_error(StatusCode::CONFLICT, "no control-plane store on this node");
    };
    let Some(mut def) = snapshot.virtual_keys.get(&id).cloned() else {
        return api_error(StatusCode::NOT_FOUND, "virtual key not found");
    };
    if let Some(name) = input.name {
        def.name = name;
    }
    if let Some(models) = input.models {
        def.models = models;
    }
    if let Some(tenant) = input.tenant {
        if let Err(message) = check_tenant(&state, tenant.as_deref()) {
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, message);
        }
        def.tenant = tenant;
    }
    if let Some(budget) = input.budget {
        def.budget = budget;
    }
    if let Some(rate) = input.rate {
        def.rate = rate;
    }
    if let Some(expires) = input.expires_ms {
        def.expires_ms = expires;
    }
    if let Some(tags) = input.tags {
        def.tags = tags;
    }
    if let Some(enabled) = input.enabled {
        def.enabled = enabled;
    }
    let new_version = match state
        .commit(Some(version), Command::PutVirtualKey { def: def.clone() })
        .await
    {
        Ok(version) => version,
        Err(err) => return commit_error(err),
    };
    state.refresh_vkeys();
    Json(json!({ "version": new_version, "data": key_view(&def) })).into_response()
}

async fn rotate_key(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let Some((snapshot, version)) = state.store_read() else {
        return api_error(StatusCode::CONFLICT, "no control-plane store on this node");
    };
    let Some(mut def) = snapshot.virtual_keys.get(&id).cloned() else {
        return api_error(StatusCode::NOT_FOUND, "virtual key not found");
    };
    let secret = vkey::generate_secret();
    def.prev_secret = Some(vkey::PrevSecret {
        secret_hash: def.secret_hash.clone(),
        valid_until_ms: vkey::unix_now_ms() + 24 * 60 * 60 * 1000,
    });
    def.secret_hash = vkey::hash_secret(&secret);
    let new_version = match state
        .commit(Some(version), Command::PutVirtualKey { def: def.clone() })
        .await
    {
        Ok(version) => version,
        Err(err) => return commit_error(err),
    };
    state.refresh_vkeys();
    Json(json!({
        "key": format!("ck-{}-{secret}", def.id),
        "version": new_version,
        "grace_until_ms": def.prev_secret.as_ref().unwrap().valid_until_ms,
    }))
    .into_response()
}

async fn delete_key(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let version = state.store_read().map(|(_, v)| v).unwrap_or(0);
    let new_version = match state
        .commit(Some(version), Command::DeleteVirtualKey { id })
        .await
    {
        Ok(version) => version,
        Err(err) => return commit_error(err),
    };
    state.refresh_vkeys();
    Json(json!({ "version": new_version })).into_response()
}

#[derive(Deserialize)]
struct UsageQuery {
    #[serde(default = "default_window")]
    window: u64,
    #[serde(default)]
    by: Option<String>,
    #[serde(default)]
    key: Option<String>,
}

fn default_window() -> u64 {
    3600
}

async fn usage(State(state): State<Arc<AppState>>, Query(query): Query<UsageQuery>) -> Response {
    let by: Vec<&str> = query
        .by
        .as_deref()
        .unwrap_or("provider")
        .split(',')
        .filter(|v| matches!(*v, "provider" | "model" | "key"))
        .collect();
    Json(state.usage.agg.query(
        vkey::unix_now_ms(),
        query.window.clamp(60, 86_400),
        &by,
        query.key.as_deref(),
    ))
    .into_response()
}

#[derive(Deserialize)]
struct RequestsQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    errors: bool,
    /// Window to search, unix milliseconds. Defaults to the last hour,
    /// which is what a live tail wants and what keeps an unqualified
    /// request from walking a month of partitions.
    #[serde(default)]
    since_ms: Option<u64>,
    #[serde(default)]
    until_ms: Option<u64>,
    /// Opaque page cursor from the previous response.
    #[serde(default)]
    after: Option<String>,
}

fn default_limit() -> usize {
    100
}

impl RequestsQuery {
    /// Everything that changes the answer, and nothing that does not.
    ///
    /// The resolved window rather than the submitted one: the console
    /// sends `since_ms`/`until_ms` computed from `Date.now()`, so two
    /// refreshes a second apart are different strings for the same
    /// question. Rounding to the second is what lets them share an
    /// answer; anything finer would memoise nothing.
    fn memo_key(&self, since_ms: u64, until_ms: u64) -> String {
        format!(
            "{}-{}-{}-{}-{}-{}",
            since_ms / 1000,
            until_ms / 1000,
            self.provider.as_deref().unwrap_or(""),
            self.model.as_deref().unwrap_or(""),
            self.key.as_deref().unwrap_or(""),
            self.errors,
        )
    }
}

async fn requests(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RequestsQuery>,
) -> Response {
    let now = crate::vkey::unix_now_ms();
    let since = query
        .since_ms
        .unwrap_or_else(|| now.saturating_sub(3_600_000));
    let filter = crate::usage::HistoryFilter {
        provider: query.provider.clone().filter(|v| !v.is_empty()),
        model: query.model.clone().filter(|v| !v.is_empty()),
        vkey: query.key.clone().filter(|v| !v.is_empty()),
    };
    // The cursor is opaque to the console: "ts:request_id", which is
    // exactly the ordering key the reader pages by.
    let after = query.after.as_deref().and_then(|cursor| {
        let (ts, id) = cursor.split_once(':')?;
        Some((ts.parse::<u64>().ok()?, id.to_owned()))
    });
    let usage = state.usage.clone();
    let limit = query.limit.clamp(1, 1_000);
    let until = query.until_ms.unwrap_or(now);
    let errors = query.errors;
    let read =
        off_runtime(move || usage.page_from_disk(limit, since, until, &filter, errors, after))
            .await;
    match read {
        Ok((data, next)) => Json(json!({
            "data": data,
            "next": next.map(|(ts, id)| format!("{ts}:{id}")),
        }))
        .into_response(),
        Err(response) => *response,
    }
}

/// Totals for the whole window, so the console header describes the
/// selected range rather than the page it happens to be showing.
///
/// Takes exactly the same filters as `/requests`, so the two can never
/// disagree about what is being counted.
async fn requests_summary(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RequestsQuery>,
) -> Response {
    let now = crate::vkey::unix_now_ms();
    let since = query
        .since_ms
        .unwrap_or_else(|| now.saturating_sub(3_600_000));
    let filter = crate::usage::HistoryFilter {
        provider: query.provider.clone().filter(|v| !v.is_empty()),
        model: query.model.clone().filter(|v| !v.is_empty()),
        vkey: query.key.clone().filter(|v| !v.is_empty()),
    };
    let usage = state.usage.clone();
    let until = query.until_ms.unwrap_or(now);
    let errors = query.errors;
    memoised(
        format!("requests/summary?{}", query.memo_key(since, until)),
        memo_ttl(until, now),
        move || serde_json::to_value(usage.summary(since, until, &filter, errors)),
    )
    .await
}

/// Everything the Usage page needs for a window, in one request.
///
/// Same filters and the same scan as `/requests`, so the page and the log
/// table can never disagree about what happened in a window.
async fn usage_summary(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RequestsQuery>,
) -> Response {
    let now = crate::vkey::unix_now_ms();
    let since = query
        .since_ms
        .unwrap_or_else(|| now.saturating_sub(3_600_000));
    let filter = crate::usage::HistoryFilter {
        provider: query.provider.clone().filter(|v| !v.is_empty()),
        model: query.model.clone().filter(|v| !v.is_empty()),
        vkey: query.key.clone().filter(|v| !v.is_empty()),
    };
    let usage = state.usage.clone();
    let until = query.until_ms.unwrap_or(now);
    let errors = query.errors;
    memoised(
        format!("usage/summary?{}", query.memo_key(since, until)),
        memo_ttl(until, now),
        move || serde_json::to_value(usage.usage_summary(since, until, &filter, errors)),
    )
    .await
}

#[derive(Deserialize)]
struct BodiesQuery {
    /// The record's timestamp, which says which day partition to open.
    ts: u64,
}

/// What was sent and what came back, for one request.
async fn request_bodies(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<BodiesQuery>,
) -> Response {
    let usage = state.usage.clone();
    let lookup = {
        let id = id.clone();
        let ts = query.ts;
        match off_runtime(move || usage.bodies_for(&id, ts)).await {
            Ok(found) => found,
            Err(response) => return *response,
        }
    };
    match lookup {
        Some(bodies) => Json(json!({
            "request_id": bodies.request_id,
            "input": bodies.input,
            "output": bodies.output,
            "truncated": bodies.truncated,
        }))
        .into_response(),
        None => Json(json!({
            "request_id": id,
            "input": null,
            "output": null,
            // The honest reasons a body is missing, so the console can
            // say which one applies rather than showing an empty panel.
            "reason": if state.config.load().usage.capture_bodies
                == router_core::config::BodyCapture::Off
            {
                "body capture is off for this gateway"
            } else {
                "no stored bodies for this request; it may predate capture or have aged out"
            },
        }))
        .into_response(),
    }
}

use router_core::access::{TeamAccess, TeamDef, UserDef, UserRole, hash_password};

/// Who am I, and what may I do — the console shapes itself around this.
async fn whoami(
    State(state): State<Arc<AppState>>,
    axum::Extension(authz): axum::Extension<Authz>,
) -> Response {
    let email = authz.user_id.as_ref().and_then(|id| {
        state
            .store_read()
            .and_then(|(s, _)| s.users.get(id).map(|u| u.email.clone()))
    });
    Json(json!({
        "principal": if authz.user_id.is_some() { "user" } else { "admin_key" },
        "email": email,
        "is_admin": authz.is_admin,
        "access": match authz.grant.access {
            TeamAccess::Full => "full",
            TeamAccess::Keys => "keys",
            TeamAccess::ReadOnly => "read_only",
        },
        "models": authz.grant.models,
        "teams": authz.grant.teams,
    }))
    .into_response()
}

async fn list_users(State(state): State<Arc<AppState>>) -> Response {
    let snapshot = state.store_read().map(|(s, _)| s);
    let teams: Vec<TeamDef> = snapshot
        .as_ref()
        .map(|s| s.teams.values().cloned().collect())
        .unwrap_or_default();
    let data: Vec<Value> = snapshot
        .iter()
        .flat_map(|s| s.users.values())
        .map(|user| {
            json!({
                "id": user.id,
                "email": user.email,
                "role": match user.role { UserRole::Admin => "admin", UserRole::Member => "member" },
                "created_ms": user.created_ms,
                "teams": teams
                    .iter()
                    .filter(|t| t.members.contains(&user.id))
                    .map(|t| json!({ "id": t.id, "name": t.name }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({ "data": data })).into_response()
}

#[derive(Deserialize)]
struct UserWrite {
    email: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    role: Option<String>,
}

fn parse_role(role: Option<&str>) -> Result<UserRole, Box<Response>> {
    match role {
        None | Some("member") => Ok(UserRole::Member),
        Some("admin") => Ok(UserRole::Admin),
        Some(other) => Err(Box::new(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unknown role `{other}`; use `admin` or `member`"),
        ))),
    }
}

async fn create_user(State(state): State<Arc<AppState>>, Json(input): Json<UserWrite>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let email = input.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a valid email is required",
        );
    }
    let Some(password) = input.password.as_deref().filter(|p| p.len() >= 8) else {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a password of at least 8 characters is required",
        );
    };
    if state
        .store_read()
        .is_some_and(|(s, _)| s.users.values().any(|u| u.email == email))
    {
        return api_error(
            StatusCode::CONFLICT,
            "a user with this email already exists",
        );
    }
    let role = match parse_role(input.role.as_deref()) {
        Ok(role) => role,
        Err(response) => return *response,
    };
    let hash = match hash_password(password) {
        Ok(hash) => hash,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let def = UserDef {
        id: format!("u_{}", uuid::Uuid::now_v7().simple()),
        email,
        password_hash: hash,
        role,
        created_ms: vkey::unix_now_ms(),
    };
    match state
        .commit(None, Command::PutUser { def: def.clone() })
        .await
    {
        Ok(_) => Json(json!({ "data": { "id": def.id, "email": def.email } })).into_response(),
        Err(err) => commit_error(err),
    }
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(input): Json<UserWrite>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let Some(mut user) = state
        .store_read()
        .and_then(|(s, _)| s.users.get(&id).cloned())
    else {
        return api_error(StatusCode::NOT_FOUND, "no such user");
    };
    if let Some(password) = input.password.as_deref() {
        if password.len() < 8 {
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, "password too short");
        }
        user.password_hash = match hash_password(password) {
            Ok(hash) => hash,
            Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
        };
    }
    if input.role.is_some() {
        user.role = match parse_role(input.role.as_deref()) {
            Ok(role) => role,
            Err(response) => return *response,
        };
    }
    match state.commit(None, Command::PutUser { def: user }).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(err) => commit_error(err),
    }
}

async fn delete_user(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    // Sessions are revoked immediately: a deleted user with a live token
    // is not deleted.
    state
        .sessions
        .lock()
        .unwrap()
        .retain(|_, session| session.principal != crate::Principal::User { id: id.clone() });
    match state.commit(None, Command::DeleteUser { id }).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(err) => commit_error(err),
    }
}

async fn list_teams(State(state): State<Arc<AppState>>) -> Response {
    let data: Vec<Value> = state
        .store_read()
        .iter()
        .flat_map(|(s, _)| s.teams.values())
        .map(|team| {
            json!({
                "id": team.id,
                "name": team.name,
                "members": team.members,
                "models": team.models,
                "access": match team.access {
                    TeamAccess::Full => "full",
                    TeamAccess::Keys => "keys",
                    TeamAccess::ReadOnly => "read_only",
                },
                "created_ms": team.created_ms,
            })
        })
        .collect();
    Json(json!({ "data": data })).into_response()
}

#[derive(Deserialize)]
struct TeamWrite {
    name: String,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    access: Option<String>,
}

async fn upsert_team(state: Arc<AppState>, id: Option<String>, input: TeamWrite) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if input.name.trim().is_empty() {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "a team name is required");
    }
    let access = match input.access.as_deref() {
        None | Some("keys") => TeamAccess::Keys,
        Some("full") => TeamAccess::Full,
        Some("read_only") => TeamAccess::ReadOnly,
        Some(other) => {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("unknown access `{other}`; use `full`, `keys` or `read_only`"),
            );
        }
    };
    let snapshot = state.store_read().map(|(s, _)| s);
    let known_users: std::collections::BTreeSet<String> = snapshot
        .iter()
        .flat_map(|s| s.users.keys().cloned())
        .collect();
    if let Some(ghost) = input.members.iter().find(|m| !known_users.contains(*m)) {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("`{ghost}` is not a user on this gateway"),
        );
    }
    let created_ms = id
        .as_ref()
        .and_then(|id| snapshot.as_ref().and_then(|s| s.teams.get(id)))
        .map(|t| t.created_ms)
        .unwrap_or_else(vkey::unix_now_ms);
    let def = TeamDef {
        id: id.unwrap_or_else(|| format!("t_{}", uuid::Uuid::now_v7().simple())),
        name: input.name.trim().to_owned(),
        members: input.members.into_iter().collect(),
        models: input.models.into_iter().collect(),
        access,
        created_ms,
    };
    match state
        .commit(None, Command::PutTeam { def: def.clone() })
        .await
    {
        Ok(_) => Json(json!({ "data": { "id": def.id } })).into_response(),
        Err(err) => commit_error(err),
    }
}

async fn put_team(State(state): State<Arc<AppState>>, Json(input): Json<TeamWrite>) -> Response {
    upsert_team(state, None, input).await
}

async fn put_team_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(input): Json<TeamWrite>,
) -> Response {
    upsert_team(state, Some(id), input).await
}

async fn delete_team(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    match state.commit(None, Command::DeleteTeam { id }).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(err) => commit_error(err),
    }
}

#[derive(Deserialize)]
struct SecretWrite {
    name: String,
    value: String,
}

/// Seal a secret into the store, for `store.<name>` references.
///
/// This is how a pasted credential (a Claude setup token) reaches the
/// config without ever appearing in the config document: the document
/// carries the reference, the store carries ciphertext, and the console
/// never reads it back.
async fn put_secret(
    State(state): State<Arc<AppState>>,
    Json(input): Json<SecretWrite>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let name = input.name.trim().to_owned();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "secret names use letters, digits, `_` and `-`",
        );
    }
    if input.value.trim().is_empty() {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "an empty secret is not a secret",
        );
    }
    let Some(store) = state.store.as_deref() else {
        return api_error(StatusCode::CONFLICT, "this node has no control-plane store");
    };
    let sealed = store.seal_secret(input.value.trim());
    match state
        .commit(
            None,
            Command::PutSecret {
                name: name.clone(),
                sealed,
            },
        )
        .await
    {
        Ok(_) => Json(json!({ "reference": format!("store.{name}") })).into_response(),
        Err(err) => commit_error(err),
    }
}

#[derive(Deserialize)]
struct CredentialFileWrite {
    name: String,
    /// The full document, e.g. an uploaded Codex auth.json.
    content: String,
}

/// Persist an uploaded credential document under the data dir and return
/// a `file:` reference to it.
///
/// A file rather than a store secret, deliberately: Codex credentials
/// rotate their refresh token on every renewal and the refresher
/// persists the merged document back to its source path. A store-backed
/// credential would serve until the first restart after a rotation, then
/// silently die. Single-node by nature — the file lives on this box —
/// which matches how subscription seats are deployed anyway.
async fn put_credential_file(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CredentialFileWrite>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let name = input.name.trim().to_owned();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "credential file names use letters, digits, `_` and `-`",
        );
    }
    if serde_json::from_str::<Value>(&input.content).is_err() {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the uploaded file is not valid JSON",
        );
    }
    let Some(dir) = state.data_dir.as_deref() else {
        return api_error(StatusCode::CONFLICT, "this node has no data directory");
    };
    let credentials = dir.join("credentials");
    if let Err(err) = std::fs::create_dir_all(&credentials) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let path = credentials.join(format!("{name}.json"));
    if let Err(err) = std::fs::write(&path, input.content.as_bytes()) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Json(json!({ "reference": format!("file:{}", path.display()) })).into_response()
}

#[derive(Deserialize)]
struct CredentialFileBulk {
    files: Vec<CredentialFileWrite>,
}

/// Persist many uploaded credential documents in one request.
///
/// Onboarding a subscription pool means dozens of `auth.json` files at
/// once; one request per file would be dozens of round trips before the
/// config is even touched. Partial success is reported rather than
/// rolled back — a malformed file among eighty should not cost the
/// operator the other seventy-nine.
async fn put_credential_files(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CredentialFileBulk>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let Some(dir) = state.data_dir.as_deref() else {
        return api_error(StatusCode::CONFLICT, "this node has no data directory");
    };
    let credentials = dir.join("credentials");
    if let Err(err) = std::fs::create_dir_all(&credentials) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    let mut written = Vec::new();
    let mut failed = Vec::new();
    for file in input.files {
        let name = file.name.trim().to_owned();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            failed.push(json!({ "name": file.name, "error": "invalid credential file name" }));
            continue;
        }
        if serde_json::from_str::<Value>(&file.content).is_err() {
            failed.push(json!({ "name": name, "error": "not valid JSON" }));
            continue;
        }
        let path = credentials.join(format!("{name}.json"));
        if let Err(err) = std::fs::write(&path, file.content.as_bytes()) {
            failed.push(json!({ "name": name, "error": err.to_string() }));
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        written.push(json!({ "name": name, "reference": format!("file:{}", path.display()) }));
    }
    Json(json!({ "written": written, "failed": failed })).into_response()
}

#[derive(Deserialize)]
struct KeyBulk {
    keys: Vec<NewKey>,
}

/// Add many credentials to a provider in a single config commit.
///
/// One commit rather than one per key: each commit is a full read-modify-
/// write of the store document (an S3 round trip in production), and
/// eighty of them in sequence would both crawl and give every other
/// writer eighty chances to collide. Existing names are skipped and
/// reported, so re-running an import is safe.
async fn add_provider_keys(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<KeyBulk>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    for key in &input.keys {
        if let Err(message) = check_tenant(&state, key.tenant.as_deref()) {
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, message);
        }
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(provider) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };

    if provider.get("keys").and_then(|k| k.as_array()).is_none() {
        provider["keys"] = toml_edit::value(toml_edit::Array::new());
    }
    let Some(keys) = provider.get_mut("keys").and_then(|k| k.as_array_mut()) else {
        return api_error(
            StatusCode::CONFLICT,
            format!("`{name}` has a malformed keys list"),
        );
    };

    let existing: Vec<String> = keys
        .iter()
        .filter_map(|k| k.as_inline_table())
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_owned))
        .collect();

    let mut added = Vec::new();
    let mut skipped = Vec::new();
    for key in &input.keys {
        if existing.contains(&key.name) || added.contains(&key.name) {
            skipped.push(key.name.clone());
            continue;
        }
        keys.push(toml_edit::Value::InlineTable(key_entry(key, &[])));
        added.push(key.name.clone());
    }
    if added.is_empty() {
        return Json(json!({ "added": added, "skipped": skipped })).into_response();
    }

    let response = commit_document(&state, version, doc).await;
    if !response.status().is_success() {
        return response;
    }
    Json(json!({ "added": added, "skipped": skipped })).into_response()
}

#[derive(Deserialize)]
struct ProbeRequest {
    /// Probe one credential; absent means every credential of the provider.
    key: Option<String>,
    /// Override the model to probe with; otherwise the first one declared.
    model: Option<String>,
}

/// Check credentials by actually using them.
///
/// A seat that has served no traffic has never reported its plan
/// windows, so its state is genuinely unknown until something asks. This
/// sends the smallest valid request per credential through the ordinary
/// dispatch path and reports what came back — and because the reply's
/// quota headers are recorded on the way through, a check also fills in
/// the windows the console draws.
///
/// Credentials are probed concurrently but capped: eighty seats firing
/// at one provider at once is a self-inflicted rate limit.
async fn probe_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<ProbeRequest>,
) -> Response {
    let table = state.table.load();
    let Some(provider) = table.providers().find(|p| p.name == name).cloned() else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };

    let targets: Vec<String> = match input.key.as_deref() {
        Some(key) => {
            if !provider.keys.iter().any(|k| k.name == key) {
                return api_error(StatusCode::NOT_FOUND, format!("no credential `{key}`"));
            }
            vec![key.to_owned()]
        }
        None => provider.keys.iter().map(|k| k.name.clone()).collect(),
    };
    if targets.is_empty() {
        return api_error(
            StatusCode::CONFLICT,
            format!("`{name}` has no credentials to check"),
        );
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(6));
    let mut tasks = tokio::task::JoinSet::new();
    for key_name in targets {
        // Every model this credential could be asked for, in declared
        // order. A model the backend no longer serves to this plan is
        // refused with a 400 that says nothing about the credential, so
        // the check moves on to the next one rather than failing the
        // seat over it — which is how every seat read "400 Bad Request"
        // for a day after `gpt-5.4-mini` was withdrawn from ChatGPT
        // accounts while still first in every seat's list.
        let candidates: Vec<String> = match input.model.clone() {
            Some(model) => vec![model],
            None => probe_models(&provider, &key_name),
        };
        if candidates.is_empty() {
            tasks.spawn(async move {
                json!({
                    "key": key_name,
                    "status": "unknown",
                    "detail": "no model declared for this credential — add one on the Models page",
                })
            });
            continue;
        }
        let state = state.clone();
        let provider = provider.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let mut last = None;
            for model in candidates {
                let outcome =
                    crate::proxy::probe_key(&state, provider.clone(), &key_name, &model).await;
                let rejected_model = outcome.status == "rejected";
                last = Some((model, outcome));
                if !rejected_model {
                    break;
                }
            }
            let (model, outcome) = last.expect("at least one candidate");
            json!({
                "key": key_name,
                "model": model,
                "status": outcome.status,
                "detail": outcome.detail,
                "http_status": outcome.http_status,
            })
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(value) = joined {
            results.push(value);
        }
    }
    Json(json!({ "results": results })).into_response()
}

/// What the canary has learned about each Codex seat: success rate,
/// latency percentiles and the last question and answer.
async fn canary_report(State(state): State<Arc<AppState>>) -> Response {
    Json(state.canary.report()).into_response()
}

/// Mint a one-time code so an operator can sign a dead seat back in.
///
/// Deliberately not gated on `writable`: this writes the seat's own
/// credential file, which is exactly what the refresher does on its own
/// every ten days. A node whose *config* is file-managed still owns its
/// credentials, and refusing here would leave the one class of seat that
/// cannot self-heal with no way to heal at all.
async fn start_device_login(
    State(state): State<Arc<AppState>>,
    Path((name, key)): Path<(String, String)>,
) -> Response {
    match crate::device_login::start(&state, &name, &key).await {
        Ok((session, login)) => Json(json!({
            "session": session,
            "user_code": login.user_code,
            "verification_url": login.verification_url,
            "expires_at_ms": login.expires_at_ms,
            "outcome": login.outcome.as_json(),
        }))
        .into_response(),
        Err(refusal) => api_error(refusal.status, refusal.message),
    }
}

/// Where a login has got to. Polled by the console while the dialog is
/// open; the flow itself runs server-side and does not depend on it.
async fn device_login_status(
    State(state): State<Arc<AppState>>,
    Path((name, key, session)): Path<(String, String, String)>,
) -> Response {
    let Some(login) = state.logins.get(&session) else {
        // Also the answer for a login that finished long enough ago to
        // have been reaped, which is why it says what to do about it.
        return api_error(
            StatusCode::NOT_FOUND,
            "that login is no longer being tracked — start a new one",
        );
    };
    if login.provider != name || login.key != key {
        return api_error(StatusCode::NOT_FOUND, "that login belongs to another seat");
    }
    Json(json!({
        "session": session,
        "user_code": login.user_code,
        "verification_url": login.verification_url,
        "expires_at_ms": login.expires_at_ms,
        "outcome": login.outcome.as_json(),
    }))
    .into_response()
}

/// The model a probe should ask for: whatever this credential declares
/// first, else whatever the provider serves, else — for a subscription
/// seat — whatever the plan is known to serve.
///
/// That last step exists because a seat's model set is not an operator
/// choice the way a metered provider's is: the plan decides it, and the
/// catalog already records it. Without it a freshly added seat cannot be
/// checked at all, and the console reports "no model declared" for a
/// credential that is perfectly able to answer. A metered provider gets
/// no such guess — an id the account cannot reach would fail the check
/// and blame the credential.
pub(crate) fn probe_model(
    provider: &router_core::router::ProviderRuntime,
    key_name: &str,
) -> Option<String> {
    probe_models(provider, key_name).into_iter().next()
}

/// Every model a probe may try for this credential, in order: the
/// credential's own list, else the provider's, else — for a subscription
/// seat — what the plan is known to serve. See [`probe_model`].
pub(crate) fn probe_models(
    provider: &router_core::router::ProviderRuntime,
    key_name: &str,
) -> Vec<String> {
    let declared = provider
        .keys
        .iter()
        .find(|k| k.name == key_name)
        .and_then(|k| k.models.as_ref())
        .or_else(|| provider.keys.iter().find_map(|k| k.models.as_ref()))
        .map(|models| models.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if !declared.is_empty() {
        return declared;
    }
    let preset = match provider.kind {
        router_core::config::ProviderKind::ClaudeSubscription => "claude_subscription",
        router_core::config::ProviderKind::CodexSubscription => "codex_subscription",
        _ => return Vec::new(),
    };
    router_core::config::presets::catalog(preset)
        .iter()
        .map(|m| m.id.to_owned())
        .collect()
}

/// Fetch the public price catalog and swap it in.
///
/// Costs are computed at request time from whatever pricing is loaded,
/// so a refresh only affects traffic from here on — historical spend is
/// already written and is deliberately not restated. An operator who
/// wants old numbers repriced has the raw token counts to do it with.
async fn refresh_pricing(State(state): State<Arc<AppState>>) -> Response {
    let url = std::env::var("RAPID_PRICE_CATALOG_URL")
        .unwrap_or_else(|_| crate::usage::DEFAULT_PRICE_CATALOG_URL.to_owned());
    match crate::usage::fetch_catalog(&state.upstream, &url).await {
        Ok(catalog) => {
            let count = catalog.len();
            let updated = state.pricing.load().with_catalog(Arc::new(catalog));
            state.pricing.store(Arc::new(updated));
            Json(json!({ "models": count, "source": url })).into_response()
        }
        Err(err) => api_error(StatusCode::BAD_GATEWAY, err),
    }
}

/// Everything the console needs to offer an "add provider" form: the
/// presets it can start from, and the models each is seeded with.
async fn catalog(State(state): State<Arc<AppState>>) -> Response {
    use router_core::config::presets;
    let configured: Vec<String> = state
        .table
        .load()
        .providers()
        .map(|p| p.name.clone())
        .collect();
    let kinds: Vec<Value> = presets::ALL_PRESETS
        .iter()
        .map(|name| {
            let preset = presets::preset(name);
            json!({
                "name": name,
                "base_url": preset.as_ref().and_then(|p| p.base_url),
                "discovery_env": preset.as_ref().and_then(|p| p.discovery_env),
                "keyless_ok": preset.as_ref().is_some_and(|p| p.keyless_ok),
                "models": presets::catalog(name).iter().map(|m| json!({
                    "id": m.id, "format": m.format.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let custom = json!({
        "name": "openai_compat",
        "custom": true,
        "base_url": null,
        "keyless_ok": true,
        "models": [],
    });
    // The two subscription kinds are not presets — they are configured by
    // `type`, not by name — but the console offers them in the same
    // picker, so they are listed here too.
    let subscriptions: Vec<Value> = ["claude_subscription", "codex_subscription"]
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "subscription": true,
                "models": presets::catalog(name).iter().map(|m| json!({
                    "id": m.id, "format": m.format.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({ "presets": kinds, "subscriptions": subscriptions, "custom": custom, "configured": configured }))
        .into_response()
}

/// Read the config document for editing, as a `toml_edit` tree.
///
/// Format-preserving: an operator's comments and key order survive a
/// change made from the console, which a parse-and-reserialize round trip
/// would silently discard.
fn config_document(state: &AppState) -> Result<(u64, toml_edit::DocumentMut), Box<Response>> {
    let (text, version) = state
        .store_read()
        .map(|(snapshot, version)| (snapshot.config_text.unwrap_or_default(), version))
        .unwrap_or_default();
    text.parse::<toml_edit::DocumentMut>()
        .map(|doc| (version, doc))
        .map_err(|err| {
            Box::new(api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("config is not valid TOML: {err}"),
            ))
        })
}

/// Validate and commit an edited document.
async fn commit_document(
    state: &Arc<AppState>,
    version: u64,
    doc: toml_edit::DocumentMut,
) -> Response {
    let text = doc.to_string();
    let env = |name: &str| {
        if let Some(secret) = name.strip_prefix("store.") {
            state
                .store
                .as_deref()
                .and_then(|s| s.resolve_secret(secret))
        } else {
            std::env::var(name).ok()
        }
    };
    if let Err(err) = Config::from_str_with_env(&text, Format::Toml, &env) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, err.to_string());
    }
    match state
        .commit(Some(version), Command::PutConfig { text })
        .await
    {
        Ok(version) => {
            // Adopt through the same path a remote change takes, so there
            // is one place where a config becomes live on a node. Without
            // this the write reaches the store and the node that made it
            // keeps serving the old routing table — the change appears to
            // have been ignored.
            state.adopt_store_state();
            Json(json!({ "version": version })).into_response()
        }
        Err(ControlPlaneError::Conflict { .. }) => api_error(
            StatusCode::CONFLICT,
            "the configuration changed since it was read; reload and try again",
        ),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Deserialize)]
struct NewProvider {
    name: String,
    /// A preset name (`openai`) or an explicit adapter (`claude_subscription`).
    kind: Option<String>,
    base_url: Option<String>,
    /// `"none"` for keyless servers; omitted otherwise.
    auth: Option<String>,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    keys: Vec<NewKey>,
}

#[derive(Deserialize)]
struct NewKey {
    /// Which service owns this account; omitted = unassigned.
    #[serde(default)]
    tenant: Option<String>,
    name: String,
    /// `env.VAR`, `file:/path`, `store.name`, or a literal.
    value: String,
    weight: Option<f64>,
    rpm: Option<u64>,
    tpm: Option<u64>,
    /// Requests this key may carry at once; omitted = the provider's
    /// `key_limits` default, or unbounded.
    max_concurrency: Option<u32>,
    #[serde(default)]
    models: Vec<String>,
}

fn key_entry(key: &NewKey, fallback_models: &[String]) -> toml_edit::InlineTable {
    let mut entry = toml_edit::InlineTable::new();
    entry.insert("name", key.name.clone().into());
    entry.insert("value", key.value.clone().into());
    if let Some(tenant) = &key.tenant {
        entry.insert("tenant", tenant.as_str().into());
    }
    if let Some(weight) = key.weight {
        entry.insert("weight", weight.into());
    }
    if let Some(rpm) = key.rpm {
        entry.insert("rpm", (rpm as i64).into());
    }
    if let Some(tpm) = key.tpm {
        entry.insert("tpm", (tpm as i64).into());
    }
    if let Some(max_concurrency) = key.max_concurrency {
        entry.insert("max_concurrency", i64::from(max_concurrency).into());
    }
    let models = if key.models.is_empty() {
        fallback_models
    } else {
        &key.models
    };
    if !models.is_empty() {
        let mut list = toml_edit::Array::new();
        for model in models {
            list.push(model.as_str());
        }
        entry.insert("models", toml_edit::Value::Array(list));
    }
    entry
}

async fn create_provider(
    State(state): State<Arc<AppState>>,
    Json(input): Json<NewProvider>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if input.name.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "name is required");
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if doc
        .get("providers")
        .and_then(|p| p.get(&input.name))
        .is_some()
    {
        return api_error(
            StatusCode::CONFLICT,
            format!("provider `{}` already exists", input.name),
        );
    }

    let providers = doc["providers"].or_insert(toml_edit::table());
    if let Some(table) = providers.as_table_mut() {
        table.set_implicit(true);
    }
    let mut entry = toml_edit::Table::new();
    if let Some(kind) = &input.kind
        && kind != &input.name
    {
        entry["type"] = toml_edit::value(kind.as_str());
    }
    if let Some(base) = &input.base_url {
        entry["base_url"] = toml_edit::value(base.as_str());
    }
    if let Some(auth) = &input.auth {
        entry["auth"] = toml_edit::value(auth.as_str());
    }
    let mut keys = toml_edit::Array::new();
    for key in &input.keys {
        keys.push(toml_edit::Value::InlineTable(key_entry(key, &input.models)));
    }
    if !keys.is_empty() {
        entry["keys"] = toml_edit::value(keys);
    }
    providers[input.name.as_str()] = toml_edit::Item::Table(entry);
    commit_document(&state, version, doc).await
}

#[derive(Deserialize)]
struct ProviderUpdate {
    /// `Some("")` clears the override back to the preset default.
    base_url: Option<String>,
}

async fn update_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<ProviderUpdate>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(provider) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };
    if let Some(base) = input.base_url {
        let trimmed = base.trim();
        if trimmed.is_empty() {
            if let Some(table) = provider.as_table_like_mut() {
                table.remove("base_url");
            }
        } else {
            provider["base_url"] = toml_edit::value(trimmed);
        }
    }
    commit_document(&state, version, doc).await
}

async fn delete_provider(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(providers) = doc.get_mut("providers").and_then(|p| p.as_table_like_mut()) else {
        return api_error(StatusCode::NOT_FOUND, "no providers configured");
    };
    if providers.remove(&name).is_none() {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    }
    commit_document(&state, version, doc).await
}

#[derive(Deserialize)]
struct NewTenant {
    name: String,
}

/// Declare a service.
///
/// The roster is the vocabulary every other control here draws on — the
/// pickers on a key, the filter on the credentials table, the bulk assign.
/// Until this existed the only way to add a word to it was to edit the
/// gateway's config by hand, which meant the console could show the whole
/// operation and not let anyone begin it.
async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(input): Json<NewTenant>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let name = input.name.trim().to_owned();
    // Stricter than the config loader, deliberately: a name typed here is
    // about to be copied onto accounts and keys and read back in log lines
    // and error messages, and there is no reason to allow one that reads
    // badly in any of them. Existing configs keep whatever they already say.
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a service name must be 1-64 characters of letters, digits, `-` or `_`",
        );
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let list = doc
        .entry("tenants")
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let Some(array) = list.as_array_mut() else {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "`tenants` in the configuration is not a list",
        );
    };
    if array.iter().any(|v| v.as_str() == Some(name.as_str())) {
        return api_error(
            StatusCode::CONFLICT,
            format!("service `{name}` is already declared"),
        );
    }
    array.push(name.as_str());
    commit_document(&state, version, doc).await
}

/// Remove a service, but only once nothing still points at it.
///
/// Deleting a name that is still in use is the quiet way to break this
/// feature: an account whose service no longer exists is owned by nobody,
/// and on a divided pool it serves nobody while still reporting healthy and
/// in quota. A key naming it owns nothing and every request it makes is
/// refused. Neither failure says why, and neither is visible until traffic
/// arrives — so this refuses, and names exactly what is in the way.
async fn delete_tenant(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let config = state.config.load();
    if !config.tenants.contains(&name) {
        return api_error(StatusCode::NOT_FOUND, format!("no service `{name}`"));
    }

    let accounts: Vec<String> = config
        .providers
        .iter()
        .flat_map(|(provider, p)| {
            p.keys
                .iter()
                .filter(|k| k.tenant.as_deref() == Some(name.as_str()))
                .map(move |k| format!("{provider}/{}", k.name))
        })
        .collect();
    let keys: Vec<String> = state
        .vkeys
        .load()
        .iter()
        .filter(|rt| rt.def.tenant.as_deref() == Some(name.as_str()))
        .map(|rt| rt.def.name.clone())
        .collect();
    // A static gateway key is the worst one to strand: its callers present a
    // shared secret and often cannot be reconfigured at all, so they would
    // simply start failing with nothing to change on their side.
    let static_keys = config
        .server
        .auth_keys
        .iter()
        .filter(|k| k.tenant.as_deref() == Some(name.as_str()))
        .count();

    if !accounts.is_empty() || !keys.is_empty() || static_keys > 0 {
        let mut blockers = Vec::new();
        if !accounts.is_empty() {
            blockers.push(format!(
                "{} account{} ({})",
                accounts.len(),
                if accounts.len() == 1 { "" } else { "s" },
                preview(&accounts)
            ));
        }
        if !keys.is_empty() {
            blockers.push(format!(
                "{} virtual key{} ({})",
                keys.len(),
                if keys.len() == 1 { "" } else { "s" },
                keys.join(", ")
            ));
        }
        if static_keys > 0 {
            blockers.push(format!("{static_keys} static gateway key(s)"));
        }
        return api_error(
            StatusCode::CONFLICT,
            format!(
                "service `{name}` still has {}. Move them to another service first — \
                 deleting it would leave them owned by nobody.",
                blockers.join(", ")
            ),
        );
    }

    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Some(array) = doc.get_mut("tenants").and_then(|v| v.as_array_mut()) {
        array.retain(|v| v.as_str() != Some(name.as_str()));
    }
    commit_document(&state, version, doc).await
}

/// The first few of a list, for an error an operator has to act on.
fn preview(items: &[String]) -> String {
    const SHOWN: usize = 3;
    if items.len() <= SHOWN {
        return items.join(", ");
    }
    format!(
        "{}, and {} more",
        items[..SHOWN].join(", "),
        items.len() - SHOWN
    )
}

#[derive(Deserialize)]
struct AccountTenant {
    /// `null` unassigns the account.
    #[serde(default)]
    tenant: Option<String>,
}

/// Move one account to a service — the whole management operation.
///
/// One field on one account, so a move cannot be half-applied and an
/// account cannot end up owned by two services or by none by accident. The
/// service it came from is implied: the account already knew.
async fn set_account_tenant(
    State(state): State<Arc<AppState>>,
    Path((name, key)): Path<(String, String)>,
    Json(input): Json<AccountTenant>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if let Err(message) = check_tenant(&state, input.tenant.as_deref()) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(keys) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
        .and_then(|p| p.get_mut("keys"))
        .and_then(|k| k.as_array_mut())
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };
    let Some(entry) = keys
        .iter_mut()
        .filter_map(|value| value.as_inline_table_mut())
        .find(|table| table.get("name").and_then(|n| n.as_str()) == Some(key.as_str()))
    else {
        return api_error(
            StatusCode::NOT_FOUND,
            format!("provider `{name}` has no account `{key}`"),
        );
    };
    match &input.tenant {
        Some(tenant) => {
            entry.insert("tenant", toml_edit::Value::from(tenant.as_str()));
        }
        None => {
            entry.remove("tenant");
        }
    }
    commit_document(&state, version, doc).await
}

async fn add_provider_key(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<NewKey>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if let Err(message) = check_tenant(&state, input.tenant.as_deref()) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(provider) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };
    let entry = key_entry(&input, &[]);
    match provider.get_mut("keys").and_then(|k| k.as_array_mut()) {
        Some(keys) => keys.push(toml_edit::Value::InlineTable(entry)),
        None => {
            let mut keys = toml_edit::Array::new();
            keys.push(toml_edit::Value::InlineTable(entry));
            provider["keys"] = toml_edit::value(keys);
        }
    }
    commit_document(&state, version, doc).await
}

async fn delete_provider_key(
    State(state): State<Arc<AppState>>,
    Path((name, key)): Path<(String, String)>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(keys) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
        .and_then(|p| p.get_mut("keys"))
        .and_then(|k| k.as_array_mut())
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no keys on `{name}`"));
    };
    let before = keys.len();
    keys.retain(|entry| {
        entry
            .as_inline_table()
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            != Some(key.as_str())
    });
    if keys.len() == before {
        return api_error(StatusCode::NOT_FOUND, format!("no key `{key}` on `{name}`"));
    }
    commit_document(&state, version, doc).await
}

#[derive(Deserialize)]
struct KeyNames {
    keys: Vec<String>,
}

/// Remove many credentials from a provider in a single config commit.
///
/// The counterpart to [`add_provider_keys`], and one commit for the same
/// reason: a commit is a full read-modify-write of the store document, so
/// removing fifteen duplicate seats one request at a time would rebuild
/// the routing table fifteen times and hand every other writer fifteen
/// chances to collide. It would also fail *partway* — leaving a caller
/// with no way to say which half of its intent had landed.
///
/// Names that are not on the provider are reported rather than refused.
/// The set an operator selects in the console is a snapshot, and a key
/// that a colleague removed in between is the outcome that was wanted;
/// failing the whole batch over it would be the surprising answer.
/// A batch matching nothing at all commits nothing.
async fn delete_provider_keys(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<KeyNames>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(keys) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
        .and_then(|p| p.get_mut("keys"))
        .and_then(|k| k.as_array_mut())
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no keys on `{name}`"));
    };

    let wanted: std::collections::BTreeSet<&str> = input.keys.iter().map(String::as_str).collect();
    let removed: Vec<String> = keys
        .iter()
        .filter_map(|entry| entry.as_inline_table())
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
        .filter(|found| wanted.contains(found))
        .map(str::to_owned)
        .collect();
    let missing: Vec<String> = input
        .keys
        .iter()
        .filter(|asked| !removed.iter().any(|found| found == *asked))
        .cloned()
        .collect();

    if removed.is_empty() {
        return Json(json!({ "removed": removed, "missing": missing })).into_response();
    }
    keys.retain(|entry| {
        !entry
            .as_inline_table()
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .is_some_and(|found| wanted.contains(found))
    });

    let response = commit_document(&state, version, doc).await;
    if !response.status().is_success() {
        return response;
    }
    Json(json!({ "removed": removed, "missing": missing })).into_response()
}

#[derive(Deserialize)]
struct ModelWrite {
    id: String,
}

/// Add a model to every key of a provider that already names models.
///
/// A model is routable when a key lists it, so "add a model" is "widen
/// the keys' model lists". A key with no list already serves everything
/// the provider offers and is left alone — narrowing it to an explicit
/// list here would *remove* routes as a side effect of adding one.
async fn add_model(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<ModelWrite>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let model = input.id.trim().to_owned();
    if model.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "a model id is required");
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(keys) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
        .and_then(|p| p.get_mut("keys"))
        .and_then(|k| k.as_array_mut())
    else {
        return api_error(
            StatusCode::NOT_FOUND,
            format!("no provider `{name}` with keys"),
        );
    };
    let mut touched = false;
    for entry in keys.iter_mut() {
        let Some(table) = entry.as_inline_table_mut() else {
            continue;
        };
        match table.get_mut("models").and_then(|m| m.as_array_mut()) {
            Some(models) => {
                if models.iter().any(|m| m.as_str() == Some(model.as_str())) {
                    continue;
                }
                models.push(model.as_str());
                touched = true;
            }
            None => {
                // A key with no list served "whatever the provider has";
                // the first declared model converts it to an explicit
                // list, which is the console's contract: models are
                // declared, never assumed.
                let mut models = toml_edit::Array::new();
                models.push(model.as_str());
                table.insert("models", toml_edit::Value::Array(models));
                touched = true;
            }
        }
    }
    if !touched {
        return api_error(
            StatusCode::CONFLICT,
            format!("every key of `{name}` already lists `{model}`"),
        );
    }
    commit_document(&state, version, doc).await
}

async fn delete_model(
    State(state): State<Arc<AppState>>,
    Path((name, model)): Path<(String, String)>,
) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(keys) = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_like_mut())
        .and_then(|p| p.get_mut(&name))
        .and_then(|p| p.get_mut("keys"))
        .and_then(|k| k.as_array_mut())
    else {
        return api_error(StatusCode::NOT_FOUND, format!("no provider `{name}`"));
    };
    for entry in keys.iter_mut() {
        if let Some(models) = entry
            .as_inline_table_mut()
            .and_then(|t| t.get_mut("models"))
            .and_then(|m| m.as_array_mut())
        {
            models.retain(|m| m.as_str() != Some(model.as_str()));
        }
    }
    commit_document(&state, version, doc).await
}

/// A routing group: the model id callers send, and the two weighted pools
/// it dispatches over.
///
/// `primary` is the traffic split — every model in it serves live
/// requests, in proportion to its weight. `fallback` is the reserve,
/// reached only once the primary pool has nothing left to try, and
/// weighted the same way among itself.
///
/// Legacy `[aliases]`/`[fallbacks]` entries are listed here too, as a
/// group whose pools are all weight 1: they expressed the same idea with
/// no way to say how much traffic went where. Saving one over this
/// endpoint rewrites it as a `[groups]` entry.
async fn list_routes(State(state): State<Arc<AppState>>) -> Response {
    let table = state.table.load();
    let mut data: Vec<Value> = table
        .groups()
        .iter()
        .map(|(name, group)| {
            json!({
                "name": name,
                "primary": pool_json(&group.primary),
                "fallback": pool_json(&group.fallback),
            })
        })
        .collect();
    for (name, target) in table.aliases() {
        if table.group(name).is_some() {
            continue;
        }
        let chain = table
            .fallbacks_for(target)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        data.push(json!({
            "name": name,
            "primary": [json!({ "target": target.to_string(), "weight": 1.0 })],
            "fallback": chain
                .iter()
                .map(|t| json!({ "target": t.to_string(), "weight": 1.0 }))
                .collect::<Vec<_>>(),
        }));
    }
    data.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Json(json!({ "data": data })).into_response()
}

fn pool_json(pool: &[router_core::config::WeightedTarget]) -> Vec<Value> {
    pool.iter()
        .map(|w| json!({ "target": w.target.to_string(), "weight": w.weight }))
        .collect()
}

#[derive(Deserialize)]
struct RouteWrite {
    name: String,
    /// Models that serve live traffic, split by weight.
    primary: Vec<RouteTargetWrite>,
    /// Models held in reserve for when the primary pool is exhausted.
    #[serde(default)]
    fallback: Vec<RouteTargetWrite>,
}

#[derive(Deserialize)]
struct RouteTargetWrite {
    target: String,
    #[serde(default = "one")]
    weight: f64,
}

fn one() -> f64 {
    1.0
}

/// Render one pool as `[{ target = "…", weight = … }, …]`.
fn pool_array(pool: &[RouteTargetWrite]) -> toml_edit::Array {
    let mut array = toml_edit::Array::new();
    for entry in pool {
        let mut item = toml_edit::InlineTable::new();
        item.insert("target", entry.target.as_str().into());
        item.insert("weight", entry.weight.into());
        array.push(toml_edit::Value::InlineTable(item));
    }
    array
}

async fn put_route(State(state): State<Arc<AppState>>, Json(input): Json<RouteWrite>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    if input.name.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "a group needs a name");
    }
    if input.primary.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "a group needs at least one primary model",
        );
    }
    for entry in input.primary.iter().chain(&input.fallback) {
        if !(entry.weight.is_finite() && entry.weight > 0.0) {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("weight for `{}` must be a number > 0", entry.target),
            );
        }
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };

    let groups = doc["groups"].or_insert(toml_edit::table());
    if let Some(table) = groups.as_table_mut() {
        table.set_implicit(true);
    }
    let mut entry = toml_edit::table();
    entry["primary"] = toml_edit::value(pool_array(&input.primary));
    if !input.fallback.is_empty() {
        entry["fallback"] = toml_edit::value(pool_array(&input.fallback));
    }
    groups[input.name.as_str()] = entry;

    // Saving over a legacy alias migrates it: leaving both behind would
    // define the same caller-facing name twice, which config validation
    // rejects outright.
    drop_legacy_alias(&mut doc, &input.name);

    commit_document(&state, version, doc).await
}

async fn delete_route(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(response) = writable(&state) {
        return response;
    }
    let (version, mut doc) = match config_document(&state) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Some(groups) = doc.get_mut("groups").and_then(|g| g.as_table_like_mut()) {
        groups.remove(&name);
    }
    drop_legacy_alias(&mut doc, &name);
    commit_document(&state, version, doc).await
}

/// Remove an `[aliases]` entry and the `[fallbacks]` chain it owned.
///
/// The chain is keyed by the *target*, not the alias, so it is only
/// orphaned once no other alias still points there.
fn drop_legacy_alias(doc: &mut toml_edit::DocumentMut, name: &str) {
    let primary = doc
        .get("aliases")
        .and_then(|a| a.get(name))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(aliases) = doc.get_mut("aliases").and_then(|a| a.as_table_like_mut()) {
        aliases.remove(name);
    }
    let Some(primary) = primary else { return };
    let still_used = doc
        .get("aliases")
        .and_then(|a| a.as_table_like())
        .is_some_and(|a| a.iter().any(|(_, v)| v.as_str() == Some(primary.as_str())));
    if !still_used
        && let Some(fallbacks) = doc.get_mut("fallbacks").and_then(|f| f.as_table_like_mut())
    {
        fallbacks.remove(&primary);
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_days")]
    days: u32,
    #[serde(default)]
    by: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    key: Option<String>,
}

fn default_days() -> u32 {
    30
}

/// The widest history read this endpoint will serve.
///
/// Above a year, not at it: the console asks for
/// `ceil(seconds / 86400) + 1` days so a "Last year" preset lands on 366,
/// and a clamp of exactly 365 would silently return a range one day
/// narrower than the one the picker says it selected.
const MAX_HISTORY_DAYS: u32 = 400;

/// Daily spend and volume for the Usage page's time ramp.
///
/// The in-memory aggregate only spans 24 hours, so anything longer is
/// read back from the flushed usage files. Capped at a year: the read
/// walks every record in range, and an unbounded range on a busy gateway
/// is a way to make the console the slowest thing in the process.
async fn history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let by = query.by.as_deref().unwrap_or("");
    // `all` returns every grouping from one read. The console asks for
    // it because it draws all of them at once, and three separate calls
    // were three identical walks of the same window.
    let every = by == "all";
    let by = if matches!(by, "provider" | "model" | "key") {
        by
    } else {
        ""
    };
    let filter = crate::usage::HistoryFilter {
        provider: query.provider.filter(|v| !v.is_empty()),
        model: query.model.filter(|v| !v.is_empty()),
        vkey: query.key.filter(|v| !v.is_empty()),
    };
    let usage = state.usage.clone();
    let by = by.to_owned();
    let days = query.days.clamp(1, MAX_HISTORY_DAYS);
    let key = format!(
        "history?{days}-{}-{}-{}-{}-{}",
        if every { "all" } else { by.as_str() },
        filter.provider.as_deref().unwrap_or(""),
        filter.model.as_deref().unwrap_or(""),
        filter.vkey.as_deref().unwrap_or(""),
        // History always runs to now, so it re-reads today's partition;
        // only the live TTL applies.
        "live",
    );
    memoised(key, MEMO_TTL_LIVE, move || {
        // `all` carries the window's latency percentiles alongside the
        // groupings, which a day bucket cannot: percentiles do not sum,
        // so there is nothing per-day to hand back and add up.
        if every {
            return serde_json::to_value(usage.history_all(days, &filter));
        }
        Ok(json!({ "data": serde_json::to_value(usage.history(days, &by, &filter))? }))
    })
    .await
}

/// Per-provider, per-credential state for the console's Providers page.
///
/// The interesting column is the ceiling each credential is working
/// against, and the two kinds are genuinely different. A metered API key
/// is limited by what we configured (`rpm`/`tpm`), and the remaining
/// allowance is ours to compute. A subscription seat is limited by the
/// plan, on windows only the provider knows — Claude's 5h and 7d,
/// Codex's primary and secondary — so what is reported here is the last
/// thing the provider actually told us, with the time it said it.
///
/// Both are per credential rather than per provider, because that is how
/// they are enforced: one exhausted seat must not read as an exhausted
/// pool.
async fn providers(State(state): State<Arc<AppState>>) -> Response {
    let now = router_core::clock::now_ms();
    let now_unix = vkey::unix_now_ms();
    let table = state.table.load();

    let window = |w: Option<router_core::quota::Window>| {
        w.map(|w| {
            json!({
                "utilization": w.utilization,
                "resets_in_s": w.resets_in.map(|d| d.as_secs()),
                "length_s": w.length.map(|d| d.as_secs()),
                "rejected": w.rejected,
            })
        })
    };

    let data: Vec<Value> = table
        .providers()
        .map(|p| {
            let keys: Vec<Value> = p
                .keys
                .iter()
                .map(|k| {
                    let (rpm_left, tpm_left) = k.rate_headroom();
                    let seat = k.credential.seat().map(|s| s.current());
                    json!({
                        "name": k.name,
                        "weight": k.weight,
                        "models": k.models,
                        // Which service owns this account; `null` = nobody
                        // owns it, and in a labelled pool that means it
                        // serves nobody until someone assigns it.
                        "tenant": k.tenant,
                        "health": k.breaker.health(now),
                        // The breaker only knows about failures. A seat
                        // sitting at 100% of its plan window has failed
                        // nothing yet and would read "healthy" right up
                        // until the first refusal, which is precisely
                        // when an operator needs the warning. Fold the
                        // provider's own quota view in.
                        "status": effective_status(k, now),
                        // Reported as a wall-clock instant, not a
                        // duration: the console renders a countdown, and a
                        // duration computed here would be stale by the
                        // time it is drawn.
                        "benched_until_ms": k.breaker.benched_until_ms().map(|until| {
                            now_unix.saturating_add(until.saturating_sub(now))
                        }),
                        "limits": {
                            "rpm": k.rpm.as_ref().map(|_| json!({ "remaining": rpm_left })),
                            "tpm": k.tpm.as_ref().map(|_| json!({ "remaining": tpm_left })),
                            // How hard this key is being leaned on right
                            // now, against how hard it may be. The number
                            // an operator watches when the provider is
                            // throttling the busiest seats.
                            "concurrency": k.in_flight().map(|(in_flight, limit)| json!({
                                "in_flight": in_flight,
                                "limit": limit,
                            })),
                        },
                        "quota": k.quota().map(|snapshot| json!({
                            "observed_ms": now_unix.saturating_sub(now.saturating_sub(snapshot.observed_ms)),
                            "peak_utilization": snapshot.quota.peak_utilization(),
                            "primary": window(snapshot.quota.primary),
                            "secondary": window(snapshot.quota.secondary),
                        })),
                        // A seat's credential expires; a metered key's
                        // does not. `null` for "unknown" is meaningful —
                        // an opaque token carries no readable expiry.
                        "credential": seat.as_ref().map(|s| json!({
                            "email": s.email,
                            // The upstream account this seat signs in as,
                            // which is *not* the same thing as the key's
                            // name. Two keys built from two files that
                            // hold credentials for one ChatGPT account
                            // are one account's worth of quota wearing
                            // two names, and nothing else in this payload
                            // says so: the names differ, the emails may
                            // differ in case or be absent, and the quota
                            // windows move together in a way that looks
                            // like coincidence. Reported so the console
                            // can group them instead of an operator
                            // decoding id_tokens by hand.
                            "account_id": s.account_id,
                            "expires_at_ms": s.expires_at_ms,
                            "can_refresh": s.refresh_token.is_some(),
                            "expired": s.is_expired(now_unix),
                        })),
                        // The last word from the provider on this
                        // credential — from the maintenance sweep, from an
                        // operator's check, or from real traffic. Held on
                        // the gateway rather than in the browser so an
                        // opened drawer shows the state of the seat now,
                        // not the result of a check this tab happened to
                        // run. Wall-clocked the same way the quota
                        // observation is, and for the same reason.
                        "last_check": k.last_check().map(|c| json!({
                            "status": c.status,
                            "detail": c.detail,
                            "http_status": c.http_status,
                            "probed": c.probed,
                            "checked_at_ms":
                                now_unix.saturating_sub(now.saturating_sub(c.observed_ms)),
                        })),
                        // How many requests this key has been handed. The
                        // console shows it because "evenly spread" is a
                        // claim an operator should be able to check.
                        "leases": k.leases(),
                        "source_path": k.source_path,
                    })
                })
                .collect();
            json!({
                "name": p.name,
                "kind": format!("{:?}", p.kind),
                "subscription": p.kind.is_subscription(),
                "base_url": p.base_url,
                // A pool nobody has divided up is shared by every caller.
                // The console needs to know which it is looking at.
                "managed": p.managed,
                "keys": keys,
            })
        })
        .collect();
    Json(json!({
        "data": data,
        // The declared services, so the console can offer them rather than
        // making an operator type a name that has to match exactly.
        "tenants": state.config.load().tenants.iter().collect::<Vec<_>>(),
    }))
    .into_response()
}

/// One word for the state of a credential, folding together the three
/// things that can be wrong with it: the breaker (has it been failing),
/// the plan quota (is it out of headroom), and the credential itself
/// (can it still authenticate).
fn effective_status(key: &router_core::router::KeyRuntime, now: u64) -> &'static str {
    let health = key.breaker.health(now);
    if health == "benched" {
        return "exhausted";
    }
    if let Some(snapshot) = key.quota() {
        let quota = snapshot.quota;
        if quota.primary.is_some_and(|w| w.rejected) || quota.secondary.is_some_and(|w| w.rejected)
        {
            return "exhausted";
        }
        if let Some(peak) = quota.peak_utilization() {
            if peak >= 1.0 {
                return "exhausted";
            }
            if peak >= 0.9 {
                return "near_limit";
            }
        }
    }
    match health {
        "healthy" => "ready",
        "probing" => "probing",
        other => other,
    }
}

/// What the console's Fleet page reads: which store is authoritative,
/// and who else is currently serving traffic against it.
///
/// There are no roles, no terms and no quorum here, because there is no
/// consensus — every node is identical and the list is simply whoever has
/// heartbeated recently.
async fn fleet(State(state): State<Arc<AppState>>) -> Response {
    let mode = if state.file_managed {
        "file"
    } else {
        "managed"
    };
    let Some(store) = state.store.as_deref() else {
        return Json(json!({
            "mode": mode,
            "node": "local",
            "backend": "none",
            "version": 0,
            "live": 1,
            "shares": 1,
            "nodes": [],
        }))
        .into_response();
    };

    let window = state.liveness_window;
    let (nodes, reachable) = match store.peers(window).await {
        Ok(peers) => (peers, true),
        // The store being unreachable is worth showing, but it is not an
        // error for this endpoint: this node is still serving.
        Err(err) => {
            tracing::warn!(%err, "could not list the fleet");
            (Vec::new(), false)
        }
    };

    let now = router_store::backend::now_ms_for_tests();
    let listed: Vec<serde_json::Value> = nodes
        .iter()
        .map(|beat| {
            json!({
                "id": beat.id,
                "addr": beat.addr,
                "age_ms": beat.age(now).as_millis() as u64,
                "self": beat.id == store.node_id(),
            })
        })
        .collect();

    Json(json!({
        "mode": mode,
        "node": store.node_id(),
        "backend": store.describe(),
        "reachable": reachable,
        "version": store.version(),
        "live": store.live_nodes(),
        "shares": state.live_nodes(),
        "nodes": listed,
    }))
    .into_response()
}

async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let receiver = state.events.subscribe();
    // A `hello` before anything else, for two reasons. The obvious one:
    // the stream is otherwise silent until traffic happens, so on a quiet
    // gateway there is nothing to distinguish "connected" from "still
    // connecting" — which is how the console came to render
    // "Reconnecting" on every reload. The subtler one: it forces the
    // response head out now rather than at the first event, so the
    // browser's `onopen` fires on connect instead of on the first
    // request somebody else makes.
    let hello = futures_util::stream::once(async {
        Ok(Event::default()
            // Tell the browser to come back in a second rather than
            // using its own ~3s default: a dropped stream should not be
            // visible for longer than it takes to re-establish.
            .retry(Duration::from_secs(1))
            .json_data(json!({ "type": "hello" }))
            .unwrap_or_default())
    });
    let updates = futures_util::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(value) => {
                    let event = Event::default().json_data(value).unwrap_or_default();
                    return Some((Ok(event), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(futures_util::StreamExt::chain(hello, updates)).keep_alive(KeepAlive::default())
}

#[allow(dead_code)]
fn _assert_json_is_send(_: Value) {}
