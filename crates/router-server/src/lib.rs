//! HTTP surface: routes, application state, middleware, and graceful
//! serving.

mod admin;
pub mod canary;
#[cfg(feature = "console")]
mod console;
pub mod device_login;
pub mod histogram;
mod proxy;
pub mod refresh;
mod rollup_cache;
mod session;
mod upstream;
pub mod usage;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use router_core::breaker::Admission;
use router_core::clock;
use router_core::config::Config;
use router_core::router::{ProviderRuntime, RoutingTable};
use router_core::vkey::{self, VirtualKeyDef, VkRuntime, VkTable};
use router_core::{ErrorClass, GatewayError};
use router_store::{ControlPlaneError, Store};
use serde_json::json;

pub use proxy::Endpoint;

/// Default seconds of silence after which a node stops counting toward
/// rate-limit shares. Three missed heartbeats at the default interval.
const DEFAULT_LIVENESS_WINDOW: Duration = Duration::from_secs(15);

/// The authenticated virtual key of a request (None: static key or open
/// access). Inserted by the auth layer, consumed by dispatch for scope,
/// limit, and budget enforcement and usage attribution.
#[derive(Clone, Default)]
pub struct VkCtx {
    /// The virtual key that authenticated, when one did.
    pub key: Option<Arc<VkRuntime>>,
    /// Which service this request belongs to.
    ///
    /// Usually the virtual key's, but a static gateway key may name one too —
    /// which is the only way traffic from a caller nobody can reconfigure ever
    /// gets a service, since a shared password cannot identify who presented
    /// it. `None` means the request names no service and can therefore spend
    /// nothing on a divided pool.
    pub tenant: Option<String>,
}

/// One console session: when it lapses, and who it belongs to.
#[derive(Debug, Clone)]
pub struct Session {
    pub expires_ms: u64,
    pub principal: Principal,
}

/// Who authenticated: the shared admin key, or a stored user.
#[derive(Debug, Clone, PartialEq)]
pub enum Principal {
    AdminKey,
    User { id: String },
}

pub struct AppState {
    pub config: ArcSwap<Config>,
    pub table: ArcSwap<RoutingTable>,
    pub vkeys: ArcSwap<VkTable>,
    pub pricing: ArcSwap<usage::Pricing>,
    pub usage: Arc<usage::UsagePipeline>,
    /// The managed store; `None` in file/env mode.
    pub store: Option<Arc<Store>>,
    /// Live console events (request ticks, config applies).
    pub events: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Admin session tokens -> expiry and who holds them.
    ///
    /// A cache, not the source of truth: a token carries its own signed
    /// claims (see [`session`]), so a restart re-derives what this map
    /// forgot instead of signing everyone out.
    pub sessions: Mutex<HashMap<String, Session>>,
    /// Mints and verifies those claims.
    pub session_signer: session::SessionSigner,
    /// Config's source of truth is a file: admin writes are disabled.
    pub file_managed: bool,
    /// Where this node keeps local state; uploaded credential files are
    /// written beneath it.
    pub data_dir: Option<PathBuf>,
    /// How recently a node must have heartbeated to count as live. Read
    /// by the fleet endpoint and the heartbeat task.
    pub liveness_window: Duration,
    /// The config text this node last successfully applied, so the
    /// refresher can tell "someone edited the config" from "someone
    /// rotated a key".
    applied_text: ArcSwap<Option<String>>,
    pub upstream: upstream::UpstreamClient,
    /// In-flight subscription-credential renewals, so concurrent requests
    /// against one seat share a single OAuth round trip.
    pub refreshes: refresh::RefreshRegistry,
    /// Device-code logins an operator has started from the console.
    pub logins: device_login::DeviceLoginRegistry,
    /// What the canary has learned about each Codex seat.
    pub canary: canary::CanaryRegistry,
    draining: AtomicBool,
    prometheus: PrometheusHandle,
}

impl AppState {
    /// Ephemeral state: no store, no usage persistence. Tests and
    /// pure-env deployments.
    pub fn new(config: Config) -> Arc<Self> {
        Self::build(config, None, None, true)
    }

    /// Ephemeral config with usage persisted to disk. For tests that
    /// exercise the history and body paths without a control-plane
    /// store.
    #[doc(hidden)]
    pub fn with_data_dir(config: Config, data_dir: PathBuf) -> Arc<Self> {
        Self::build(config, None, Some(data_dir), true)
    }

    /// Managed mode: the store is the source of truth and admin writes
    /// are enabled.
    pub fn managed(config: Config, store: Arc<Store>, data_dir: PathBuf) -> Arc<Self> {
        Self::build(config, Some(store), Some(data_dir), false)
    }

    /// File mode with a data dir: config stays file-owned (admin
    /// read-only) but usage history and store-held virtual keys persist.
    pub fn file_with_data_dir(config: Config, store: Arc<Store>, data_dir: PathBuf) -> Arc<Self> {
        Self::build(config, Some(store), Some(data_dir), true)
    }

    fn build(
        config: Config,
        store: Option<Arc<Store>>,
        data_dir: Option<PathBuf>,
        file_managed: bool,
    ) -> Arc<Self> {
        let table = RoutingTable::from_config(&config);
        let defs = Self::collect_vkey_defs(&config, store.as_deref());
        // Boot builds the table here rather than through apply_config, so the
        // warning has to be raised in both places or it only ever fires on a
        // reload — which is the one moment nobody is watching for it.
        warn_on_orphaned_callers(&table, &defs, &config);
        let vkeys = VkTable::build(&defs, None);
        let pricing = usage::Pricing::from_config(&config);
        let node_id = store
            .as_deref()
            .map(|s| s.node_id().to_owned())
            .unwrap_or_else(|| "node".into());
        let usage = usage::UsagePipeline::start(data_dir.clone(), &config.usage, &node_id);
        if let Some(dir) = data_dir.as_deref() {
            usage::UsagePipeline::seed_budgets(dir, &vkeys);
        }
        let session_signer = session::SessionSigner::resolve(data_dir.as_deref());
        if !session_signer.is_durable() {
            tracing::info!(
                "console sessions are per-process: no data directory to keep a signing key in, \
                 so a restart signs operators out"
            );
        }
        let retained_data_dir = data_dir.clone();
        let (events, _) = tokio::sync::broadcast::channel(256);
        Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            table: ArcSwap::from_pointee(table),
            vkeys: ArcSwap::from_pointee(vkeys),
            pricing: ArcSwap::from_pointee(pricing),
            usage,
            store,
            events,
            sessions: Mutex::new(HashMap::new()),
            session_signer,
            data_dir: retained_data_dir,
            file_managed,
            liveness_window: DEFAULT_LIVENESS_WINDOW,
            applied_text: ArcSwap::from_pointee(None),
            upstream: upstream::UpstreamClient::new(),
            refreshes: refresh::RefreshRegistry::default(),
            logins: device_login::DeviceLoginRegistry::default(),
            canary: canary::CanaryRegistry::default(),
            draining: AtomicBool::new(false),
            prometheus: prometheus_handle().clone(),
        })
    }

    /// File-declared keys plus store-held keys (store wins on id clash —
    /// rotation state lives there).
    fn collect_vkey_defs(config: &Config, store: Option<&Store>) -> Vec<VirtualKeyDef> {
        let mut by_id: std::collections::BTreeMap<String, VirtualKeyDef> = config
            .virtual_keys
            .iter()
            .map(|d| (d.id.clone(), d.clone()))
            .collect();
        if let Some(store) = store {
            for def in store.read().0.virtual_key_defs() {
                by_id.insert(def.id.clone(), def);
            }
        }
        by_id.into_values().collect()
    }

    /// Apply a validated config: rebuild the routing snapshot, key table,
    /// and pricing, and swap them atomically. In-flight requests keep the
    /// snapshots they resolved against.
    pub fn apply_config(&self, config: Config) {
        let table = RoutingTable::from_config_with(&config, Some(&self.table.load()));
        let defs = self.collect_defs(&config);
        let prev = self.vkeys.load();
        self.vkeys.store(Arc::new(VkTable::build_with_shares(
            &defs,
            Some(&prev),
            self.live_nodes(),
        )));
        self.pricing
            .store(Arc::new(usage::Pricing::from_config(&config)));
        warn_on_orphaned_callers(&table, &defs, &config);
        self.table.store(Arc::new(table));
        self.config.store(Arc::new(config));
        let _ = self.events.send(json!({ "type": "config_applied" }));
    }

    /// Rebuild the key table after a store-side key change (create,
    /// rotate, revoke) without touching routing.
    pub fn refresh_vkeys(&self) {
        let config = self.config.load();
        let defs = self.collect_defs(&config);
        let prev = self.vkeys.load();
        self.vkeys.store(Arc::new(VkTable::build_with_shares(
            &defs,
            Some(&prev),
            self.live_nodes(),
        )));
    }

    /// Key definitions from the config plus whichever control plane is
    /// authoritative — the replicated state when clustered, the local
    /// store otherwise.
    fn collect_defs(&self, config: &Config) -> Vec<VirtualKeyDef> {
        let mut by_id: std::collections::BTreeMap<String, VirtualKeyDef> = config
            .virtual_keys
            .iter()
            .map(|d| (d.id.clone(), d.clone()))
            .collect();
        if let Some((state, _)) = self.store_read() {
            for def in state.virtual_key_defs() {
                by_id.insert(def.id.clone(), def);
            }
        }
        by_id.into_values().collect()
    }

    /// Adopt whatever the control-plane document currently says: reparse
    /// the config if it changed, otherwise just rebuild the key table.
    ///
    /// A config that no longer parses is *kept out* rather than applied.
    /// The likely cause is a `store.*` secret or an env var this node
    /// cannot resolve but the writing node could, and swapping in a
    /// half-built routing table would take a healthy node down for a
    /// problem it did not cause.
    pub fn adopt_store_state(&self) {
        let Some((snapshot, version)) = self.store_read() else {
            return;
        };
        let Some(text) = snapshot.config_text.clone() else {
            self.refresh_vkeys();
            return;
        };
        if self.applied_text.load().as_deref() == Some(&text) {
            self.refresh_vkeys();
            return;
        }
        let env = |name: &str| {
            if let Some(secret) = name.strip_prefix("store.") {
                self.store.as_deref().and_then(|s| s.resolve_secret(secret))
            } else {
                std::env::var(name).ok()
            }
        };
        match Config::from_str_with_env(&text, router_core::config::Format::Toml, &env) {
            Ok(config) => {
                tracing::info!(version, "adopted control-plane config");
                self.applied_text.store(Arc::new(Some(text)));
                self.apply_config(config);
            }
            Err(err) => {
                tracing::error!(
                    version,
                    %err,
                    "the control-plane config does not parse on this node; \
                     keeping the last good one and continuing to serve",
                );
                let _ = self.events.send(json!({
                    "type": "config_rejected",
                    "version": version,
                    "error": err.to_string(),
                }));
            }
        }
    }

    /// Poll the control-plane store for changes another node made.
    ///
    /// This is what replaces replication: there is no leader pushing to
    /// followers, just every node reading the same document on a timer.
    /// The cost is that a config change takes up to one interval to reach
    /// the fleet, which for a document a human edits is not a cost worth
    /// engineering away.
    /// Keep model prices current without anyone maintaining a table.
    ///
    /// Fetched once at startup and then daily: prices move rarely, new
    /// models appear constantly, and a gateway that reports $0.00 for a
    /// model released last week is worse than useless — it is quietly
    /// wrong in the direction of "everything is free". A failed fetch is
    /// logged and left alone; the built-in table and any `[pricing]`
    /// entries keep working, so this can only improve on what is there.
    /// Ship usage history to the store, and keep a fleet-wide rollup
    /// view warm.
    ///
    /// Every minute rather than on every flush: uploads are per file and
    /// a busy gateway writes one file per flush interval, so batching the
    /// scan keeps object counts and request costs sane while still
    /// putting history out of reach of a lost instance within a minute.
    pub fn spawn_usage_shipper(self: &Arc<Self>) {
        let Some(store) = self.store.clone() else {
            return;
        };
        if !store.holds_blobs() {
            return;
        }
        let Some(dir) = self.data_dir.clone() else {
            return;
        };
        let state = self.clone();
        let node = store.node_id().to_owned();
        tokio::spawn(async move {
            loop {
                let (shipped, failed) = usage::ship_partitions(&store, &dir, &node).await;
                if shipped > 0 || failed > 0 {
                    tracing::debug!(shipped, failed, "usage partitions shipped");
                }
                // Everything the local disk does not already hold,
                // refreshed on the same beat so the console's fleet
                // totals are at most a minute stale. Shipping first
                // matters: this node's newest files are on disk and in
                // the store by the time the read runs, and the read
                // skips the ones it can see locally.
                let rows = usage::fleet_rollups(&store, 90, &dir).await;
                state.usage.set_fleet_rollups(rows);
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    pub fn spawn_price_refresher(self: &Arc<Self>) {
        let url = std::env::var("RAPID_PRICE_CATALOG_URL")
            .unwrap_or_else(|_| usage::DEFAULT_PRICE_CATALOG_URL.to_owned());
        if url.eq_ignore_ascii_case("off") {
            return;
        }
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                match usage::fetch_catalog(&state.upstream, &url).await {
                    Ok(catalog) => {
                        let count = catalog.len();
                        let updated = state.pricing.load().with_catalog(Arc::new(catalog));
                        state.pricing.store(Arc::new(updated));
                        tracing::info!(models = count, "model price catalog loaded");
                    }
                    Err(err) => tracing::warn!(%err, "could not refresh model prices"),
                }
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });
    }

    /// Ask every Codex seat a real question each `interval`. See
    /// [`canary`].
    pub fn spawn_canary(self: &Arc<Self>, interval: Duration) {
        canary::spawn(self.clone(), interval);
    }

    /// Keep every subscription seat's credential fresh, off the request
    /// path.
    ///
    /// Renewal used to happen only when a request was already in flight —
    /// proactively just before a token was used, or reactively on the 401
    /// it caused. A seat nobody happened to route to therefore sat expired
    /// until traffic found it, and the request that found it was the one
    /// that paid: a pool of eighty-nine seats accumulated eighteen expired
    /// credentials, and better than half of all requests were answering
    /// 401 to callers.
    ///
    /// This closes that gap. Renewal is *ahead* of expiry (the same skew
    /// the request path uses), so a seat is ready before anything needs
    /// it, and a token that cannot be renewed is a fact the console can
    /// show rather than one discovered by failing a caller.
    ///
    /// It also brings seats whose breaker has opened back into rotation,
    /// which nothing else does. Selection prefers the healthy pool and
    /// only falls through to offering a half-open probe slot when that
    /// pool is empty — so in a fleet of any size, an open breaker is never
    /// asked again and the seat is retired for good. That is how a batch
    /// of seats stayed out at 0% after their credentials had been
    /// re-authenticated: the credential was fixed, but nothing was ever
    /// going to send the request that noticed.
    ///
    /// Probing here rather than on the request path is the point. It costs
    /// the caller nothing, and the breaker's own cooldown still bounds it
    /// to one probe per seat per cooldown, so a permanently dead seat
    /// costs one `max_tokens: 1` request a tick and no caller latency.
    /// Only seats that are actually out are probed — a healthy seat is
    /// never asked, and a seat benched on a quota window is left alone
    /// until the window rolls, because that is the resource a subscription
    /// plan is conserving.
    pub fn spawn_seat_maintenance(self: &Arc<Self>, interval: Duration) {
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let table = state.table.load();
                // Collected first so the routing snapshot is not held
                // across an await; a reload may swap it underneath us.
                // The provider handle comes along because recovery needs
                // to build a probe against it, not just the seat.
                let seats: Vec<(Arc<ProviderRuntime>, usize)> = table
                    .providers()
                    .filter(|p| p.kind.is_subscription())
                    .flat_map(|p| (0..p.keys.len()).map(|index| (p.clone(), index)))
                    .collect();
                drop(table);

                let mut renewed = 0usize;
                let mut failed = 0usize;
                let mut recovered = 0usize;
                for (provider, index) in seats {
                    let key = &provider.keys[index];

                    if let (Some(seat), Some(path)) = (key.seat(), key.source_path.as_deref()) {
                        let now = vkey::unix_now_ms();
                        let state_now = seat.current();
                        if state_now.wants_refresh(now, refresh::REFRESH_SKEW_MS)
                            || state_now.is_expired(now)
                        {
                            if refresh::refresh_now(
                                &state.upstream,
                                &state.refreshes,
                                provider.kind,
                                seat,
                                &refresh::Persist::File(path.to_owned()),
                                now,
                            )
                            .await
                            {
                                renewed += 1;
                                metrics::counter!(
                                    "rapid_seat_refresh_total",
                                    "provider" => provider.name.clone(),
                                )
                                .increment(1);
                            } else {
                                failed += 1;
                            }
                        }
                    }

                    if Self::recover_seat(&state, &provider, index).await {
                        recovered += 1;
                        metrics::counter!(
                            "rapid_seat_recovered_total",
                            "provider" => provider.name.clone(),
                        )
                        .increment(1);
                    }
                }
                if renewed > 0 || failed > 0 || recovered > 0 {
                    tracing::info!(renewed, failed, recovered, "subscription seats maintained");
                    // Nudge any open console: a seat that just came back
                    // or was just renewed is exactly what somebody staring
                    // at the providers page is waiting to see. Only when
                    // something actually changed — a tick that found
                    // nothing to do must not refresh every browser every
                    // minute.
                    let _ = state.events.send(json!({ "type": "seats_checked" }));
                }
            }
        });
    }

    /// Offer one out-of-service seat its half-open probe, off the request
    /// path. `true` when the seat came back.
    ///
    /// `admit` is the authority on whether a probe is owed, and taking the
    /// slot from here is what keeps this honest: the breaker still allows
    /// exactly one probe per cooldown, so a request that arrives mid-probe
    /// cannot double up, and a seat still inside its cooldown — or benched
    /// on a quota window the provider declared — is skipped without a
    /// request being sent. An `Admission::Yes` means the bench had already
    /// elapsed and `admit` cleared it, so the seat is back with nothing
    /// spent.
    async fn recover_seat(
        state: &Arc<Self>,
        provider: &Arc<ProviderRuntime>,
        index: usize,
    ) -> bool {
        let key = &provider.keys[index];
        if key.breaker.looks_healthy(clock::now_ms()) {
            return false;
        }
        if !matches!(key.breaker.admit(clock::now_ms()), Admission::Probe) {
            return false;
        }
        let Some(model) = admin::probe_model(provider, &key.name) else {
            // Nothing to ask for. Hand the probe slot back rather than
            // leaving the breaker half-open until the cooldown reclaims
            // it, which would hold a live seat out for no reason.
            key.breaker.record_failure(clock::now_ms());
            return false;
        };
        // `probe_key` settles the breaker with the outcome, so a seat that
        // answers closes itself and rejoins the pool on the next request.
        let outcome = proxy::probe_key(state, provider.clone(), &key.name, &model).await;
        let back = key.breaker.looks_healthy(clock::now_ms());
        if !back {
            tracing::debug!(
                provider = %provider.name,
                seat = %key.name,
                status = %outcome.status,
                detail = %outcome.detail,
                "seat is still out"
            );
        }
        back
    }

    pub fn spawn_refresher(self: &Arc<Self>, interval: Duration) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match store.refresh().await {
                    Ok(Some(version)) => {
                        tracing::debug!(version, "control-plane document changed");
                        state.adopt_store_state();
                    }
                    Ok(None) => {}
                    Err(err) => {
                        // Traffic is unaffected: the cached document is
                        // still serving. Say so once per failure rather
                        // than pretending the node is broken.
                        tracing::warn!(%err, "could not refresh the control-plane document");
                    }
                }
            }
        });
    }

    /// Announce this node and keep the rate-limit divisor tracking the
    /// fleet. A node that stops heartbeating ages out of everyone else's
    /// count within the liveness window, which is the whole of membership
    /// management in a stateless deployment.
    pub fn spawn_heartbeat(self: &Arc<Self>, interval: Duration, window: Duration) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let state = self.clone();
        tokio::spawn(async move {
            let mut last = store.live_nodes();
            loop {
                match store.beat(window).await {
                    Ok(live) if live != last => {
                        last = live;
                        state.refresh_vkeys();
                        tracing::info!(live_nodes = live, "rate-limit shares rescaled");
                        let _ = state
                            .events
                            .send(json!({ "type": "fleet_changed", "live": live }));
                    }
                    Ok(_) => {}
                    Err(err) => tracing::warn!(%err, "heartbeat failed"),
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// How many gateway nodes are alive. Rate limits divide by this, so a
    /// key's `rpm` tracks the fleet without anyone editing configs.
    pub fn live_nodes(&self) -> usize {
        self.store
            .as_deref()
            .map(|s| s.live_nodes())
            .unwrap_or(1)
            .max(1)
    }

    /// Commit a control-plane change through the external store.
    pub async fn commit(
        &self,
        expect: Option<u64>,
        command: router_store::Command,
    ) -> Result<u64, ControlPlaneError> {
        let store = self.store.as_deref().ok_or_else(|| {
            ControlPlaneError::Fault("this node has no control-plane store".into())
        })?;
        store.commit(expect, command).await
    }

    /// The current control-plane document and the version it reflects.
    /// Served from the node's cache — no I/O, no waiting on the backend.
    pub fn store_read(&self) -> Option<(router_store::StoreState, u64)> {
        self.store.as_deref().map(|s| s.read())
    }

    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}

/// The Prometheus recorder is process-global; installing twice (tests,
/// reload paths) must be a no-op rather than a panic.
fn prometheus_handle() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("no other metrics recorder may be installed");
        metrics::gauge!("rapid_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
        handle
    })
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let max_body = state.config.load().server.max_body_size as usize;

    let v1 = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        // The Codex CLI in ChatGPT-subscription mode posts here, not to
        // `/v1/responses` — same Responses body, the path its backend uses.
        // Point its `chatgpt_base_url` at the gateway and it arrives on this
        // route with a virtual key, so a subscription CLI can be routed
        // without leaving subscription mode.
        .route("/backend-api/codex/responses", post(responses))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/audio/speech", post(audio_speech))
        .route("/v1/audio/transcriptions", post(audio_transcriptions))
        .route("/v1/audio/translations", post(audio_translations))
        .route("/v1/images/generations", post(images_generations))
        .route("/v1/files", post(files_upload).get(files_list))
        .route("/v1/files/{id}", get(files_retrieve))
        .route("/v1/files/{id}/content", get(files_content))
        .route("/v1/models", get(proxy::models))
        .route("/anthropic/v1/messages", post(anthropic_messages))
        .route("/genai/v1beta/models/{model_action}", post(genai_generate))
        .route("/genai/v1/models/{model_action}", post(genai_generate))
        .route(
            "/passthrough/{provider}/{*rest}",
            axum::routing::any(passthrough),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_auth,
        ))
        .layer(DefaultBodyLimit::max(max_body));

    // Compressed, but only here. The console's bundle and the analytics
    // JSON are both large and both highly compressible — a year of daily
    // rows is mostly repeated field names — and they are read over
    // whatever network the operator happens to be on.
    //
    // Deliberately *not* on `/v1`: the proxy path's whole claim is
    // microseconds of added latency, and re-compressing a provider's
    // response would spend milliseconds to save bytes on a stream the
    // caller is already reading incrementally.
    let admin = Router::new()
        .nest("/admin/api", admin::router(state.clone()))
        .layer(compression());

    let app = Router::new()
        .merge(v1)
        .merge(admin)
        .route("/health", get(health))
        .route("/metrics", get(metrics_endpoint))
        .layer(axum::middleware::from_fn(request_id));
    #[cfg(feature = "console")]
    let app = app.merge(
        Router::new()
            .route("/favicon.svg", get(console::favicon))
            .route("/favicon.ico", get(console::favicon))
            .route("/console", get(console::root))
            .route("/console/", get(console::root))
            .route("/console/{*path}", get(console::asset))
            .layer(compression()),
    );
    app.with_state(state)
}

/// Brotli or gzip, whichever the client asked for.
///
/// Server-sent events are excluded: compressing a stream that is read
/// event by event buffers it, and a live tail that arrives in bursts is
/// worse than one that arrives uncompressed.
fn compression()
-> tower_http::compression::CompressionLayer<impl tower_http::compression::Predicate> {
    use tower_http::compression::Predicate as _;
    tower_http::compression::CompressionLayer::new()
        .br(true)
        .gzip(true)
        .compress_when(
            tower_http::compression::predicate::DefaultPredicate::new().and(
                tower_http::compression::predicate::NotForContentType::new("text/event-stream"),
            ),
        )
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    match proxy::InboundChat::from_openai(body) {
        Ok(inbound) => proxy::handle_chat(state, inbound, headers, vk.key, vk.tenant).await,
        Err(err) => proxy::error_response(&err),
    }
}

async fn anthropic_messages(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    match proxy::InboundChat::from_anthropic(&body) {
        Ok(inbound) => proxy::handle_chat(state, inbound, headers, vk.key, vk.tenant).await,
        Err(err) => proxy::error_response_in(router_providers::Dialect::Anthropic, &err),
    }
}

/// Gemini routes carry `{model}:{action}` as one path segment.
async fn genai_generate(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(model_action): axum::extract::Path<String>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let dialect = router_providers::Dialect::Gemini;
    let Some((model, action)) = model_action.split_once(':') else {
        return proxy::error_response_in(
            dialect,
            &GatewayError::new(ErrorClass::NotFound, "expected `models/{model}:{action}`"),
        );
    };
    let stream = match action {
        "generateContent" => false,
        "streamGenerateContent" => true,
        other => {
            return proxy::error_response_in(
                dialect,
                &GatewayError::new(
                    ErrorClass::NotFound,
                    format!("unsupported action `{other}`"),
                ),
            );
        }
    };
    match proxy::InboundChat::from_gemini(&body, model.to_owned(), stream) {
        Ok(inbound) => proxy::handle_chat(state, inbound, headers, vk.key, vk.tenant).await,
        Err(err) => proxy::error_response_in(dialect, &err),
    }
}

async fn responses(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy::handle_responses(state, headers, body, vk.key, vk.tenant).await
}

/// Say out loud when dividing a pool has left callers with nothing.
///
/// Refusing a key that names no service on a divided provider is the right
/// behaviour — degrading to the unlabelled accounts would quietly recreate
/// the free-for-all the labels exist to end. But the first symptom of it is
/// a 403 in production, and possibly long after the label that caused it.
/// The person who applied that label is the one who can still fix it
/// cheaply, so say it on every load and reload, while somebody is watching.
fn warn_on_orphaned_callers(
    table: &router_core::router::RoutingTable,
    defs: &[router_core::vkey::VirtualKeyDef],
    config: &router_core::config::Config,
) {
    let divided: Vec<&str> = table
        .providers()
        .filter(|p| p.managed)
        .map(|p| p.name.as_str())
        .collect();
    if divided.is_empty() {
        return;
    }
    let orphaned: Vec<&str> = defs
        .iter()
        .filter(|d| d.enabled && d.tenant.is_none())
        .map(|d| d.name.as_str())
        .collect();
    if !orphaned.is_empty() {
        tracing::warn!(
            providers = ?divided,
            keys = ?orphaned,
            "these virtual keys name no service, so they can spend nothing on \
             the providers listed — give each one a `tenant`"
        );
    }
    // A static key can name a service now, so only the ones that do not are
    // a problem — and they are the sharpest kind, because the callers
    // presenting them often cannot be reconfigured at all. Give the key's
    // position rather than the key.
    let unnamed: Vec<usize> = config
        .server
        .auth_keys
        .iter()
        .enumerate()
        .filter(|(_, key)| key.tenant.is_none())
        .map(|(i, _)| i)
        .collect();
    if !unnamed.is_empty() {
        tracing::warn!(
            providers = ?divided,
            auth_keys = ?unnamed,
            "traffic on these static gateway keys names no service and can \
             spend nothing on the providers listed; give each one a `tenant`"
        );
    }
}

async fn passthrough(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((provider, rest)): axum::extract::Path<(String, String)>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let query = uri.query().map(str::to_owned);
    proxy::handle_passthrough(
        state, provider, rest, method, query, headers, body, vk.key, vk.tenant,
    )
    .await
}

async fn completions(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy::handle_relay(
        state,
        Endpoint::Completions,
        headers,
        body,
        vk.key,
        vk.tenant,
    )
    .await
}

async fn embeddings(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy::handle_relay(
        state,
        Endpoint::Embeddings,
        headers,
        body,
        vk.key,
        vk.tenant,
    )
    .await
}

async fn audio_speech(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy::handle_relay(
        state,
        Endpoint::AudioSpeech,
        headers,
        body,
        vk.key,
        vk.tenant,
    )
    .await
}

async fn images_generations(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy::handle_relay(
        state,
        Endpoint::ImagesGenerations,
        headers,
        body,
        vk.key,
        vk.tenant,
    )
    .await
}

async fn audio_transcriptions(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    proxy::handle_stream_relay(
        state,
        "/audio/transcriptions",
        "audio_transcriptions",
        headers,
        body,
        vk.key,
        vk.tenant,
        true,
    )
    .await
}

async fn audio_translations(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    proxy::handle_stream_relay(
        state,
        "/audio/translations",
        "audio_translations",
        headers,
        body,
        vk.key,
        vk.tenant,
        true,
    )
    .await
}

async fn files_upload(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    proxy::handle_stream_relay(
        state,
        "/files",
        "files_upload",
        headers,
        body,
        vk.key,
        vk.tenant,
        false,
    )
    .await
}

async fn files_list(
    State(state): State<Arc<AppState>>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    proxy::handle_provider_relay(state, "/files", "files_list", headers, vk.key, vk.tenant).await
}

async fn files_retrieve(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    proxy::handle_provider_relay(
        state,
        &format!("/files/{id}"),
        "files_retrieve",
        headers,
        vk.key,
        vk.tenant,
    )
    .await
}

async fn files_content(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Extension(vk): axum::Extension<VkCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    proxy::handle_provider_relay(
        state,
        &format!("/files/{id}/content"),
        "files_content",
        headers,
        vk.key,
        vk.tenant,
    )
    .await
}

/// Honor an inbound `x-request-id` or mint a UUIDv7, and echo it on the
/// response.
async fn request_id(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

    // Stamp it back onto the request so the dispatch path records the same
    // id the client is handed — a log line the caller quotes has to find
    // the request they actually made.
    if let Ok(v) = HeaderValue::from_str(&id) {
        request.headers_mut().insert("x-request-id", v);
    }

    let mut response = next.run(request).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-request-id", v);
    }
    response
}

/// Gateway authentication: virtual keys (`ck-…`) verify against the key
/// table (constant-time); anything else checks the static `auth_keys`.
/// Anonymous access exists only when no static keys are configured and
/// `require_auth` is off.
async fn gateway_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let config = state.config.load();

    // Every dialect's native credential carrier is accepted: OpenAI SDKs
    // send `Authorization: Bearer`, Anthropic SDKs `x-api-key`, Google
    // SDKs `x-goog-api-key` (or `?key=`).
    let headers = request.headers();
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()))
        .or_else(|| {
            request
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("key=")))
        })
        .map(str::to_owned);

    let gate_active = !config.server.auth_keys.is_empty() || config.server.require_auth;
    let mut ctx = VkCtx::default();
    let static_key = presented.as_deref().and_then(|token| {
        config
            .server
            .auth_keys
            .iter()
            .find(|key| key.secret.verify(token))
    });
    let static_match = static_key.is_some();

    match presented.as_deref() {
        // Traffic on a static key belongs to whichever service that key
        // names, if any. The caller sends nothing extra and knows nothing
        // about this.
        Some(_) if static_match => {
            ctx.tenant = static_key.and_then(|key| key.tenant.clone());
        }
        // A `ck-` token always means virtual-key semantics — enforced
        // when it is not also an explicitly configured static key.
        Some(token) if token.starts_with("ck-") => {
            match state.vkeys.load().verify(token, vkey::unix_now_ms()) {
                Ok(rt) => {
                    ctx.tenant = rt.def.tenant.clone();
                    ctx.key = Some(rt);
                }
                Err(reason) => {
                    metrics::counter!("rapid_vkey_rejects_total", "reason" => format!("{reason:?}"))
                        .increment(1);
                    return proxy::error_response(&GatewayError::new(
                        ErrorClass::Authentication,
                        "invalid virtual key",
                    ));
                }
            }
        }
        Some(_) => {
            if gate_active {
                return proxy::error_response(&GatewayError::new(
                    ErrorClass::Authentication,
                    "missing or invalid gateway API key",
                ));
            }
        }
        None => {
            if gate_active {
                return proxy::error_response(&GatewayError::new(
                    ErrorClass::Authentication,
                    "missing or invalid gateway API key",
                ));
            }
        }
    }

    request.extensions_mut().insert(ctx);
    next.run(request).await
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.is_draining() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "draining" })),
        )
    } else {
        (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            })),
        )
    }
}

async fn metrics_endpoint(State(state): State<Arc<AppState>>) -> String {
    state.prometheus.render()
}

/// Serve until `shutdown` resolves, then drain: stop accepting, flip
/// `/health` to draining, and give in-flight requests up to
/// `drain_timeout` to finish before returning.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let drain_timeout = state.config.load().server.drain_timeout;
    let drain_state = state;

    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel::<()>();
    let graceful = async move {
        shutdown.await;
        drain_state.set_draining();
        tracing::info!("shutdown requested; draining in-flight requests");
        let _ = drained_tx.send(());
    };

    let server = axum::serve(listener, app).with_graceful_shutdown(graceful);
    tokio::select! {
        result = server => result,
        _ = enforce_drain_deadline(drained_rx, drain_timeout) => {
            tracing::warn!(?drain_timeout, "drain deadline exceeded; exiting with requests in flight");
            Ok(())
        }
    }
}

async fn enforce_drain_deadline(drained: tokio::sync::oneshot::Receiver<()>, timeout: Duration) {
    // The deadline starts when draining starts, not when the server starts.
    let _ = drained.await;
    tokio::time::sleep(timeout).await;
}
