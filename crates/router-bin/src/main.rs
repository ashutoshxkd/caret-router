use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use router_core::config::{Config, Format};
use router_server::AppState;
use router_store::{BackendSpec, Command as StoreCommand, Store};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum Mode {
    Managed,
    File,
}

#[derive(Parser)]
#[command(name = "rapid-router", version, about = "A fast LLM gateway")]
struct Cli {
    /// TOML or JSON config. In managed mode it seeds an empty store.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Directory for the embedded store and usage history.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Where control-plane state lives: file, s3, or dynamodb. Every
    /// node pointed at the same one is a node of the same fleet.
    #[arg(long, global = true, env = "RAPID_STORE_BACKEND")]
    store_backend: Option<String>,

    /// S3 bucket holding the control-plane document.
    #[arg(long, global = true, env = "RAPID_STORE_BUCKET")]
    store_bucket: Option<String>,

    /// Key prefix within the bucket. Defaults to the bucket root.
    #[arg(long, global = true, env = "RAPID_STORE_PREFIX")]
    store_prefix: Option<String>,

    /// DynamoDB table holding the control-plane document.
    #[arg(long, global = true, env = "RAPID_STORE_TABLE")]
    store_table: Option<String>,

    /// AWS region for the store. Defaults to the ambient AWS config.
    #[arg(long, global = true, env = "RAPID_STORE_REGION")]
    store_region: Option<String>,

    /// Override the AWS endpoint, for local testing or a private gateway.
    #[arg(long, global = true, env = "RAPID_STORE_ENDPOINT")]
    store_endpoint: Option<String>,

    /// Path to the control-plane document for the `file` backend.
    /// Defaults to `store.json` in the data dir; point several nodes at
    /// one path on a shared volume to run a fleet without AWS.
    #[arg(long, global = true, env = "RAPID_STORE_PATH")]
    store_path: Option<PathBuf>,

    /// Override the port from the config. The control-plane document is
    /// shared, so this is how two nodes run on one host.
    #[arg(long, global = true, env = "RAPID_PORT")]
    port: Option<u16>,

    /// Address this node advertises to the console's fleet list.
    #[arg(long, global = true, env = "RAPID_ADVERTISE_ADDR")]
    advertise: Option<String>,

    /// Managed mode permits console writes; file mode is read-only.
    #[arg(long, global = true, value_enum, default_value = "managed")]
    mode: Mode,

    /// Reload automatically when the file-mode config changes.
    #[arg(long)]
    watch: bool,

    /// Human-friendly log output instead of JSON lines.
    #[arg(long)]
    dev: bool,

    /// Ask every Codex seat a detailed question this often, in seconds,
    /// to watch availability and answer times (`GET /admin/api/canary`). Off
    /// when absent or 0. Each node runs its own, so in a fleet set it on
    /// one node only.
    #[arg(long, global = true, env = "RAPID_CANARY_INTERVAL_SECS")]
    canary_interval_secs: Option<u64>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a config file and exit.
    Check { path: PathBuf },
    /// Import or export the managed configuration document.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage encrypted store.* values while the gateway is stopped.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Create and manage virtual keys.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Show which nodes are currently serving against this store.
    Fleet,

    /// Generate the cluster-wide key that seals stored secrets.
    MasterKey,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Issue a key. The full `ck-…` value is printed exactly once.
    Create {
        #[arg(long)]
        name: String,
        /// Comma-separated models and/or aliases; omit for all models.
        #[arg(long, value_delimiter = ',')]
        models: Vec<String>,
        /// Which service this key belongs to; must be one of `tenants`.
        #[arg(long)]
        tenant: Option<String>,
        /// Spend cap as `AMOUNT/PERIOD`, e.g. `250/monthly`.
        #[arg(long, value_name = "USD/PERIOD")]
        budget_usd: Option<String>,
        #[arg(long)]
        rpm: Option<u64>,
        #[arg(long)]
        tpm: Option<u64>,
        /// RFC 3339 UTC, e.g. `2027-01-01T00:00:00Z`.
        #[arg(long)]
        expires: Option<String>,
    },
    /// List keys (ids and attributes; never secrets).
    Ls,
    /// Issue a new secret for an existing key, honoring an overlap window.
    Rotate {
        id: String,
        /// Hours the previous secret keeps working.
        #[arg(long, default_value_t = 24)]
        grace_hours: u64,
    },
    /// Disable a key without deleting its attributes or history.
    Disable { id: String },
    /// Re-enable a disabled key.
    Enable { id: String },
    /// Delete a key outright.
    Rm { id: String },
    /// Hash a secret for a `secret_hash` entry in a file-mode config.
    Hash {
        /// The secret to hash; omit to read it from stdin.
        secret: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the managed TOML document.
    Export,
    /// Validate and replace the managed document from a file.
    Import { path: PathBuf },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Read a secret from stdin, or from the named environment variable.
    Set {
        name: String,
        #[arg(long)]
        from_env: Option<String>,
    },
    /// Delete one stored secret.
    Delete { name: String },
    /// List secret names. Values are never printed.
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.dev);
    match &cli.command {
        Some(Command::Check { path }) => check(path),
        Some(Command::Config { command }) => config_command(&cli, command),
        Some(Command::Secret { command }) => secret_command(&cli, command),
        Some(Command::Key { command }) => key_command(&cli, command),
        Some(Command::Fleet) => fleet_command(&cli),
        Some(Command::MasterKey) => master_key_command(),
        None => run(cli),
    }
}

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir
        .clone()
        .or_else(|| std::env::var_os("RAPID_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".rapidrouter")
        })
}

fn check(path: &Path) -> ExitCode {
    match Config::load(path) {
        Ok(config) => {
            println!(
                "OK: {} provider(s), {} routing group(s), {} alias(es), {} fallback chain(s)",
                config.providers.len(),
                config.groups.len(),
                config.aliases.len(),
                config.fallbacks.len(),
            );
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
}

/// The one-off commands are synchronous from the operator's point of
/// view but the store is not, so they each get a small runtime.
///
/// Only for the subcommands. Calling this from inside the server's
/// runtime panics — use `.await` there.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime")
        .block_on(future)
}

/// The store's write path is async and the one-off commands are not.
fn commit(
    store: &Store,
    expect: Option<u64>,
    command: StoreCommand,
) -> Result<u64, router_store::ControlPlaneError> {
    block_on(store.commit(expect, command))
}

/// The `[store]` section of `--config`, if one was given. CLI flags and
/// environment variables layer on top of it in [`backend_spec`].
fn config_store_section(cli: &Cli) -> Result<Option<router_core::config::StoreConfig>, ExitCode> {
    let Some(path) = cli.config.as_deref() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        // A missing config is diagnosed later, with a better message.
        Err(_) => return Ok(None),
    };
    match router_core::config::store_section(&text, format_for(path)) {
        Ok(section) => Ok(Some(section)),
        Err(err) => Err(fail(err)),
    }
}

fn open_store(cli: &Cli) -> Result<Store, ExitCode> {
    let section = config_store_section(cli)?;
    let spec = backend_spec(cli, section.as_ref()).map_err(fail)?;
    let dir = data_dir(cli);
    let addr = advertise_addr(cli, None);
    block_on(Store::open(&spec, &dir, &addr)).map_err(fail)
}

/// Reads and writes now go through the same handle: with an external
/// store there is no exclusive lock to contend for, so an operator can
/// inspect or edit a running fleet's configuration from anywhere.
fn open_store_for_reading(cli: &Cli) -> Result<Store, ExitCode> {
    open_store(cli)
}

fn config_command(cli: &Cli, command: &ConfigCommand) -> ExitCode {
    let store = match if matches!(command, ConfigCommand::Export) {
        open_store_for_reading(cli)
    } else {
        open_store(cli)
    } {
        Ok(store) => store,
        Err(code) => return code,
    };
    match command {
        ConfigCommand::Export => {
            let (state, _) = store.read();
            match state.config_text {
                Some(text) => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
                None => fail("managed store has no configuration"),
            }
        }
        ConfigCommand::Import { path } => {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(err) => return fail(err),
            };
            if let Err(err) = validate_store_config(&store, &text, format_for(path)) {
                return fail(err);
            }
            match commit(&store, None, StoreCommand::PutConfig { text }) {
                Ok(version) => {
                    println!("Imported managed configuration at version {version}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
    }
}

fn secret_command(cli: &Cli, command: &SecretCommand) -> ExitCode {
    let store = match open_store(cli) {
        Ok(store) => store,
        Err(code) => return code,
    };
    match command {
        SecretCommand::Set { name, from_env } => {
            if !valid_secret_name(name) {
                return fail(
                    "secret name must contain only letters, digits, dot, dash, or underscore",
                );
            }
            let value = match from_env {
                Some(var) => match std::env::var(var) {
                    Ok(value) if !value.is_empty() => value,
                    Ok(_) => return fail(format!("environment variable {var} is empty")),
                    Err(_) => return fail(format!("environment variable {var} is not set")),
                },
                None => {
                    let mut value = String::new();
                    if let Err(err) = std::io::stdin().read_to_string(&mut value) {
                        return fail(err);
                    }
                    value.trim_end_matches(['\r', '\n']).to_owned()
                }
            };
            if value.is_empty() {
                return fail("secret value must not be empty");
            }
            let sealed = store.seal_secret(&value);
            match commit(
                &store,
                None,
                StoreCommand::PutSecret {
                    name: name.clone(),
                    sealed,
                },
            ) {
                Ok(version) => {
                    println!("Stored {name} at version {version}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        SecretCommand::Delete { name } => {
            match commit(
                &store,
                None,
                StoreCommand::DeleteSecret { name: name.clone() },
            ) {
                Ok(version) => {
                    println!("Deleted {name} at version {version}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        SecretCommand::List => {
            let (state, _) = store.read();
            for name in state.secrets.keys() {
                println!("{name}");
            }
            ExitCode::SUCCESS
        }
    }
}

fn key_command(cli: &Cli, command: &KeyCommand) -> ExitCode {
    use router_core::vkey::{self, PrevSecret, RateLimit, VirtualKeyDef};

    // Hashing needs no store — it is the file-mode authoring path.
    if let KeyCommand::Hash { secret } = command {
        let value = match secret {
            Some(value) => value.clone(),
            None => {
                let mut buf = String::new();
                if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
                    return fail(err);
                }
                buf.trim_end_matches(['\r', '\n']).to_owned()
            }
        };
        if value.is_empty() {
            return fail("secret must not be empty");
        }
        println!("{}", vkey::hash_secret(&value));
        return ExitCode::SUCCESS;
    }

    let store = match if matches!(command, KeyCommand::Ls) {
        open_store_for_reading(cli)
    } else {
        open_store(cli)
    } {
        Ok(store) => store,
        Err(code) => return code,
    };

    // Mutate one key in place, then commit the whole definition back.
    let edit = |id: &str, f: &dyn Fn(&mut VirtualKeyDef)| -> Result<(), String> {
        let (state, _) = store.read();
        let mut def = state
            .virtual_keys
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no key with id `{id}`"))?;
        f(&mut def);
        commit(&store, None, StoreCommand::PutVirtualKey { def })
            .map(|_| ())
            .map_err(|err| err.to_string())
    };

    match command {
        KeyCommand::Hash { .. } => unreachable!("handled above"),
        KeyCommand::Create {
            name,
            models,
            tenant,
            budget_usd,
            rpm,
            tpm,
            expires,
        } => {
            let budget = match budget_usd.as_deref().map(parse_budget).transpose() {
                Ok(budget) => budget,
                Err(err) => return fail(err),
            };
            let expires_ms = match expires.as_deref().map(|s| {
                vkey::parse_rfc3339_utc_ms(s)
                    .ok_or_else(|| format!("`{s}` is not RFC 3339 UTC (e.g. 2027-01-01T00:00:00Z)"))
            }) {
                Some(Ok(ms)) => Some(ms),
                Some(Err(err)) => return fail(err),
                None => None,
            };
            let rate = (rpm.is_some() || tpm.is_some()).then_some(RateLimit {
                rpm: *rpm,
                tpm: *tpm,
            });
            // A tenant nobody declared produces a key that looks fine and
            // owns nothing: on any pool where accounts are labelled, every
            // request it makes is refused. Config load and the console both
            // reject the typo; this command writes straight to the store, so
            // without this check it is the one way to create such a key — and
            // the rollout guide tells operators to create their keys here.
            if let Some(tenant) = tenant.as_deref() {
                let (state, _) = store.read();
                match state.config_text.as_deref() {
                    // Store-held configuration is always TOML; see load_initial_config.
                    Some(text) => match validate_store_config(&store, text, Format::Toml) {
                        Ok(config) => {
                            if !config.tenants.contains(tenant) {
                                let known: Vec<&str> =
                                    config.tenants.iter().map(String::as_str).collect();
                                return fail(format!(
                                    "`{tenant}` is not a declared service; \
                                     add it to `tenants` first (declared: {})",
                                    if known.is_empty() {
                                        "none".to_owned()
                                    } else {
                                        known.join(", ")
                                    }
                                ));
                            }
                        }
                        // The stored config does not parse. That is somebody
                        // else's problem and not worth blocking a key on, but
                        // it does mean the name went unchecked, so say so.
                        Err(err) => eprintln!(
                            "warning: could not read the service roster to check `{tenant}` ({err})"
                        ),
                    },
                    // File-mode: the roster lives in a config this command
                    // cannot see. Config load still rejects a bad name, but it
                    // does so at startup rather than here.
                    None => eprintln!(
                        "warning: no stored configuration, so `{tenant}` was not checked \
                         against the service roster"
                    ),
                }
            }

            let generated = vkey::generate();
            let def = VirtualKeyDef {
                id: generated.id.clone(),
                name: name.clone(),
                secret_hash: vkey::hash_secret(&generated.secret),
                prev_secret: None,
                models: models.clone(),
                tenant: tenant.clone(),
                budget,
                rate,
                expires_ms,
                tags: Default::default(),
                enabled: true,
                created_ms: vkey::unix_now_ms(),
            };
            match commit(&store, None, StoreCommand::PutVirtualKey { def }) {
                Ok(_) => {
                    println!("{}", generated.full());
                    eprintln!(
                        "Key `{name}` created with id {}. This secret is shown once — store it now.",
                        generated.id
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        KeyCommand::Ls => {
            let (state, _) = store.read();
            if state.virtual_keys.is_empty() {
                println!("No virtual keys. Create one with `rapid-router key create --name NAME`.");
                return ExitCode::SUCCESS;
            }
            println!(
                "{:<8} {:<24} {:<8} {:<14} {:<12} SCOPE",
                "ID", "NAME", "STATE", "BUDGET", "LIMITS"
            );
            for def in state.virtual_keys.values() {
                let budget = def
                    .budget
                    .map(|b| format!("${:.0}/{}", b.usd, period_name(b.period)))
                    .unwrap_or_else(|| "-".into());
                let limits = def
                    .rate
                    .map(|r| match (r.rpm, r.tpm) {
                        (Some(rpm), Some(tpm)) => format!("{rpm}rpm {tpm}tpm"),
                        (Some(rpm), None) => format!("{rpm}rpm"),
                        (None, Some(tpm)) => format!("{tpm}tpm"),
                        (None, None) => "-".into(),
                    })
                    .unwrap_or_else(|| "-".into());
                let mut scope = if def.models.is_empty() {
                    "all models".to_owned()
                } else {
                    def.models.join(",")
                };
                if let Some(tenant) = &def.tenant {
                    scope.push_str(&format!(" [tenant {tenant}]"));
                }
                let state_label = if !def.enabled {
                    "disabled"
                } else if def.expires_ms.is_some_and(|e| e <= vkey::unix_now_ms()) {
                    "expired"
                } else {
                    "active"
                };
                println!(
                    "{:<8} {:<24} {:<8} {:<14} {:<12} {}",
                    def.id, def.name, state_label, budget, limits, scope
                );
            }
            ExitCode::SUCCESS
        }
        KeyCommand::Rotate { id, grace_hours } => {
            let secret = vkey::generate_secret();
            let valid_until_ms = vkey::unix_now_ms() + grace_hours * 3_600_000;
            let new_hash = vkey::hash_secret(&secret);
            let result = edit(id, &|def: &mut VirtualKeyDef| {
                def.prev_secret = Some(PrevSecret {
                    secret_hash: def.secret_hash.clone(),
                    valid_until_ms,
                });
                def.secret_hash = new_hash.clone();
            });
            match result {
                Ok(()) => {
                    println!("ck-{id}-{secret}");
                    eprintln!(
                        "Rotated. The previous secret keeps working for {grace_hours}h so \
                         deployments can roll without a hard cut."
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        KeyCommand::Disable { id } => {
            match edit(id, &|def: &mut VirtualKeyDef| def.enabled = false) {
                Ok(()) => {
                    println!("Disabled {id}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        KeyCommand::Enable { id } => {
            match edit(id, &|def: &mut VirtualKeyDef| def.enabled = true) {
                Ok(()) => {
                    println!("Enabled {id}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
        KeyCommand::Rm { id } => {
            let (state, _) = store.read();
            if !state.virtual_keys.contains_key(id) {
                return fail(format!("no key with id `{id}`"));
            }
            match commit(
                &store,
                None,
                StoreCommand::DeleteVirtualKey { id: id.clone() },
            ) {
                Ok(_) => {
                    println!("Removed {id}");
                    ExitCode::SUCCESS
                }
                Err(err) => fail(err),
            }
        }
    }
}

fn period_name(period: router_core::vkey::BudgetPeriod) -> &'static str {
    use router_core::vkey::BudgetPeriod::*;
    match period {
        Daily => "daily",
        Weekly => "weekly",
        Monthly => "monthly",
    }
}

/// `250/monthly` -> a budget. The period defaults to monthly.
fn parse_budget(spec: &str) -> Result<router_core::vkey::Budget, String> {
    use router_core::vkey::{Budget, BudgetPeriod};
    let (amount, period) = match spec.split_once('/') {
        Some((amount, period)) => (amount, period),
        None => (spec, "monthly"),
    };
    let usd: f64 = amount
        .trim()
        .parse()
        .map_err(|_| format!("`{amount}` is not a number (expected e.g. `250/monthly`)"))?;
    if !(usd.is_finite() && usd > 0.0) {
        return Err("budget must be a positive number".into());
    }
    let period = match period.trim() {
        "daily" | "day" => BudgetPeriod::Daily,
        "weekly" | "week" => BudgetPeriod::Weekly,
        "monthly" | "month" => BudgetPeriod::Monthly,
        other => {
            return Err(format!(
                "unknown period `{other}` (expected daily, weekly, or monthly)"
            ));
        }
    };
    Ok(Budget { usd, period })
}

/// Which control-plane backend this invocation should talk to.
///
/// CLI flags win over the config file so an operator can point a
/// file-managed deployment at a shared store without editing the file
/// their deploy tool owns.
fn backend_spec(
    cli: &Cli,
    from_config: Option<&router_core::config::StoreConfig>,
) -> Result<BackendSpec, String> {
    let kind = cli
        .store_backend
        .clone()
        .or_else(|| from_config.map(|s| s.backend.clone()))
        .unwrap_or_else(|| "file".into());

    let region = cli
        .store_region
        .clone()
        .or_else(|| from_config.and_then(|s| s.region.clone()));
    let endpoint = cli
        .store_endpoint
        .clone()
        .or_else(|| from_config.and_then(|s| s.endpoint.clone()));

    match kind.as_str() {
        "file" => Ok(BackendSpec::File {
            path: cli
                .store_path
                .clone()
                .unwrap_or_else(|| data_dir(cli).join("store.json")),
        }),
        "memory" => Ok(BackendSpec::Memory),
        "s3" => {
            let bucket = cli
                .store_bucket
                .clone()
                .or_else(|| from_config.and_then(|s| s.bucket.clone()))
                .ok_or("the s3 store needs a bucket: --store-bucket or [store] bucket")?;
            Ok(BackendSpec::S3 {
                bucket,
                prefix: cli
                    .store_prefix
                    .clone()
                    .or_else(|| from_config.and_then(|s| s.prefix.clone()))
                    .unwrap_or_default(),
                region,
                endpoint,
            })
        }
        "dynamodb" => {
            let table = cli
                .store_table
                .clone()
                .or_else(|| from_config.and_then(|s| s.table.clone()))
                .ok_or("the dynamodb store needs a table: --store-table or [store] table")?;
            Ok(BackendSpec::DynamoDb {
                table,
                region,
                endpoint,
            })
        }
        other => Err(format!(
            "unknown store backend `{other}` — expected file, s3, or dynamodb"
        )),
    }
}

/// The address this node reports to the console's fleet list. Nothing
/// dials it; it is there so an operator can tell two tasks apart.
fn advertise_addr(cli: &Cli, port: Option<u16>) -> String {
    if let Some(addr) = &cli.advertise {
        return addr.clone();
    }
    let port = port.unwrap_or(8080);
    let host = std::env::var("RAPID_ADVERTISE_HOST")
        .ok()
        .or_else(local_ipv4)
        .unwrap_or_else(|| "127.0.0.1".into());
    format!("{host}:{port}")
}

/// The address a peer would reach us on, discovered by asking the OS which
/// local interface it would use to leave the box. No packets are sent.
fn local_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?; // TEST-NET-1: routable, never real
    socket.local_addr().ok().map(|a| a.ip().to_string())
}

fn fleet_command(cli: &Cli) -> ExitCode {
    let store = match open_store(cli) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let window = Duration::from_secs(15);
    let peers = match block_on(store.peers(window)) {
        Ok(peers) => peers,
        Err(err) => return fail(err),
    };
    println!("Store:   {}", store.describe());
    println!("Version: {}", store.version());
    if peers.is_empty() {
        println!("Nodes:   none heartbeating (this store is not shared, or the fleet is down)");
        return ExitCode::SUCCESS;
    }
    let now = router_store::backend::now_ms_for_tests();
    println!("Nodes:   {}", peers.len());
    for beat in peers {
        println!(
            "  {:<38} {:<22} last seen {}s ago",
            beat.id,
            beat.addr,
            beat.age(now).as_secs()
        );
    }
    ExitCode::SUCCESS
}

fn master_key_command() -> ExitCode {
    println!("{}", router_store::Sealer::generate_master_key());
    eprintln!(
        "Set this as {} on every node. It seals stored secrets, so nodes that \
         disagree about it cannot read each other's. Keep it in your platform's \
         secret manager, not in the config file.",
        router_store::MASTER_KEY_ENV,
    );
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> ExitCode {
    let data_dir = data_dir(&cli);
    let section = match config_store_section(&cli) {
        Ok(section) => section,
        Err(code) => return code,
    };
    let spec = match backend_spec(&cli, section.as_ref()) {
        Ok(spec) => spec,
        Err(message) => return fail(message),
    };
    let tuning = section.unwrap_or_default();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime");

    runtime.block_on(async move {
        let store = match Store::open(&spec, &data_dir, &advertise_addr(&cli, None)).await {
            Ok(store) => Arc::new(store),
            Err(err) => return fail(err),
        };
        tracing::info!(store = %store.describe(), node = store.node_id(), "control plane");

        let mut config = match load_initial_config(&cli, &store).await {
            Ok(config) => config,
            Err(code) => return code,
        };
        if let Some(port) = cli.port {
            config.server.port = port;
        }
        store.set_addr(advertise_addr(&cli, Some(config.server.port)));

        let addr = format!("{}:{}", config.server.host, config.server.port);
        let providers: Vec<String> = config.providers.keys().cloned().collect();
        let state = if cli.mode == Mode::Managed {
            AppState::managed(config, store.clone(), data_dir.clone())
        } else {
            AppState::file_with_data_dir(config, store.clone(), data_dir.clone())
        };

        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(err) => return fail(format!("failed to bind {addr}: {err}")),
        };
        tracing::info!(%addr, ?providers, mode = ?cli.mode, "rapid-router listening");

        if cli.mode == Mode::File {
            spawn_reload_tasks(state.clone(), cli.config.clone(), cli.watch, store.clone());
        }

        // The two timers that stand in for a cluster: one to notice what
        // other nodes wrote, one to tell them we are here.
        state.spawn_refresher(Duration::from_secs(tuning.refresh_interval_secs));
        // Model prices, kept current from the public catalog.
        state.spawn_price_refresher();
        // Usage history out of reach of a lost instance.
        state.spawn_usage_shipper();
        // Subscription credentials are renewed on their own beat rather
        // than only when a request happens to need one.
        state.spawn_seat_maintenance(Duration::from_secs(60));
        if let Some(secs) = cli.canary_interval_secs.filter(|secs| *secs > 0) {
            state.spawn_canary(Duration::from_secs(secs));
        }
        state.spawn_heartbeat(
            Duration::from_secs(tuning.heartbeat_interval_secs),
            Duration::from_secs(tuning.liveness_window_secs),
        );

        let app = router_server::build_router(state.clone());
        let result = router_server::serve(listener, state, app, shutdown_signal()).await;

        // Leaving cleanly returns this node's share of every rate limit
        // to the fleet now, rather than after the liveness window.
        store.depart().await;

        match result {
            Ok(()) => {
                tracing::info!("shutdown complete");
                ExitCode::SUCCESS
            }
            Err(err) => fail(format!("server error: {err}")),
        }
    })
}

async fn load_initial_config(cli: &Cli, store: &Store) -> Result<Config, ExitCode> {
    if cli.mode == Mode::Managed {
        let (snapshot, _) = store.read();
        if let Some(text) = snapshot.config_text {
            return validate_store_config(store, &text, Format::Toml).map_err(fail);
        }
        if let Some(path) = cli.config.as_deref() {
            let text = std::fs::read_to_string(path).map_err(fail)?;
            let config = validate_store_config(store, &text, format_for(path)).map_err(fail)?;
            store
                .commit(None, StoreCommand::PutConfig { text })
                .await
                .map_err(fail)?;
            return Ok(config);
        }
        if let Some(config) = Config::discover_from_env(&|name: &str| std::env::var(name).ok()) {
            return Ok(config);
        }
        return bootstrap(store).await.map_err(fail);
    }
    match cli.config.as_deref() {
        Some(path) => load_file_config(store, path).map_err(fail),
        None => Config::discover_from_env(&|name: &str| std::env::var(name).ok()).ok_or_else(|| {
            fail("file mode needs --config or at least one conventional provider environment variable")
        }),
    }
}

async fn bootstrap(store: &Store) -> Result<Config, Box<dyn std::error::Error>> {
    let secret = router_core::vkey::generate_secret();
    store
        .commit(
            None,
            StoreCommand::PutSecret {
                name: "bootstrap_admin".into(),
                sealed: store.seal_secret(&secret),
            },
        )
        .await?;
    let text = "[console]\nadmin_keys = [\"store.bootstrap_admin\"]\n".to_owned();
    let config = validate_store_config(store, &text, Format::Toml)?;
    store.commit(None, StoreCommand::PutConfig { text }).await?;
    eprintln!("Bootstrap admin key (shown once): {secret}");
    eprintln!("Open http://127.0.0.1:8080/console");
    Ok(config)
}

fn load_file_config(store: &Store, path: &Path) -> Result<Config, router_core::config::LoadError> {
    let text = std::fs::read_to_string(path)?;
    validate_store_config(store, &text, format_for(path))
}

fn validate_store_config(
    store: &Store,
    text: &str,
    format: Format,
) -> Result<Config, router_core::config::LoadError> {
    let env = |name: &str| {
        name.strip_prefix("store.")
            .and_then(|secret| store.resolve_secret(secret))
            .or_else(|| std::env::var(name).ok())
    };
    Config::from_str_with_env(text, format, &env)
}

fn format_for(path: &Path) -> Format {
    if path.extension().and_then(|value| value.to_str()) == Some("json") {
        Format::Json
    } else {
        Format::Toml
    }
}

fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn spawn_reload_tasks(
    state: Arc<AppState>,
    config_path: Option<PathBuf>,
    watch: bool,
    store: Arc<Store>,
) {
    let Some(path) = config_path else { return };
    let reload = {
        let state = state.clone();
        let path = path.clone();
        move || match load_file_config(&store, &path) {
            Ok(new_config) => {
                state.apply_config(new_config);
                tracing::info!(path = %path.display(), "config reloaded");
            }
            Err(err) => {
                tracing::error!(path = %path.display(), %err, "reload failed; keeping previous config")
            }
        }
    };
    #[cfg(unix)]
    {
        let reload = reload.clone();
        tokio::spawn(async move {
            let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to install SIGHUP handler");
            while hup.recv().await.is_some() {
                reload();
            }
        });
    }
    if watch {
        tokio::spawn(async move {
            let mut last = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let current = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                if current.is_some() && current != last {
                    last = current;
                    reload();
                }
            }
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init_tracing(dev: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if dev {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    }
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("{error}");
    ExitCode::FAILURE
}
