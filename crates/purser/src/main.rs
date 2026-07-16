//! Purser command-line interface for the local, single-machine vault.

mod project_sync;
mod secret_sync;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use purser_store::{AuditEvent, Project, Store};
use purser_sync::{
    accept_pairing, accept_sync, bind_pairing, bind_sync, connect_pairing, connect_sync,
    request_pairing, serve_pairing, IrohTransport, PairingCode, PairingKeyMaterial, Record,
    SyncConnection, Transport,
};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROJECTS_ROOT_SETTING: &str = "projects_root";
const FOOTER: &str = "built with Rust. Rust good. 🦀";

#[derive(Parser)]
#[command(
    name = "purser",
    version,
    about = "Local encrypted secrets with agent-blind process execution",
    after_help = FOOTER,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Encrypt a dotenv file, then remove the plaintext source.
    Import(ImportArgs),
    /// Inspect or update encrypted secret metadata.
    Secrets(SecretsArgs),
    /// Run a command with one profile injected into the child environment.
    Run(ProcessArgs),
    /// Open an interactive shell with one profile injected.
    Shell(ProfileArgs),
    /// Run a command in an environment with secret variables removed.
    Agent(AgentArgs),
    /// Read the value-blind audit trail.
    Audit(AuditArgs),
    /// Register and inspect project metadata.
    Project(ProjectArgs),
    /// Inspect this device or prove peer-to-peer connectivity.
    Device(DeviceArgs),
    /// Replicate encrypted secrets and project manifests with a paired device.
    Sync(SyncArgs),
    /// Set or print the device-local directory used for newly cloned projects.
    ProjectsRoot(ProjectsRootArgs),
    /// Show registered projects and secret configuration status.
    Status,
    /// Clone missing projects and install their dependencies.
    Up(UpArgs),
    /// Print shell wrappers for transparent per-project execution.
    Hook(HookArgs),
    /// Remove this device's Purser data (database + keyring keys), with confirmation.
    ///
    /// Cargo cannot be hooked, so this is separate from removing the binary: it clears the
    /// data, then tells you to run `cargo uninstall purser` for the binary itself.
    Uninstall,
    #[command(name = "_in-project", hide = true)]
    InProject,
}

#[derive(Debug, Args)]
struct ImportArgs {
    path: PathBuf,
    #[arg(long)]
    profile: String,
}

#[derive(Debug, Args)]
struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Debug, Subcommand)]
enum SecretsCommand {
    /// List secret names and configuration status.
    List(ProfileArgs),
    /// Prompt for and store a new encrypted secret version.
    Set(SetArgs),
}

#[derive(Debug, Args)]
struct ProfileArgs {
    #[arg(long)]
    profile: String,
}

#[derive(Debug, Args)]
struct SetArgs {
    name: String,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    group: String,
}

#[derive(Debug, Args)]
struct ProcessArgs {
    #[arg(long)]
    profile: String,
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[arg(long)]
    denied: bool,
    #[command(subcommand)]
    command: Option<AuditCommand>,
}

#[derive(Debug, Args)]
struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Register or update a local project.
    Add(ProjectAddArgs),
    /// Unregister a project. Its files and secrets are left alone.
    Remove(ProjectRemoveArgs),
}

#[derive(Debug, Args)]
struct ProjectAddArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    profile: Option<String>,
}

#[derive(Debug, Args)]
struct ProjectRemoveArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
}

#[derive(Args)]
struct DeviceArgs {
    /// Override the hostname stored as this device's label.
    #[arg(long, global = true)]
    label: Option<String>,
    #[command(subcommand)]
    command: DeviceCommand,
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Print this device's persistent iroh identity.
    Info,
    /// List devices recorded in the local database.
    List,
    /// Accept unauthenticated hello probes until Ctrl-C.
    Listen,
    /// Dial a NodeId and measure an unauthenticated hello round-trip.
    Connect { node_id: String },
    /// Show a one-time enrollment code, or with `--join` enroll this device by entering one.
    ///
    /// The code is never taken as an argument: it grants the vault key, and an argument
    /// lingers in shell history and is briefly visible in the process list. `--join` reads
    /// it from a hidden prompt (or stdin when piped).
    Pair {
        #[arg(long)]
        join: bool,
    },
}

#[derive(Debug, Args)]
struct SyncArgs {
    /// NodeId of a paired device to exchange records with.
    #[arg(long)]
    peer: Option<String>,
    #[command(subcommand)]
    command: Option<SyncCommand>,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Serve paired peers until Ctrl-C.
    Serve,
}

#[derive(Debug, Args)]
struct UpArgs {
    /// Report what would change without syncing, cloning, or installing.
    #[arg(long)]
    dry_run: bool,
    /// Use only what this device already knows; do not contact paired devices first.
    #[arg(long)]
    no_sync: bool,
    /// WARNING: materialize vault secrets into missing project .env files.
    #[arg(long)]
    write_env: bool,
}

#[derive(Debug, Args)]
struct ProjectsRootArgs {
    path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct HookArgs {
    shell: HookShell,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum HookShell {
    Bash,
    Zsh,
    Powershell,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Show events from the most recently opened session.
    Last,
}

fn main() {
    // Inspect only argv[1]. Collecting every argument here would retain a second copy of
    // an entered pairing code for the lifetime of the process.
    let first_argument = std::env::args_os().nth(1);
    if first_argument.as_ref().and_then(|value| value.to_str()) == Some("rust") {
        println!("good.");
        return;
    }
    if matches!(
        first_argument.as_ref().and_then(|value| value.to_str()),
        Some("--version" | "-V")
    ) {
        println!("purser {VERSION}");
        println!("{FOOTER}");
        return;
    }

    let exit_code = match execute(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        TopCommand::Import(args) => import(args),
        TopCommand::Secrets(args) => secrets(args),
        TopCommand::Run(args) => run_with_profile(args),
        TopCommand::Shell(args) => shell(args),
        TopCommand::Agent(args) => agent(args),
        TopCommand::Audit(args) => audit(args),
        TopCommand::Project(args) => project(args),
        TopCommand::Device(args) => device(args),
        TopCommand::Sync(args) => sync(args),
        TopCommand::ProjectsRoot(args) => projects_root(args),
        TopCommand::Status => status(),
        TopCommand::Up(args) => up(args),
        TopCommand::Hook(args) => hook(args),
        TopCommand::Uninstall => uninstall(),
        TopCommand::InProject => in_project(),
    }
}

fn sync(args: SyncArgs) -> Result<i32> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the sync networking runtime")?
        .block_on(sync_async(args))
}

async fn sync_async(args: SyncArgs) -> Result<i32> {
    let identity = ensure_device_identity(None)?;
    match (args.command, args.peer) {
        (Some(SyncCommand::Serve), None) => sync_serve(identity.key).await?,
        (None, Some(peer)) => sync_peer(identity.key, &peer).await?,
        (Some(SyncCommand::Serve), Some(_)) => {
            bail!("--peer cannot be used with `sync serve`");
        }
        // Pairing already recorded who the peers are; making the owner paste a NodeId to
        // reach a device Purser knows about is friction Purser invented.
        (None, None) => {
            let (reached, unreachable) = sync_all_paired(identity.key).await?;
            if reached == 0 {
                bail!("no paired device could be reached");
            }
            if unreachable > 0 {
                println!("Synced with {reached}; {unreachable} unreachable.");
            }
        }
    }
    Ok(0)
}

async fn sync_serve(key: iroh::SecretKey) -> Result<()> {
    let endpoint = bind_sync(key).await?;
    if tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .is_err()
    {
        eprintln!("warning: no relay became reachable; direct local connections may still work");
    }
    println!("Listening for paired sync peers as {}", endpoint.id());
    std::io::stdout().flush()?;

    loop {
        tokio::select! {
            result = accept_sync(&endpoint) => {
                match result {
                    Ok(connection) => {
                        let peer = connection.peer_id();
                        let authorized = Store::open()?
                            .find_device_by_public_key(peer.as_bytes())?
                            .is_some_and(|device| !device.is_self);
                        if !authorized {
                            connection.refuse();
                            eprintln!("warning: refused unpaired sync peer {peer}; no records sent");
                            continue;
                        }
                        tokio::select! {
                            result = serve_sync_connection(connection) => {
                                if let Err(error) = result {
                                    eprintln!("warning: paired peer {peer} sync failed: {error:#}");
                                }
                            }
                            result = tokio::signal::ctrl_c() => {
                                result.context("could not listen for Ctrl-C")?;
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("warning: incoming sync handshake failed: {error:#}");
                    }
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("could not listen for Ctrl-C")?;
                break;
            }
        }
    }
    endpoint.close().await;
    Ok(())
}

async fn serve_sync_connection(connection: SyncConnection) -> Result<()> {
    let store = Store::open()?;
    let mut records = secret_sync::build_records(&store)?;
    let secret_sent = records.len();
    let project_records = project_sync::build_records(&store)?;
    let project_sent = project_records.len();
    records.extend(project_records);
    let incoming = connection.exchange_responder(&records).await?;
    apply_and_report_sync_records(&Store::open()?, &incoming, secret_sent, project_sent)?;
    Ok(())
}

/// A peer that is asleep must cost seconds, not minutes: `up` dials every paired device
/// before doing any local work, and one unreachable laptop cannot be allowed to hang it.
const SYNC_DIAL_TIMEOUT: Duration = Duration::from_secs(30);

async fn sync_peer(key: iroh::SecretKey, node_id: &str) -> Result<()> {
    let peer: iroh::PublicKey = node_id
        .parse()
        .context("NODE_ID must be an iroh public key")?;
    let paired = Store::open()?
        .find_device_by_public_key(peer.as_bytes())?
        .is_some_and(|device| !device.is_self);
    if !paired {
        bail!("sync refused: {peer} is not a paired device");
    }
    let endpoint = bind_sync(key).await?;
    let result = sync_one_peer(&endpoint, peer).await;
    endpoint.close().await;
    result
}

/// Exchange with every paired device, reusing one endpoint.
///
/// Returns (reached, unreachable). A device that is off is an ordinary fact of syncing
/// between your own machines, not an error: the others still sync, and this one will catch
/// up next time. Only the caller decides whether nothing-reached is worth failing over.
async fn sync_all_paired(key: iroh::SecretKey) -> Result<(usize, usize)> {
    let peers: Vec<(iroh::PublicKey, String)> = Store::open()?
        .list_devices()?
        .into_iter()
        .filter(|device| !device.is_self)
        .map(|device| {
            let key = iroh::PublicKey::try_from(device.public_key.as_slice())
                .context("a stored device has an invalid iroh public key")?;
            Ok((key, device.label))
        })
        .collect::<Result<_>>()?;
    if peers.is_empty() {
        bail!("no paired devices yet. Enroll one with `purser device pair`.");
    }

    let endpoint = bind_sync(key).await?;
    let (mut reached, mut unreachable) = (0, 0);
    for (peer, label) in peers {
        println!("{label} ({}):", short_node_id(&peer));
        match tokio::time::timeout(SYNC_DIAL_TIMEOUT, sync_one_peer(&endpoint, peer)).await {
            Ok(Ok(())) => reached += 1,
            Ok(Err(error)) => {
                unreachable += 1;
                eprintln!("  warning: sync failed: {error:#}");
            }
            Err(_) => {
                unreachable += 1;
                eprintln!("  warning: no response within {SYNC_DIAL_TIMEOUT:?}; is it awake and running `purser sync serve`?");
            }
        }
    }
    endpoint.close().await;
    Ok((reached, unreachable))
}

async fn sync_one_peer(endpoint: &iroh::Endpoint, peer: iroh::PublicKey) -> Result<()> {
    let store = Store::open()?;
    let mut records = secret_sync::build_records(&store)?;
    let secret_sent = records.len();
    let project_records = project_sync::build_records(&store)?;
    let project_sent = project_records.len();
    records.extend(project_records);
    let connection = connect_sync(endpoint, peer).await?;
    let incoming = connection.exchange_initiator(&records).await?;
    apply_and_report_sync_records(&Store::open()?, &incoming, secret_sent, project_sent)
}

/// Enough of a NodeId to recognize, not so much that it wraps the line.
fn short_node_id(peer: &iroh::PublicKey) -> String {
    peer.to_string().chars().take(12).collect()
}

fn report_sync_summary(summary: &secret_sync::SyncSummary) {
    for warning in &summary.warnings {
        eprintln!("warning: {warning}");
    }
    println!("{}", summary.render());
}

fn apply_and_report_sync_records(
    store: &Store,
    incoming: &[Record],
    secret_sent: usize,
    project_sent: usize,
) -> Result<()> {
    let (projects, secrets): (Vec<_>, Vec<_>) = incoming
        .iter()
        .cloned()
        .partition(project_sync::is_project_record);
    let mut secret_summary = secret_sync::apply_records(store, &secrets)?;
    secret_summary.sent = secret_sent;
    report_sync_summary(&secret_summary);

    let mut project_summary = project_sync::apply_records(store, &projects)?;
    project_summary.sent = project_sent;
    for warning in &project_summary.warnings {
        eprintln!("warning: {warning}");
    }
    println!("{}", project_summary.render());
    Ok(())
}

struct DeviceIdentity {
    key: iroh::SecretKey,
    label: String,
}

fn device(args: DeviceArgs) -> Result<i32> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the device networking runtime")?
        .block_on(device_async(args))
}

async fn device_async(args: DeviceArgs) -> Result<i32> {
    let identity = ensure_device_identity(args.label)?;
    match args.command {
        DeviceCommand::Info => {
            println!("NodeId: {}", identity.key.public());
            println!("Label: {}", identity.label);
        }
        DeviceCommand::List => {
            for device in Store::open()?.list_devices()? {
                let node_id = iroh::PublicKey::try_from(device.public_key.as_slice())
                    .context("a stored device has an invalid iroh public key")?;
                let marker = if device.is_self { " (self)" } else { "" };
                println!("{}  {}{}", node_id, device.label, marker);
            }
        }
        DeviceCommand::Listen => device_listen(identity.key).await?,
        DeviceCommand::Connect { node_id } => device_connect(identity.key, &node_id).await?,
        DeviceCommand::Pair { join } => {
            if join {
                device_pair_join(identity, read_pairing_code()?).await?
            } else {
                device_pair_serve(identity).await?
            }
        }
    }
    Ok(0)
}

fn ensure_device_identity(label_override: Option<String>) -> Result<DeviceIdentity> {
    let key_bytes = purser_vault::device_key()?;
    let key = iroh::SecretKey::from_bytes(&key_bytes);
    let store = Store::open()?;
    let stored = store.find_device_by_public_key(key.public().as_bytes())?;
    let label = label_override
        .or_else(|| stored.map(|device| device.label))
        .unwrap_or_else(machine_label);
    store.upsert_self_device(&label, key.public().as_bytes())?;
    Ok(DeviceIdentity { key, label })
}

fn machine_label() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|label| !label.trim().is_empty())
        .unwrap_or_else(|| "unknown-device".to_owned())
}

async fn device_listen(key: iroh::SecretKey) -> Result<()> {
    let endpoint = IrohTransport::bind(key).await?;
    eprintln!("WARNING: THIS CHANNEL IS UNAUTHENTICATED.");
    eprintln!("Any peer is accepted in transport step 3a. Pairing and authorization land in 3b.");
    eprintln!("No vault data, database rows, or sensitive values are sent by this command.");
    if tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .is_err()
    {
        eprintln!("warning: no relay became reachable; direct local connections may still work");
    }
    println!("Listening as {}", endpoint.id());
    std::io::stdout().flush()?;

    loop {
        tokio::select! {
            // One peer must never take the listener down with it: a hangup, a malformed
            // frame, or a hostile probe is that peer's problem, reported and survived.
            // Only losing the endpoint itself ends the loop.
            result = IrohTransport::accept(&endpoint) => {
                let (transport, peer) = result.context("the iroh endpoint stopped accepting")?;
                println!("Connected peer: {peer}");
                tokio::select! {
                    result = async {
                        let hello = transport.recv().await?;
                        transport.send(&hello).await
                    } => {
                        match result {
                            Ok(()) => println!("Hello echoed to {peer}"),
                            Err(error) => eprintln!("warning: peer {peer} hello failed: {error:#}"),
                        }
                    }
                    result = tokio::signal::ctrl_c() => {
                        result.context("could not listen for Ctrl-C")?;
                        break;
                    }
                }
                std::io::stdout().flush()?;
            }
            result = tokio::signal::ctrl_c() => {
                result.context("could not listen for Ctrl-C")?;
                break;
            }
        }
    }
    endpoint.close().await;
    Ok(())
}

async fn device_connect(key: iroh::SecretKey, node_id: &str) -> Result<()> {
    let peer: iroh::PublicKey = node_id
        .parse()
        .context("NODE_ID must be an iroh public key")?;
    let endpoint = IrohTransport::bind(key).await?;
    let transport = IrohTransport::connect(&endpoint, peer).await?;
    let hello = Record {
        id: "purser-3a-hello".to_owned(),
        version: 1,
        ciphertext: b"hello".to_vec(),
    };
    let started = Instant::now();
    transport.send(&hello).await?;
    let echoed = transport.recv().await?;
    if echoed != hello {
        bail!("peer returned an invalid hello response");
    }
    println!(
        "Connected to {}: hello round-trip succeeded in {:.2?}",
        transport.peer_id(),
        started.elapsed()
    );
    endpoint.close().await;
    Ok(())
}

const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Read the one-time pairing code without ever placing it in argv, where it would linger in
/// shell history and be briefly visible in the process list. Hidden prompt when interactive;
/// a plain stdin line when piped, so scripted enrollment still works.
fn read_pairing_code() -> Result<String> {
    use std::io::IsTerminal;
    let raw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Pairing code: ").context("could not read the pairing code")?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("could not read the pairing code from stdin")?;
        line
    };
    let code = raw.trim().to_owned();
    if code.is_empty() {
        bail!("no pairing code was entered");
    }
    Ok(code)
}

async fn device_pair_serve(identity: DeviceIdentity) -> Result<()> {
    // This device gives its vault key away during pairing, so it must already hold one.
    // Check before opening the window: otherwise the joiner authenticates and does real
    // work only to fail in the authorized closure with VaultKeyMissing. Fail-fast here
    // rather than minting a key, so a fresh device that meant to JOIN (and should have run
    // `pair <CODE>`) is told what it did instead of silently becoming its own vault.
    if !purser_vault::vault_key_exists()? {
        bail!(
            "this device has no vault key to share yet. Import a secret first \
             (e.g. `purser import .env --profile local`), or to join another device's vault \
             run `purser device pair <CODE>` with the code shown on that device."
        );
    }
    let endpoint = bind_pairing(identity.key).await?;
    if tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .is_err()
    {
        eprintln!("warning: no relay became reachable; direct local connections may still work");
    }
    let (mut encoded, code) = PairingCode::generate(endpoint.id());
    // Stdout contains exactly the copy/pasteable code and no other pairing material.
    println!("{}", encoded.as_str());
    std::io::stdout().flush()?;
    encoded.zeroize();
    eprintln!("Pairing window open for 10 minutes; it closes after one successful enrollment.");

    let deadline = tokio::time::Instant::now() + PAIRING_WINDOW;
    loop {
        let connection = match tokio::time::timeout_at(deadline, accept_pairing(&endpoint)).await {
            Ok(result) => result?,
            Err(_) => {
                endpoint.close().await;
                bail!("pairing window expired");
            }
        };
        let attempt = tokio::time::timeout_at(
            deadline,
            serve_pairing(connection, endpoint.id(), &code, &identity.label, || {
                // This closure is not called until the peer's HMAC has verified.
                let key = purser_vault::export_vault_key()
                    .context("could not load this device's vault key after authorization")?;
                Ok(PairingKeyMaterial::from_zeroizing(key))
            }),
        )
        .await;
        match attempt {
            Err(_) => {
                endpoint.close().await;
                bail!("pairing window expired");
            }
            Ok(Ok(peer)) => {
                Store::open()?.upsert_paired_device(&peer.label, peer.id.as_bytes())?;
                println!("Paired device: {}  {}", peer.id, peer.label);
                endpoint.close().await;
                return Ok(());
            }
            Ok(Err(error)) => {
                eprintln!("warning: pairing attempt refused: {error:#}");
                if tokio::time::Instant::now() >= deadline {
                    endpoint.close().await;
                    bail!("pairing window expired");
                }
            }
        }
    }
}

async fn device_pair_join(identity: DeviceIdentity, mut encoded: String) -> Result<()> {
    refuse_pairing_over_existing_state()?;
    let decoded = PairingCode::decode(&encoded);
    encoded.zeroize();
    let code = decoded.context("invalid pairing code")?;
    let endpoint = bind_pairing(identity.key).await?;
    let connection = connect_pairing(&endpoint, code.peer()).await?;
    let received = request_pairing(connection, endpoint.id(), &code, &identity.label).await?;

    // Recheck immediately before the irreversible local write in case another process
    // changed this scoped device while the network handshake was in progress.
    refuse_pairing_over_existing_state()?;
    purser_vault::install_vault_key_if_absent(received.key_material.as_bytes())?;
    Store::open()?.upsert_paired_device(&received.peer.label, received.peer.id.as_bytes())?;
    println!("Paired with {}  {}", received.peer.id, received.peer.label);
    endpoint.close().await;
    Ok(())
}

fn refuse_pairing_over_existing_state() -> Result<()> {
    if Store::open()?.has_secret_versions()? {
        bail!(
            "pairing refused: this device already stores encrypted secret versions; \
             replacing its vault key would make them permanently unreadable"
        );
    }
    if purser_vault::vault_key_exists()? {
        bail!(
            "pairing refused: this device already has a vault key and it will not be overwritten"
        );
    }
    Ok(())
}

fn in_project() -> Result<i32> {
    let current = std::env::current_dir().context("could not read the current directory")?;
    let store = Store::open()?;
    Ok(i32::from(
        find_containing_project(&store, &current)?.is_none(),
    ))
}

/// Find the closest registered project by checking the current directory, then its parents.
fn find_containing_project(store: &Store, path: &Path) -> Result<Option<Project>> {
    let canonical = canonical_project_path(path)?;
    for ancestor in canonical.ancestors() {
        let local_path = ancestor
            .to_str()
            .ok_or_else(|| anyhow!("project path must be valid UTF-8"))?;
        if let Some(project) = store.find_project_by_path(local_path)? {
            return Ok(Some(project));
        }
    }
    Ok(None)
}

fn project(args: ProjectArgs) -> Result<i32> {
    match args.command {
        ProjectCommand::Add(args) => project_add(args),
        ProjectCommand::Remove(args) => project_remove(args),
    }
}

fn project_remove(args: ProjectRemoveArgs) -> Result<i32> {
    // A project whose directory is already gone must still be removable, so fall back to
    // plain absolutization when canonicalization cannot resolve a missing path.
    let path = match canonical_project_path(&args.path) {
        Ok(path) => path,
        Err(_) => absolute_path(&args.path)?,
    };
    let local_path = path
        .to_str()
        .ok_or_else(|| anyhow!("project path must be valid UTF-8"))?;
    let store = Store::open()?;
    if store.remove_project_by_path(local_path)? {
        println!(
            "Unregistered {}. Files and secrets were left alone.",
            path.display()
        );
        Ok(0)
    } else {
        bail!("no project is registered at {}", path.display());
    }
}

/// Absolutize without touching the filesystem, so a deleted directory still resolves.
///
/// Rebuilding from components normalizes the separators and drops `.` segments, so a path
/// typed as `C:/foo` matches one the manifest stored as `C:\foo`. Without that, a project
/// could not be unregistered once its directory was gone — the one time it matters most.
fn absolute_path(path: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .context("could not read the current directory")?
            .join(path)
    };
    Ok(plain_path(joined.components().collect()))
}

fn project_add(args: ProjectAddArgs) -> Result<i32> {
    let path = canonical_project_path(&args.path)?;
    if !path.is_dir() {
        bail!("project path is not a directory: {}", path.display());
    }
    let local_path = path
        .to_str()
        .ok_or_else(|| anyhow!("project path must be valid UTF-8"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("project path must end in a valid UTF-8 directory name"))?;
    let (git_remote, branch) = git_metadata(&path);
    let package_manager = detect_package_manager(&path);

    let store = Store::open()?;
    store.upsert_project(
        name,
        git_remote.as_deref(),
        branch.as_deref(),
        package_manager,
        args.profile.as_deref(),
        local_path,
    )?;
    if git_remote.is_none() {
        println!("Note: no git remote found — `up` cannot clone {name} if it goes missing.");
    }
    println!("Registered {name} at {}.", path.display());
    Ok(0)
}

fn projects_root(args: ProjectsRootArgs) -> Result<i32> {
    let store = Store::open()?;
    let Some(path) = args.path else {
        match store.setting(PROJECTS_ROOT_SETTING)? {
            Some(path) => println!("{path}"),
            None => println!(
                "Projects root is not configured. Set it with `purser projects-root PATH`."
            ),
        }
        return Ok(0);
    };
    if path.exists() && !path.is_dir() {
        bail!("projects root is not a directory: {}", path.display());
    }
    let path = if path.exists() {
        canonical_project_path(&path)?
    } else {
        absolute_path(&path)?
    };
    let value = path
        .to_str()
        .ok_or_else(|| anyhow!("projects root must be valid UTF-8"))?;
    store.set_setting(PROJECTS_ROOT_SETTING, value)?;
    println!("Projects root set to {}.", path.display());
    Ok(0)
}

fn uninstall() -> Result<i32> {
    let db_path = Store::database_path()?;
    let has_db = db_path.exists();
    let has_key = purser_vault::vault_key_exists()?;

    if !has_db && !has_key {
        println!("Nothing to remove: this device has no Purser data.");
        println!("To remove the binary itself, run: cargo uninstall purser");
        return Ok(0);
    }

    // Summarize what a wipe would destroy, reading before anything is touched. The store is
    // dropped at the end of this block so the database file is unlocked before deletion —
    // Windows will not delete a file that still has an open handle.
    let (secret_count, peer_count, self_label) = if has_db {
        let store = Store::open()?;
        let secret_count = store.all_secret_names()?.len();
        let devices = store.list_devices()?;
        let peer_count = devices.iter().filter(|device| !device.is_self).count();
        let self_label = devices
            .iter()
            .find(|device| device.is_self)
            .map(|device| device.label.clone());
        (secret_count, peer_count, self_label)
    } else {
        (0, 0, None)
    };

    println!("This device has {secret_count} secret(s) and is paired with {peer_count} device(s).");
    if secret_count > 0 && peer_count == 0 {
        println!("WARNING: no other device holds these secrets — wiping is PERMANENT loss.");
    }
    println!();
    println!("  [k] Keep my data (remove only the binary, yourself)");
    println!("  [w] Wipe everything on this device (database + vault key) — IRREVERSIBLE");

    let choice = prompt_line("Choice [k/w]: ")?;
    let wipe = matches!(choice.trim().to_ascii_lowercase().as_str(), "w" | "wipe");
    if !wipe {
        println!("Kept your data. To remove the binary, run: cargo uninstall purser");
        return Ok(0);
    }

    // Typed-name confirmation: a stray `w` must never be enough to destroy the vault key.
    let confirm_token = self_label.as_deref().unwrap_or("wipe");
    let typed = prompt_line(&format!(
        "Type this device's name '{confirm_token}' to confirm the wipe: "
    ))?;
    if typed.trim() != confirm_token {
        bail!("names did not match; nothing was removed");
    }

    if has_db {
        remove_database_files(&db_path)?;
    }
    purser_vault::delete_all_keys()?;

    println!("Wiped this device's Purser data (database + keyring keys).");
    println!("Now remove the binary: cargo uninstall purser");
    Ok(0)
}

/// Delete the SQLite database and any journal/WAL sidecars beside it.
fn remove_database_files(db_path: &Path) -> Result<()> {
    fs::remove_file(db_path).with_context(|| format!("could not remove {}", db_path.display()))?;
    if let (Some(dir), Some(name)) = (db_path.parent(), db_path.file_name().and_then(|n| n.to_str()))
    {
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(dir.join(format!("{name}{suffix}"))); // best-effort
        }
    }
    Ok(())
}

/// Print a prompt and read one line from stdin. Works interactively and when piped.
fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("could not read from stdin")?;
    Ok(line)
}

fn status() -> Result<i32> {
    let store = Store::open()?;
    let projects = store.list_projects()?;
    if projects.is_empty() {
        println!("No registered projects.");
        return Ok(0);
    }
    for project in projects {
        let path_status = project
            .local_path
            .as_deref()
            .is_some_and(|path| Path::new(path).exists());
        let package_manager = project.package_manager.as_deref().unwrap_or("-");
        if let Some(profile) = project.profile_ref.as_deref() {
            let secrets = store.list_secrets(profile)?;
            let configured = secrets.iter().filter(|secret| secret.configured).count();
            let not_configured = secrets.len() - configured;
            println!(
                "{}\t{}\tpackage={}\tprofile={}\tsecrets={configured} configured, {not_configured} not configured",
                project.name,
                if path_status { "cloned" } else { "MISSING" },
                package_manager,
                profile
            );
        } else {
            println!(
                "{}\t{}\tpackage={}\tprofile=-\tsecrets=-",
                project.name,
                if path_status { "cloned" } else { "MISSING" },
                package_manager
            );
        }
    }
    Ok(0)
}

/// Pull from the other devices before reproducing this one, so `up` on a fresh machine is
/// one command rather than three.
///
/// Nothing here is fatal. `up` must keep working on a plane: with no peers paired, or none
/// of them awake, the local manifest is still worth acting on. Only the networking runtime
/// is paid for, and only when a sync is actually attempted.
fn sync_before_up() -> Result<()> {
    // Every step here is best-effort: a missing device identity, a runtime that will not
    // build, or an unreachable peer must all degrade to "use local state", never abort `up`.
    if let Err(error) = try_sync_before_up() {
        eprintln!("warning: skipping sync: {error:#}");
        eprintln!("warning: continuing with this device's own manifest.");
    }
    println!();
    Ok(())
}

fn try_sync_before_up() -> Result<()> {
    let identity = ensure_device_identity(None)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the sync networking runtime")?;
    let (reached, unreachable) = runtime.block_on(sync_all_paired(identity.key))?;
    println!("Synced with {reached} device(s); {unreachable} unreachable.");
    Ok(())
}

fn up(args: UpArgs) -> Result<i32> {
    if !args.no_sync && !args.dry_run {
        sync_before_up()?;
    }
    let store = Store::open()?;
    let projects = store.list_projects()?;
    if projects.is_empty() {
        println!("No registered projects. Register one with `purser project add .`.");
        return Ok(0);
    }
    let mut failures = Vec::new();
    for project in &projects {
        println!("{}:", project.name);
        // A project is reported failed at most once, however many of its steps fail.
        let mut failed = false;
        let mut effective_project = project.clone();
        let mut preparation_actions = Vec::new();
        match prepare_project_for_up(&store, project, args.dry_run) {
            Ok((prepared, actions)) => {
                effective_project = prepared;
                preparation_actions = actions;
            }
            Err(error) => {
                println!("  FAILED: {error:#}");
                failed = true;
            }
        }
        let bring_up = if failed {
            None
        } else {
            Some(bring_up_project(&effective_project, args.dry_run))
        };
        match bring_up {
            None => {}
            Some(Ok(actions)) if actions.is_empty() && preparation_actions.is_empty() => {
                println!("  nothing to do")
            }
            Some(Ok(actions)) => {
                let prefix = if args.dry_run { "would" } else { "done" };
                for action in preparation_actions.into_iter().chain(actions) {
                    println!("  {prefix} {action}");
                }
                if project.local_path.is_none() && !args.dry_run {
                    let path = effective_project
                        .local_path
                        .as_deref()
                        .expect("prepared project has a local path");
                    let canonical = canonical_project_path(Path::new(path))?;
                    let canonical = canonical
                        .to_str()
                        .ok_or_else(|| anyhow!("project path must be valid UTF-8"))?;
                    store.set_project_local_path(&project.id, canonical)?;
                    effective_project.local_path = Some(canonical.to_owned());
                }
            }
            // One project failing must not stop the rest of the machine coming up.
            Some(Err(error)) => {
                println!("  FAILED: {error:#}");
                failed = true;
            }
        }
        if !failed && args.write_env && effective_project.profile_ref.is_some() {
            match materialize_project_dotenv(&store, &effective_project, args.dry_run) {
                Ok(DotenvMaterialization::Written(variable_count)) => println!(
                    "  WARNING: wrote {variable_count} variables to {}",
                    project_dotenv_path(&effective_project)?.display()
                ),
                Ok(DotenvMaterialization::WouldWrite(variable_count)) => println!(
                    "  WARNING: would write {variable_count} variables to {}",
                    project_dotenv_path(&effective_project)?.display()
                ),
                Ok(DotenvMaterialization::Skipped(reason)) => {
                    println!("  skipped .env: {reason}")
                }
                Err(error) => {
                    println!("  FAILED to write .env: {error:#}");
                    failed = true;
                }
            }
        }
        if failed {
            failures.push(project.name.clone());
        }
        report_profile_status(&store, &effective_project)?;
    }
    if failures.is_empty() {
        Ok(0)
    } else {
        eprintln!("Failed projects: {}", failures.join(", "));
        Ok(1)
    }
}

fn prepare_project_for_up(
    store: &Store,
    project: &Project,
    dry_run: bool,
) -> Result<(Project, Vec<String>)> {
    if project.local_path.is_some() {
        return Ok((project.clone(), Vec::new()));
    }
    let remote = project.git_remote.as_deref().ok_or_else(|| {
        anyhow!(
            "project has no local path and no git remote; register it locally with `purser project add PATH`"
        )
    })?;
    let root = store.setting(PROJECTS_ROOT_SETTING)?.ok_or_else(|| {
        anyhow!(
            "project needs cloning, but no projects root is configured; run `purser projects-root PATH`"
        )
    })?;
    validate_project_directory_name(&project.name)?;
    let target = Path::new(&root).join(&project.name);
    let target_text = target
        .to_str()
        .ok_or_else(|| anyhow!("project clone path must be valid UTF-8"))?;
    let mut prepared = project.clone();
    prepared.local_path = Some(target_text.to_owned());
    let mut actions = Vec::new();

    if target.exists() && !directory_is_empty(&target)? {
        if !target.is_dir() {
            bail!(
                "clone target exists and is not a directory: {}",
                target.display()
            );
        }
        let found_remote =
            git_output(&target, &["remote", "get-url", "origin"]).with_context(|| {
                format!(
                    "clone target {} is non-empty and is not the expected git repository",
                    target.display()
                )
            })?;
        if found_remote != remote {
            bail!(
                "clone target {} is non-empty and belongs to a different repository (expected {remote}, found {found_remote}); skipped",
                target.display()
            );
        }
        actions.push(format!("adopt existing repository at {}", target.display()));
        if !dry_run {
            let canonical = canonical_project_path(&target)?;
            let canonical = canonical
                .to_str()
                .ok_or_else(|| anyhow!("project path must be valid UTF-8"))?;
            store.set_project_local_path(&project.id, canonical)?;
            prepared.local_path = Some(canonical.to_owned());
        }
    }
    Ok((prepared, actions))
}

fn validate_project_directory_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if path.file_name().and_then(OsStr::to_str) != Some(name)
        || path.components().count() != 1
        || name == "."
        || name == ".."
    {
        bail!("project name cannot be used as a clone directory: {name}");
    }
    Ok(())
}

fn directory_is_empty(path: &Path) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    Ok(fs::read_dir(path)
        .with_context(|| format!("could not inspect clone target {}", path.display()))?
        .next()
        .is_none())
}

enum DotenvMaterialization {
    Written(usize),
    WouldWrite(usize),
    Skipped(&'static str),
}

fn project_dotenv_path(project: &Project) -> Result<PathBuf> {
    let local_path = project
        .local_path
        .as_deref()
        .ok_or_else(|| anyhow!("project has no local path"))?;
    Ok(Path::new(local_path).join(".env"))
}

fn materialize_project_dotenv(
    store: &Store,
    project: &Project,
    dry_run: bool,
) -> Result<DotenvMaterialization> {
    let profile = project
        .profile_ref
        .as_deref()
        .ok_or_else(|| anyhow!("project has no profile"))?;

    // Decide to skip BEFORE decrypting, so a skipped project never holds plaintext at all.
    let dotenv_path = project_dotenv_path(project)?;
    let directory = dotenv_path
        .parent()
        .ok_or_else(|| anyhow!("project path has no parent directory"))?;
    if !directory.is_dir() {
        return Ok(DotenvMaterialization::Skipped(
            "the project directory does not exist",
        ));
    }
    if dotenv_path.exists() {
        return Ok(DotenvMaterialization::Skipped(
            "one already exists (delete it to regenerate)",
        ));
    }

    let active = store.get_active_versions(profile)?;
    // Writing an empty .env would be worse than writing nothing: the file's mere existence
    // makes every later run skip, so secrets added to this profile would never materialize.
    if active.is_empty() {
        return Ok(DotenvMaterialization::Skipped(
            "the profile has no configured secrets",
        ));
    }
    let mut plaintexts = Vec::with_capacity(active.len());
    for (name, ciphertext) in active {
        let plaintext = Zeroizing::new(purser_vault::decrypt(&ciphertext)?);
        std::str::from_utf8(&plaintext).with_context(|| {
            format!("secret {name} is not valid UTF-8 and cannot be written to a dotenv file")
        })?;
        plaintexts.push((name, plaintext));
    }

    if dry_run {
        return Ok(DotenvMaterialization::WouldWrite(plaintexts.len()));
    }

    ensure_ignored(&dotenv_path)?;

    let mut contents = Zeroizing::new(String::new());
    for (name, plaintext) in &plaintexts {
        validate_name(name).with_context(|| format!("invalid secret name {name}"))?;
        let value = std::str::from_utf8(plaintext).expect("validated above");
        let line = serialize_dotenv_entry(name, value);
        contents.push_str(&line);
    }

    // Materialize through a hardened temp file, then hard-link it into place. This makes the
    // .env appear complete or not at all: a failed or interrupted write can never leave a
    // half-populated file holding SOME of the secrets. The link (not a rename) fails rather
    // than overwrites if a .env appeared meanwhile, preserving the never-overwrite rule.
    let temp_path = directory.join(format!(".env.purser-{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp_path); // clear any stale temp from a crashed prior run

    let outcome = (|| -> Result<bool> {
        write_hardened_file(&temp_path, contents.as_bytes())?;
        // Audit BEFORE committing: the append-only record must exist before a secret becomes
        // readable on disk, never after. (If the link below loses the never-overwrite race,
        // this over-reports by one — an accepted, fail-closed trade versus writing silently.)
        for (name, _) in &plaintexts {
            store.append_audit_event(None, "env_written", Some(name), "used")?;
        }
        match fs::hard_link(&temp_path, &dotenv_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(anyhow::Error::new(error))
                .with_context(|| format!("could not install {}", dotenv_path.display())),
        }
    })();

    contents.zeroize();
    for (_, plaintext) in &mut plaintexts {
        plaintext.zeroize();
    }
    // Remove the temp copy on every path: on success the linked .env keeps the content; on
    // failure or a lost race this leaves no hardened plaintext artifact behind.
    let _ = fs::remove_file(&temp_path);

    if outcome? {
        Ok(DotenvMaterialization::Written(plaintexts.len()))
    } else {
        Ok(DotenvMaterialization::Skipped(
            "one appeared while purser was running",
        ))
    }
}

/// Create `path` fresh (never overwriting), 0600 on Unix, write `contents`, and flush it to
/// disk. Used to stage a dotenv before atomically linking it into place.
fn write_hardened_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("could not write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("could not flush {}", path.display()))?;
    Ok(())
}

/// Clone and rehydrate one project, returning a description of each action taken.
///
/// In `dry_run` the descriptions are still produced but nothing is executed.
fn bring_up_project(project: &Project, dry_run: bool) -> Result<Vec<String>> {
    let local_path = project
        .local_path
        .as_deref()
        .ok_or_else(|| anyhow!("project has no local path"))?;
    let path = Path::new(local_path);
    let mut actions = Vec::new();

    if !path.exists() || directory_is_empty(path)? {
        let git_remote = project.git_remote.as_deref().ok_or_else(|| {
            anyhow!("project directory is missing and there is no git remote to clone from")
        })?;
        actions.push(format!("clone {git_remote} into {}", path.display()));
        if !dry_run {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("could not create project parent {}", parent.display())
                })?;
            }
            let mut command = program_command("git")?;
            command.arg("clone").arg(git_remote).arg(path);
            run_command(&mut command, "git clone")?;
        }
        if let Some(branch) = project.branch.as_deref() {
            actions.push(format!("check out {branch}"));
            if !dry_run {
                let mut command = program_command("git")?;
                command.arg("-C").arg(path).arg("checkout").arg(branch);
                run_command(&mut command, "git checkout")?;
            }
        }
    }

    if let Some((program, install_arguments)) = install_command(project.package_manager.as_deref())
    {
        actions.push(format!("run {program} {}", install_arguments.join(" ")));
        if !dry_run {
            let mut command = program_command(program)?;
            command.args(install_arguments).current_dir(path);
            run_command(&mut command, "dependency install")?;
        }
    }
    Ok(actions)
}

fn report_profile_status(store: &Store, project: &Project) -> Result<()> {
    let Some(profile) = project.profile_ref.as_deref() else {
        println!("  profile: none");
        return Ok(());
    };
    let secrets = store.list_secrets(profile)?;
    if secrets.is_empty() {
        println!("  profile {profile}: no secrets registered");
        return Ok(());
    }
    // Names and configured-status only — a value must never reach stdout.
    let missing: Vec<_> = secrets
        .iter()
        .filter(|secret| !secret.configured)
        .map(|secret| secret.name.as_str())
        .collect();
    if missing.is_empty() {
        println!(
            "  profile {profile}: all {} secrets configured",
            secrets.len()
        );
    } else {
        println!("  profile {profile}: missing {}", missing.join(", "));
    }
    Ok(())
}

fn run_command(command: &mut Command, operation: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("could not run {operation}"))?;
    if !status.success() {
        bail!("{operation} exited with {}", exit_code(status));
    }
    Ok(())
}

/// Resolve a program name to a concrete file, searching PATH the way a shell would.
///
/// Windows' `CreateProcess` only appends `.exe`, but every Node-ecosystem launcher ships as
/// a `.cmd` shim, so `Command::new("npm")` fails outright with "program not found". Finding
/// the shim ourselves keeps the spawn a plain argv — no `cmd /c` string to quote wrong.
#[cfg(windows)]
fn resolve_program(program: &str) -> Option<PathBuf> {
    let path_extensions =
        std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    let directories = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&directories) {
        for extension in path_extensions.split(';').filter(|item| !item.is_empty()) {
            let candidate = directory.join(format!("{program}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn resolve_program(program: &str) -> Option<PathBuf> {
    let directories = std::env::var_os("PATH")?;
    std::env::split_paths(&directories)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// Build a `Command` for a program that may be a shim rather than a real executable.
fn program_command(program: &str) -> Result<Command> {
    let resolved = resolve_program(program)
        .ok_or_else(|| anyhow!("{program} is not installed or not on PATH"))?;
    Ok(Command::new(resolved))
}

/// Build a child command while resolving Windows command shims without a shell string.
fn child_command(program: &OsStr) -> Command {
    #[cfg(windows)]
    {
        let path = Path::new(program);
        if path.components().count() == 1 && path.extension().is_none() {
            if let Some(resolved) = program.to_str().and_then(resolve_program) {
                return Command::new(resolved);
            }
        }
    }
    Command::new(program)
}

/// Canonicalize a project path into the form the manifest stores.
fn canonical_project_path(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize project path {}", path.display()))?;
    Ok(plain_path(canonical))
}

/// Strip Windows' `\\?\` verbatim prefix, which `fs::canonicalize` always adds.
///
/// A verbatim path is not interchangeable with the plain one: it does not compare equal to
/// what `current_dir` returns (so project lookup by cwd would miss), and git rejects it as a
/// clone target. The manifest therefore stores the plain form.
#[cfg(windows)]
fn plain_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    let Some(rest) = text.strip_prefix(r"\\?\") else {
        return path;
    };
    // Only a plain drive path (`\\?\C:\dir`) shortens by truncation. A verbatim UNC share
    // (`\\?\UNC\server\share`) needs a different rewrite, so leave that one untouched.
    let mut characters = rest.chars();
    let is_drive_path = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.next() == Some(':')
        && characters.next() == Some('\\');
    if is_drive_path {
        PathBuf::from(rest.to_string())
    } else {
        path
    }
}

#[cfg(not(windows))]
fn plain_path(path: PathBuf) -> PathBuf {
    path
}

/// Best-effort `(remote, branch)` for a directory.
///
/// A project need not be a git repository: it is registered either way, and `up` simply has
/// nothing to clone. Only a missing directory with no remote is an error, and that surfaces
/// in `up`, not here.
fn git_metadata(path: &Path) -> (Option<String>, Option<String>) {
    let Ok(remotes) = git_output(path, &["remote"]) else {
        return (None, None);
    };
    let remote_name = remotes
        .lines()
        .find(|remote| *remote == "origin")
        .or_else(|| remotes.lines().next())
        .map(str::to_owned);
    let git_remote = remote_name
        .as_deref()
        .and_then(|remote| git_output(path, &["remote", "get-url", remote]).ok())
        .filter(|remote| !remote.is_empty());
    let branch = current_branch(path).or_else(|| {
        remote_name
            .as_deref()
            .and_then(|remote| remote_head_branch(path, remote))
    });
    (git_remote, branch)
}

fn git_output(path: &Path, arguments: &[&str]) -> Result<String> {
    let mut command = program_command("git")?;
    let output = command
        .arg("-C")
        .arg(path)
        .args(arguments)
        .stderr(Stdio::null())
        .output()
        .context("could not run git")?;
    if !output.status.success() {
        bail!("git metadata query failed");
    }
    Ok(String::from_utf8(output.stdout)
        .context("git metadata was not valid UTF-8")?
        .trim()
        .to_owned())
}

fn current_branch(path: &Path) -> Option<String> {
    git_output(path, &["rev-parse", "--abbrev-ref", "HEAD"])
        .ok()
        .filter(|branch| branch != "HEAD" && !branch.is_empty())
}

fn remote_head_branch(path: &Path, remote: &str) -> Option<String> {
    let reference = format!("refs/remotes/{remote}/HEAD");
    let branch = git_output(path, &["symbolic-ref", "--short", &reference]).ok()?;
    branch
        .strip_prefix(&format!("{remote}/"))
        .map(str::to_owned)
}

fn detect_package_manager(path: &Path) -> Option<&'static str> {
    if path.join("pnpm-lock.yaml").is_file() {
        Some("pnpm")
    } else if path.join("bun.lockb").is_file() || path.join("bun.lock").is_file() {
        Some("bun")
    } else if path.join("yarn.lock").is_file() {
        Some("yarn")
    } else if path.join("package-lock.json").is_file() {
        Some("npm")
    } else if path.join("Cargo.toml").is_file() {
        Some("cargo")
    } else if path.join("uv.lock").is_file() || path.join("pyproject.toml").is_file() {
        Some("uv")
    } else if path.join("package.json").is_file() {
        Some("npm")
    } else {
        None
    }
}

fn install_command(
    package_manager: Option<&str>,
) -> Option<(&'static str, &'static [&'static str])> {
    match package_manager {
        Some("pnpm") => Some(("pnpm", &["install"])),
        Some("npm") => Some(("npm", &["install"])),
        Some("bun") => Some(("bun", &["install"])),
        Some("yarn") => Some(("yarn", &["install"])),
        Some("cargo") => Some(("cargo", &["fetch"])),
        Some("uv") => Some(("uv", &["sync"])),
        _ => None,
    }
}

const DEV_TOOLS: &[&str] = &["npm", "pnpm", "bun", "yarn", "node", "vite", "cargo", "uv"];
const AGENT_TOOLS: &[&str] = &["claude", "codex"];

fn hook(args: HookArgs) -> Result<i32> {
    let code = match args.shell {
        HookShell::Bash | HookShell::Zsh => posix_hook(),
        HookShell::Powershell => powershell_hook(),
    };
    print!("{code}");
    Ok(0)
}

fn posix_hook() -> String {
    let mut code = String::new();
    for tool in DEV_TOOLS {
        code.push_str(&format!(
            "{tool}() {{\n  if command -v purser >/dev/null 2>&1 && purser _in-project >/dev/null 2>&1; then\n    purser run --profile auto -- {tool} \"$@\"\n  else\n    command {tool} \"$@\"\n  fi\n}}\n\n"
        ));
    }
    for tool in AGENT_TOOLS {
        code.push_str(&format!(
            "{tool}() {{\n  if command -v purser >/dev/null 2>&1 && purser _in-project >/dev/null 2>&1; then\n    purser agent -- {tool} \"$@\"\n  else\n    command {tool} \"$@\"\n  fi\n}}\n\n"
        ));
    }
    code
}

fn powershell_hook() -> String {
    let mut code = String::new();
    for (tools, purser_command) in [
        (DEV_TOOLS, "run --profile auto --"),
        (AGENT_TOOLS, "agent --"),
    ] {
        for tool in tools {
            code.push_str(&format!(
                "function global:{tool} {{\n    $purserCommand = Get-Command purser -CommandType Application -ErrorAction SilentlyContinue\n    if ($null -ne $purserCommand) {{\n        & $purserCommand.Source _in-project *> $null\n        if ($LASTEXITCODE -eq 0) {{\n            & $purserCommand.Source {purser_command} {tool} @args\n            $childExitCode = $LASTEXITCODE\n            $global:LASTEXITCODE = $childExitCode\n            return\n        }}\n    }}\n    $toolCommand = Get-Command {tool} -CommandType Application -ErrorAction SilentlyContinue\n    if ($null -eq $toolCommand) {{\n        Get-Command {tool} -CommandType Application -ErrorAction Stop | Out-Null\n        $global:LASTEXITCODE = 1\n        return\n    }}\n    & $toolCommand.Source @args\n    $childExitCode = $LASTEXITCODE\n    $global:LASTEXITCODE = $childExitCode\n    return\n}}\n\n"
            ));
        }
    }
    code
}

fn import(args: ImportArgs) -> Result<i32> {
    let mut source = Zeroizing::new(
        fs::read_to_string(&args.path)
            .with_context(|| format!("could not read dotenv source {}", args.path.display()))?,
    );
    let mut entries = parse_dotenv(&source)?;
    ensure_ignored(&args.path)?;

    let store = Store::open()?;
    let mut imported_names = Vec::with_capacity(entries.len());
    for (name, value) in &mut entries {
        let ciphertext = purser_vault::encrypt(value.as_bytes())?;
        let id = store.upsert_secret(name, &args.profile, None, true)?;
        store.add_secret_version(&id, &ciphertext)?;
        imported_names.push(name.clone());
        value.zeroize();
    }
    source.zeroize();
    fs::remove_file(&args.path).with_context(|| {
        format!(
            "secrets were encrypted, but the plaintext source could not be removed: {}",
            args.path.display()
        )
    })?;

    println!("Imported secret names:");
    for name in imported_names {
        println!("  {name}");
    }
    println!(
        "WARNING: plaintext source {} was removed after encryption.",
        args.path.display()
    );
    Ok(0)
}

fn secrets(args: SecretsArgs) -> Result<i32> {
    let store = Store::open()?;
    match args.command {
        SecretsCommand::List(args) => {
            let profile = resolve_named_profile(&store, &args.profile)?;
            for secret in store.list_secrets(&profile)? {
                let status = if secret.configured {
                    "configured"
                } else {
                    "not configured"
                };
                println!("{}\t{}", secret.name, status);
            }
        }
        SecretsCommand::Set(args) => {
            validate_name(&args.name)?;
            let profile = resolve_named_profile(&store, &args.profile)?;
            let mut value = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
            let ciphertext = purser_vault::encrypt(value.as_bytes())?;
            value.zeroize();
            let id = store.upsert_secret(&args.name, &profile, Some(&args.group), true)?;
            let version = store.add_secret_version(&id, &ciphertext)?;
            println!("Stored {} version {} (configured).", args.name, version);
        }
    }
    Ok(0)
}

/// Resolve a `--profile` argument, mapping the literal `auto` onto the current project.
///
/// `run`/`shell` fall back to injecting nothing when `auto` cannot resolve, because running
/// the tool still beats failing. A secrets command has no such fallback: reading or writing
/// a guessed profile is worse than stopping, so an unresolvable `auto` is an error here.
fn resolve_named_profile(store: &Store, profile: &str) -> Result<String> {
    if profile != "auto" {
        return Ok(profile.to_owned());
    }
    let current = std::env::current_dir().context("could not read the current directory")?;
    let project = find_containing_project(store, &current)?.ok_or_else(|| {
        anyhow!("--profile auto: the current directory is not in a registered Purser project")
    })?;
    project.profile_ref.ok_or_else(|| {
        anyhow!(
            "--profile auto: project {} has no profile; pass --profile explicitly, or re-register it with `purser project add . --profile <name>`",
            project.name
        )
    })
}

fn run_with_profile(args: ProcessArgs) -> Result<i32> {
    if args.profile == "auto" {
        return run_with_auto_profile(&args.command, false);
    }
    let store = Store::open()?;
    let scope = profile_scope(&args.profile);
    let session = store.open_session("human", Some(&scope))?;
    let result = spawn_with_profile(&store, &session, &args.profile, &args.command, false);
    store.close_session(&session)?;
    Ok(exit_code(result?))
}

fn shell(args: ProfileArgs) -> Result<i32> {
    let command = shell_command();
    if args.profile == "auto" {
        return run_with_auto_profile(&command, true);
    }
    let store = Store::open()?;
    let scope = profile_scope(&args.profile);
    let session = store.open_session("human", Some(&scope))?;
    let result = spawn_with_profile(&store, &session, &args.profile, &command, true);
    store.close_session(&session)?;
    Ok(exit_code(result?))
}

fn run_with_auto_profile(command: &[OsString], interactive: bool) -> Result<i32> {
    let current = match std::env::current_dir() {
        Ok(current) => current,
        Err(error) => {
            eprintln!(
                "Note: could not read the current directory ({error}); running without secret injection."
            );
            return Ok(exit_code(spawn_without_profile(command, interactive)?));
        }
    };
    let store = match Store::open() {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "Note: could not open the Purser project manifest ({error}); running without secret injection."
            );
            return Ok(exit_code(spawn_without_profile(command, interactive)?));
        }
    };
    let project = match find_containing_project(&store, &current) {
        Ok(project) => project,
        Err(error) => {
            eprintln!(
                "Note: could not resolve the current Purser project ({error}); running without secret injection."
            );
            return Ok(exit_code(spawn_without_profile(command, interactive)?));
        }
    };
    let Some(project) = project else {
        eprintln!(
            "Note: the current directory is not in a registered Purser project; running without secret injection."
        );
        return Ok(exit_code(spawn_without_profile(command, interactive)?));
    };
    let Some(profile) = project.profile_ref else {
        eprintln!(
            "Note: the current Purser project has no profile; running without secret injection."
        );
        return Ok(exit_code(spawn_without_profile(command, interactive)?));
    };

    let scope = profile_scope(&profile);
    let session = store.open_session("human", Some(&scope))?;
    let result = spawn_with_profile(&store, &session, &profile, command, interactive);
    store.close_session(&session)?;
    Ok(exit_code(result?))
}

fn spawn_without_profile(argv: &[OsString], interactive: bool) -> Result<ExitStatus> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| anyhow!("a child command is required"))?;
    let mut command = child_command(program);
    command.args(arguments);
    if interactive {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    command.status().context("could not run child process")
}

fn spawn_with_profile(
    store: &Store,
    session: &str,
    profile: &str,
    argv: &[OsString],
    interactive: bool,
) -> Result<ExitStatus> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| anyhow!("a child command is required"))?;
    let active = store.get_active_versions(profile)?;
    let mut plaintexts = Vec::with_capacity(active.len());
    for (name, ciphertext) in active {
        let plaintext = purser_vault::decrypt(&ciphertext)?;
        std::str::from_utf8(&plaintext).with_context(|| {
            format!("secret {name} is not valid UTF-8 and cannot be an environment value")
        })?;
        plaintexts.push((name, plaintext));
    }

    let mut command = child_command(program);
    command.args(arguments);
    if interactive {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    for (name, plaintext) in &plaintexts {
        // Command owns an internal child-environment copy; the parent environment is untouched.
        command.env(
            name,
            std::str::from_utf8(plaintext).expect("validated above"),
        );
    }

    let child_result = command.spawn().context("could not spawn child process");
    drop(command);
    for (_, plaintext) in &mut plaintexts {
        plaintext.zeroize();
    }
    let mut child = child_result?;
    for (name, _) in &plaintexts {
        store.append_audit_event(Some(session), "injected", Some(name), "used")?;
    }
    child.wait().context("could not wait for child process")
}

fn agent(args: AgentArgs) -> Result<i32> {
    let store = Store::open()?;
    let session = store.open_session("agent", Some(r#"{"environment":"sanitized"}"#))?;
    store.append_audit_event(Some(&session), "session_start", None, "used")?;

    let result = spawn_agent_child(&store, &args.command);
    let decision = if result.is_ok() { "used" } else { "denied" };
    store.append_audit_event(Some(&session), "session_end", None, decision)?;
    store.close_session(&session)?;
    Ok(exit_code(result?))
}

fn spawn_agent_child(store: &Store, argv: &[OsString]) -> Result<ExitStatus> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| anyhow!("an agent command is required"))?;
    let secret_names: HashSet<String> = store
        .all_secret_names()?
        .into_iter()
        .map(|name| normalize_env_name(&name))
        .collect();

    let mut command = child_command(program);
    command.args(arguments);
    // Sanitize by stripping only variables whose names collide with a known secret.
    // Secret VALUES are never in this process's environment (they live in the vault),
    // so inheriting the rest keeps the agent runnable while guaranteeing no secret
    // variable reaches it.
    for (key, _value) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|name| secret_names.contains(&normalize_env_name(name)))
        {
            command.env_remove(&key);
        }
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("could not run agent child process")
}

fn audit(args: AuditArgs) -> Result<i32> {
    let store = Store::open()?;
    if args.denied && args.command.is_some() {
        bail!("choose only one of `audit last` or `audit --denied`");
    }
    let events = if args.denied {
        store.denied_events()?
    } else if matches!(args.command, Some(AuditCommand::Last)) {
        store.recent_events()?
    } else {
        bail!("choose `audit last` or `audit --denied`");
    };
    print_events(&events);
    Ok(0)
}

fn print_events(events: &[AuditEvent]) {
    if events.is_empty() {
        println!("No matching audit events.");
        return;
    }
    for event in events {
        let reference = event.secret_ref.as_deref().unwrap_or("-");
        let session = event.session_id.as_deref().unwrap_or("-");
        println!(
            "{}  {:<13} {:<7} secret={} session={}",
            event.created_at, event.kind, event.decision, reference, session
        );
    }
}

fn ensure_ignored(source: &Path) -> Result<()> {
    let filename = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("dotenv source must have a valid UTF-8 filename"))?;
    let ignore_path = source
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".gitignore");
    let existing = match fs::read_to_string(&ignore_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("could not read .gitignore"),
    };
    if existing.lines().any(|line| line.trim() == filename) {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ignore_path)
        .context("could not update .gitignore")?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file)?;
    }
    writeln!(file, "{filename}")?;
    Ok(())
}

fn serialize_dotenv_entry(name: &str, value: &str) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::with_capacity(name.len() + value.len() + 4));
    output.push_str(name);
    output.push_str("=\"");
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            other => output.push(other),
        }
    }
    output.push_str("\"\n");
    output
}

fn parse_dotenv(input: &str) -> Result<Vec<(String, Zeroizing<String>)>> {
    let mut entries = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with(char::is_whitespace) {
                line = rest.trim_start();
            }
        }
        let (name, raw_value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid dotenv assignment on line {}", index + 1))?;
        let name = name.trim();
        validate_name(name)
            .with_context(|| format!("invalid name on dotenv line {}", index + 1))?;
        let value = parse_dotenv_value(raw_value.trim(), index + 1)?;
        entries.push((name.to_owned(), Zeroizing::new(value)));
    }
    Ok(entries)
}

fn parse_dotenv_value(raw: &str, line_number: usize) -> Result<String> {
    if let Some(quote) = raw
        .as_bytes()
        .first()
        .copied()
        .filter(|byte| matches!(byte, b'\'' | b'"'))
    {
        if raw.len() < 2 || raw.as_bytes().last().copied() != Some(quote) {
            bail!("unterminated quoted value on dotenv line {line_number}");
        }
        let inner = &raw[1..raw.len() - 1];
        if quote == b'\'' {
            return Ok(inner.to_owned());
        }
        let mut output = String::with_capacity(inner.len());
        let mut characters = inner.chars();
        while let Some(character) = characters.next() {
            if character != '\\' {
                output.push(character);
                continue;
            }
            match characters.next() {
                Some('n') => output.push('\n'),
                Some('r') => output.push('\r'),
                Some('t') => output.push('\t'),
                Some('"') => output.push('"'),
                Some('\\') => output.push('\\'),
                Some(other) => {
                    output.push('\\');
                    output.push(other);
                }
                None => output.push('\\'),
            }
        }
        return Ok(output);
    }

    let comment_start = raw
        .char_indices()
        .find(|(index, character)| {
            *character == '#' && *index > 0 && raw[..*index].ends_with(char::is_whitespace)
        })
        .map(|(index, _)| index);
    Ok(raw[..comment_start.unwrap_or(raw.len())]
        .trim_end()
        .to_owned())
}

fn validate_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let first = bytes
        .next()
        .ok_or_else(|| anyhow!("secret name cannot be empty"))?;
    if !(first == b'_' || first.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        bail!("secret name must match [A-Za-z_][A-Za-z0-9_]*");
    }
    Ok(())
}

#[cfg(windows)]
fn shell_command() -> Vec<OsString> {
    vec![OsString::from("powershell.exe")]
}

#[cfg(not(windows))]
fn shell_command() -> Vec<OsString> {
    vec![std::env::var_os("SHELL").unwrap_or_else(|| OsString::from("sh"))]
}

fn normalize_env_name(name: &str) -> String {
    #[cfg(windows)]
    {
        name.to_ascii_uppercase()
    }
    #[cfg(not(windows))]
    {
        name.to_owned()
    }
}

fn profile_scope(profile: &str) -> String {
    let mut escaped = String::with_capacity(profile.len());
    for character in profile.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(&mut escaped, "\\u{:04x}", control as u32);
            }
            other => escaped.push(other),
        }
    }
    format!(r#"{{"profile":"{escaped}"}}"#)
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use purser_store::SyncProject;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "purser-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn package_manager_for_markers(markers: &[&str]) -> Option<&'static str> {
        let directory = std::env::temp_dir().join(format!(
            "purser-package-manager-{}-{}",
            std::process::id(),
            markers.join("-").replace('.', "_")
        ));
        fs::create_dir_all(&directory).unwrap();
        for marker in markers {
            fs::write(directory.join(marker), []).unwrap();
        }
        let package_manager = detect_package_manager(&directory);
        fs::remove_dir_all(directory).unwrap();
        package_manager
    }

    fn direct_addr(endpoint: &iroh::Endpoint) -> iroh::EndpointAddr {
        let port = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .unwrap()
            .port();
        iroh::EndpointAddr::new(endpoint.id())
            .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    const TEST_VAULT_KEY: [u8; 32] = [0x6D; 32];

    fn test_seal(bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(purser_vault::encrypt_with_key(&TEST_VAULT_KEY, bytes)?)
    }

    fn test_open(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(purser_vault::decrypt_with_key(
            &TEST_VAULT_KEY,
            bytes,
        )?))
    }

    #[test]
    fn real_sync_endpoints_reconstruct_a_secret_on_the_receiver() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(30), async {
                    let sender = Store::open_in_memory().unwrap();
                    let receiver = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
                    sender
                        .insert_synced_secret(
                            "01PORTABLE",
                            "SYNCED_VALUE",
                            "synctest",
                            Some("test"),
                            "2026-07-15T12:00:00.000000000Z",
                        )
                        .unwrap();
                    sender
                        .insert_synced_secret_version(
                            "01PORTABLE",
                            1,
                            &test_seal(b"it-worked").unwrap(),
                            "2026-07-15T12:00:00.000000000Z",
                        )
                        .unwrap();
                    let records =
                        secret_sync::build_records_with(&sender, test_open, test_seal).unwrap();
                    let sender_at_rest = sender.all_secret_versions_for_sync().unwrap()[0]
                        .ciphertext
                        .clone();
                    assert!(!records[0]
                        .ciphertext
                        .windows(b"SYNCED_VALUE".len())
                        .any(|window| window == b"SYNCED_VALUE"));
                    assert!(!records[0]
                        .ciphertext
                        .windows(b"it-worked".len())
                        .any(|window| window == b"it-worked"));

                    let server_endpoint = bind_sync(iroh::SecretKey::generate()).await.unwrap();
                    let server_addr = direct_addr(&server_endpoint);
                    let accepting = server_endpoint.clone();
                    let receiving_store = Arc::clone(&receiver);
                    let server = tokio::spawn(async move {
                        let connection = accept_sync(&accepting).await.unwrap();
                        let incoming = connection.exchange_responder(&[]).await.unwrap();
                        let store = receiving_store.lock().unwrap();
                        secret_sync::apply_records_with(&store, &incoming, test_open, test_seal)
                            .unwrap()
                    });

                    let client_endpoint = bind_sync(iroh::SecretKey::generate()).await.unwrap();
                    let connection = connect_sync(&client_endpoint, server_addr).await.unwrap();
                    let returned = connection.exchange_initiator(&records).await.unwrap();
                    assert!(returned.is_empty());
                    let summary = server.await.unwrap();
                    assert_eq!(summary.received, 1);
                    {
                        let store = receiver.lock().unwrap();
                        let versions = store.all_secret_versions_for_sync().unwrap();
                        assert_eq!(versions[0].secret_id, "01PORTABLE");
                        assert_eq!(versions[0].name, "SYNCED_VALUE");
                        assert_eq!(
                            test_open(&versions[0].ciphertext).unwrap()[..],
                            b"it-worked"[..]
                        );
                        assert_ne!(versions[0].ciphertext, sender_at_rest);
                    }
                    client_endpoint.close().await;
                    server_endpoint.close().await;
                })
                .await
                .expect("real secret sync test timed out");
            });
    }

    #[test]
    fn unpaired_real_sync_peer_is_refused_before_any_record_is_built_or_sent() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(30), async {
                    let server_store = Store::open_in_memory().unwrap();
                    let server_endpoint = bind_sync(iroh::SecretKey::generate()).await.unwrap();
                    let server_addr = direct_addr(&server_endpoint);
                    let accepting = server_endpoint.clone();
                    let records_built = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let server_flag = Arc::clone(&records_built);
                    let server = tokio::spawn(async move {
                        let connection = accept_sync(&accepting).await.unwrap();
                        let peer = connection.peer_id();
                        let authorized = server_store
                            .find_device_by_public_key(peer.as_bytes())
                            .unwrap()
                            .is_some_and(|device| !device.is_self);
                        if !authorized {
                            connection.refuse();
                            return;
                        }
                        server_flag.store(true, Ordering::SeqCst);
                        let _ = connection.exchange_responder(&[]).await;
                    });

                    let client_endpoint = bind_sync(iroh::SecretKey::generate()).await.unwrap();
                    let connection = connect_sync(&client_endpoint, server_addr).await.unwrap();
                    let result = connection
                        .exchange_initiator(&[Record {
                            id: "must-not-receive".into(),
                            version: 1,
                            ciphertext: vec![9, 8, 7],
                        }])
                        .await;
                    assert!(result.is_err(), "unpaired peer received a sync response");
                    server.await.unwrap();
                    assert!(!records_built.load(Ordering::SeqCst));
                    client_endpoint.close().await;
                    server_endpoint.close().await;
                })
                .await
                .expect("unpaired sync refusal test timed out");
            });
    }

    #[test]
    fn dotenv_parser_handles_assignments_quotes_comments_blanks_and_export() {
        let parsed = parse_dotenv(
            "\n# heading\nPLAIN=value\nDOUBLE=\"two words\"\nSINGLE='literal value'\nexport EXPORTED=yes\nWITH_HASH=url#fragment\nTRAILING=kept # comment\n",
        )
        .unwrap();
        let ordinary: Vec<_> = parsed
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            ordinary,
            vec![
                ("PLAIN", "value"),
                ("DOUBLE", "two words"),
                ("SINGLE", "literal value"),
                ("EXPORTED", "yes"),
                ("WITH_HASH", "url#fragment"),
                ("TRAILING", "kept"),
            ]
        );
    }

    #[test]
    fn dotenv_errors_do_not_include_values() {
        let sensitive = "do-not-show-this";
        let error = parse_dotenv(&format!("BROKEN=\"{sensitive}"))
            .unwrap_err()
            .to_string();
        assert!(!error.contains(sensitive));
    }

    #[test]
    fn serialized_dotenv_values_round_trip_identically() {
        let expected: BTreeMap<_, _> = [
            ("SPACES", "two words"),
            ("COMMENT", "kept # not-a-comment"),
            ("QUOTES", "a \"quote\" and a \\ slash"),
            ("LINES", "first\nsecond\tcolumn\rend"),
            ("EMPTY", ""),
        ]
        .into_iter()
        .collect();
        let mut contents = Zeroizing::new(String::new());
        for (name, value) in &expected {
            contents.push_str(&serialize_dotenv_entry(name, value));
        }

        let parsed = parse_dotenv(&contents).unwrap();
        for (name, expected_value) in expected {
            let (_, actual_value) = parsed
                .iter()
                .find(|(parsed_name, _)| parsed_name == name)
                .unwrap();
            assert_eq!(actual_value.as_str(), expected_value);
        }
    }

    #[test]
    fn dotenv_serializer_escapes_a_known_value() {
        let value = "line\n\"quote\"\\tail";
        let serialized = serialize_dotenv_entry("KNOWN", value);
        assert_eq!(
            serialized.as_str(),
            "KNOWN=\"line\\n\\\"quote\\\"\\\\tail\"\n"
        );
        assert!(!serialized.contains(value));
    }

    #[test]
    fn package_manager_detection_recognizes_every_marker() {
        for (marker, expected) in [
            ("pnpm-lock.yaml", "pnpm"),
            ("bun.lockb", "bun"),
            ("bun.lock", "bun"),
            ("yarn.lock", "yarn"),
            ("package-lock.json", "npm"),
            ("Cargo.toml", "cargo"),
            ("uv.lock", "uv"),
            ("pyproject.toml", "uv"),
            ("package.json", "npm"),
        ] {
            assert_eq!(package_manager_for_markers(&[marker]), Some(expected));
        }
    }

    #[test]
    fn pnpm_lock_takes_precedence_over_package_lock() {
        assert_eq!(
            package_manager_for_markers(&["pnpm-lock.yaml", "package-lock.json"]),
            Some("pnpm")
        );
    }

    /// A registered path must equal what `current_dir` yields, or lookup by cwd misses.
    #[test]
    #[cfg(windows)]
    fn canonical_paths_carry_no_verbatim_prefix() {
        let directory = std::env::current_dir().unwrap();
        let canonical = canonical_project_path(&directory).unwrap();
        assert!(!canonical.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(canonical, plain_path(canonical.clone()));
    }

    #[test]
    #[cfg(windows)]
    fn verbatim_unc_shares_are_left_alone() {
        let share = PathBuf::from(r"\\?\UNC\server\share");
        assert_eq!(plain_path(share.clone()), share);
        assert_eq!(
            plain_path(PathBuf::from(r"\\?\C:\dir")),
            PathBuf::from(r"C:\dir")
        );
    }

    /// `Command::new("npm")` cannot spawn on Windows, where npm is a `.cmd` shim.
    #[test]
    fn shim_installed_programs_resolve_on_this_platform() {
        assert!(resolve_program("git").is_some(), "git should be on PATH");
        assert!(resolve_program("purser-definitely-not-a-real-program").is_none());
    }

    /// Removing a project whose directory is gone must not depend on separator style.
    #[test]
    #[cfg(windows)]
    fn absolute_path_normalizes_separators_for_a_missing_directory() {
        let forward = absolute_path(Path::new("C:/nope/./gone")).unwrap();
        let backward = absolute_path(Path::new(r"C:\nope\gone")).unwrap();
        assert_eq!(forward, backward);
        assert_eq!(forward, PathBuf::from(r"C:\nope\gone"));
    }

    /// A project need not be a git repository; `project add` must still register it.
    #[test]
    fn git_metadata_of_a_non_repository_is_empty_not_an_error() {
        let directory = std::env::temp_dir().join(format!("purser-nongit-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let metadata = git_metadata(&directory);
        fs::remove_dir_all(&directory).unwrap();
        assert_eq!(metadata, (None, None));
    }

    #[test]
    fn project_resolution_picks_the_closest_registered_ancestor() {
        let root = temporary_directory("project-resolution");
        let nested_project = root.join("workspace");
        let child = nested_project.join("src").join("feature");
        fs::create_dir_all(&child).unwrap();
        let store = Store::open_in_memory().unwrap();
        for (path, name, profile) in [
            (&root, "root", "root-profile"),
            (&nested_project, "workspace", "workspace-profile"),
        ] {
            let canonical = canonical_project_path(path).unwrap();
            store
                .upsert_project(
                    name,
                    None,
                    None,
                    None,
                    Some(profile),
                    canonical.to_str().unwrap(),
                )
                .unwrap();
        }

        let project = find_containing_project(&store, &child).unwrap().unwrap();
        assert_eq!(project.name, "workspace");
        assert_eq!(project.profile_ref.as_deref(), Some("workspace-profile"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_resolution_outside_registered_paths_is_empty() {
        let directory = temporary_directory("outside-project");
        let store = Store::open_in_memory().unwrap();
        assert!(find_containing_project(&store, &directory)
            .unwrap()
            .is_none());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_synced_project_without_a_path_clones_into_the_configured_root() {
        let fixture = temporary_directory("synced-project-clone");
        let remote = fixture.join("remote.git");
        let projects_root = fixture.join("projects");
        let mut init = program_command("git").unwrap();
        init.arg("init").arg("--bare").arg(&remote);
        run_command(&mut init, "initialize test remote").unwrap();

        let store = Store::open_in_memory().unwrap();
        store
            .insert_synced_project(&SyncProject {
                id: "01PORTABLE",
                name: "portable",
                git_remote: Some(remote.to_str().unwrap()),
                branch: None,
                package_manager: None,
                profile_ref: None,
                updated_at: "2026-07-15T12:00:00.000000000Z",
            })
            .unwrap();
        store
            .set_setting(PROJECTS_ROOT_SETTING, projects_root.to_str().unwrap())
            .unwrap();

        let project = store.find_project_by_id("01PORTABLE").unwrap().unwrap();
        assert!(project.local_path.is_none());
        let (prepared, preparation_actions) =
            prepare_project_for_up(&store, &project, false).unwrap();
        assert!(preparation_actions.is_empty());
        let actions = bring_up_project(&prepared, false).unwrap();
        assert!(actions[0].starts_with("clone "));
        let cloned = projects_root.join("portable");
        assert!(cloned.join(".git").is_dir());
        let canonical = canonical_project_path(&cloned).unwrap();
        store
            .set_project_local_path("01PORTABLE", canonical.to_str().unwrap())
            .unwrap();
        assert_eq!(
            store
                .find_project_by_id("01PORTABLE")
                .unwrap()
                .unwrap()
                .local_path,
            Some(canonical.to_string_lossy().into_owned())
        );
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn a_synced_project_needing_clone_reports_how_to_configure_the_root() {
        let store = Store::open_in_memory().unwrap();
        store
            .insert_synced_project(&SyncProject {
                id: "01PORTABLE",
                name: "portable",
                git_remote: Some("https://example.invalid/portable.git"),
                branch: None,
                package_manager: None,
                profile_ref: None,
                updated_at: "2026-07-15T12:00:00.000000000Z",
            })
            .unwrap();
        let project = store.find_project_by_id("01PORTABLE").unwrap().unwrap();
        let error = prepare_project_for_up(&store, &project, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("purser projects-root PATH"));
    }

    #[test]
    fn every_hook_has_a_passthrough_for_every_wrapped_tool() {
        let posix = posix_hook();
        let powershell = powershell_hook();
        assert!(!posix.is_empty());
        assert!(!powershell.is_empty());
        for tool in DEV_TOOLS.iter().chain(AGENT_TOOLS) {
            assert!(posix.contains(&format!("command {tool} \"$@\"")));
            assert!(powershell.contains(&format!("Get-Command {tool} -CommandType Application")));
            assert!(powershell.contains("& $toolCommand.Source @args"));
        }
    }

    #[test]
    fn generated_hooks_contain_no_secret_values() {
        let secret_value = "hook-must-never-contain-this-secret-value";
        assert!(!posix_hook().contains(secret_value));
        assert!(!powershell_hook().contains(secret_value));
    }

    #[test]
    fn in_project_probe_has_the_exact_hidden_command_name() {
        let parsed = Cli::try_parse_from(["purser", "_in-project"]).unwrap();
        assert!(matches!(parsed.command, TopCommand::InProject));
        let command = Cli::command();
        let probe = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "_in-project")
            .unwrap();
        assert!(probe.is_hide_set());
    }

    #[test]
    fn device_commands_follow_the_nested_clap_shape() {
        let info =
            Cli::try_parse_from(["purser", "device", "info", "--label", "workstation"]).unwrap();
        match info.command {
            TopCommand::Device(DeviceArgs {
                label,
                command: DeviceCommand::Info,
            }) => assert_eq!(label.as_deref(), Some("workstation")),
            _ => panic!("device info parsed as the wrong command"),
        }

        let connect = Cli::try_parse_from(["purser", "device", "connect", "node-id"]).unwrap();
        assert!(matches!(
            connect.command,
            TopCommand::Device(DeviceArgs {
                command: DeviceCommand::Connect { node_id },
                ..
            }) if node_id == "node-id"
        ));

        // Hosting takes no secret; joining is a flag, never a positional, so the code
        // cannot arrive through argv.
        let host = Cli::try_parse_from(["purser", "device", "pair"]).unwrap();
        assert!(matches!(
            host.command,
            TopCommand::Device(DeviceArgs {
                label: None,
                command: DeviceCommand::Pair { join: false },
            })
        ));

        let join = Cli::try_parse_from(["purser", "device", "pair", "--join"]).unwrap();
        assert!(matches!(
            join.command,
            TopCommand::Device(DeviceArgs {
                command: DeviceCommand::Pair { join: true },
                ..
            })
        ));

        // A stray positional (an old-style code argument) must now be rejected.
        assert!(Cli::try_parse_from(["purser", "device", "pair", "opaque-code"]).is_err());
    }

    #[test]
    fn sync_commands_follow_the_requested_clap_shape() {
        let serve = Cli::try_parse_from(["purser", "sync", "serve"]).unwrap();
        assert!(matches!(
            serve.command,
            TopCommand::Sync(SyncArgs {
                peer: None,
                command: Some(SyncCommand::Serve),
            })
        ));

        let peer = Cli::try_parse_from(["purser", "sync", "--peer", "node-id"]).unwrap();
        assert!(matches!(
            peer.command,
            TopCommand::Sync(SyncArgs {
                peer: Some(node_id),
                command: None,
            }) if node_id == "node-id"
        ));
    }

    #[test]
    fn uninstall_parses_as_a_bare_command() {
        assert!(matches!(
            Cli::try_parse_from(["purser", "uninstall"])
                .unwrap()
                .command,
            TopCommand::Uninstall
        ));
    }

    #[test]
    fn projects_root_accepts_zero_or_one_path() {
        assert!(matches!(
            Cli::try_parse_from(["purser", "projects-root"])
                .unwrap()
                .command,
            TopCommand::ProjectsRoot(ProjectsRootArgs { path: None })
        ));
        assert!(matches!(
            Cli::try_parse_from(["purser", "projects-root", "D:/projects"])
                .unwrap()
                .command,
            TopCommand::ProjectsRoot(ProjectsRootArgs { path: Some(_) })
        ));
    }
}
