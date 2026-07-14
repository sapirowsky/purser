//! Purser command-line interface for the local, single-machine vault.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use purser_store::{AuditEvent, Store};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use zeroize::{Zeroize, Zeroizing};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const FOOTER: &str = "built with Rust. Rust good. 🦀";

#[derive(Debug, Parser)]
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

#[derive(Debug, Subcommand)]
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

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Show events from the most recently opened session.
    Last,
}

fn main() {
    let raw: Vec<OsString> = std::env::args_os().collect();
    if raw.get(1).and_then(|value| value.to_str()) == Some("rust") {
        println!("good.");
        return;
    }
    if matches!(
        raw.get(1).and_then(|value| value.to_str()),
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
    }
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
            for secret in store.list_secrets(&args.profile)? {
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
            let mut value = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
            let ciphertext = purser_vault::encrypt(value.as_bytes())?;
            value.zeroize();
            let id = store.upsert_secret(&args.name, &args.profile, Some(&args.group), true)?;
            let version = store.add_secret_version(&id, &ciphertext)?;
            println!("Stored {} version {} (configured).", args.name, version);
        }
    }
    Ok(0)
}

fn run_with_profile(args: ProcessArgs) -> Result<i32> {
    let store = Store::open()?;
    let scope = profile_scope(&args.profile);
    let session = store.open_session("human", Some(&scope))?;
    let result = spawn_with_profile(&store, &session, &args.profile, &args.command, false);
    store.close_session(&session)?;
    Ok(exit_code(result?))
}

fn shell(args: ProfileArgs) -> Result<i32> {
    let command = shell_command();
    let store = Store::open()?;
    let scope = profile_scope(&args.profile);
    let session = store.open_session("human", Some(&scope))?;
    let result = spawn_with_profile(&store, &session, &args.profile, &command, true);
    store.close_session(&session)?;
    Ok(exit_code(result?))
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

    let mut command = Command::new(program);
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

    let mut command = Command::new(program);
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
}
