//! Purser command-line interface for the local, single-machine vault.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use purser_store::{AuditEvent, Project, Store};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
    /// Register and inspect project metadata.
    Project(ProjectArgs),
    /// Show registered projects and secret configuration status.
    Status,
    /// Clone missing projects and install their dependencies.
    Up(UpArgs),
    /// Print shell wrappers for transparent per-project execution.
    Hook(HookArgs),
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

#[derive(Debug, Args)]
struct UpArgs {
    #[arg(long)]
    dry_run: bool,
    /// WARNING: materialize vault secrets into missing project .env files.
    #[arg(long)]
    write_env: bool,
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
        TopCommand::Project(args) => project(args),
        TopCommand::Status => status(),
        TopCommand::Up(args) => up(args),
        TopCommand::Hook(args) => hook(args),
        TopCommand::InProject => in_project(),
    }
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

fn up(args: UpArgs) -> Result<i32> {
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
        match bring_up_project(project, args.dry_run) {
            Ok(actions) if actions.is_empty() => println!("  nothing to do"),
            Ok(actions) => {
                let prefix = if args.dry_run { "would" } else { "done" };
                for action in actions {
                    println!("  {prefix} {action}");
                }
            }
            // One project failing must not stop the rest of the machine coming up.
            Err(error) => {
                println!("  FAILED: {error:#}");
                failed = true;
            }
        }
        if args.write_env && project.profile_ref.is_some() {
            match materialize_project_dotenv(&store, project, args.dry_run) {
                Ok(DotenvMaterialization::Written(variable_count)) => println!(
                    "  WARNING: wrote {variable_count} variables to {}",
                    project_dotenv_path(project)?.display()
                ),
                Ok(DotenvMaterialization::WouldWrite(variable_count)) => println!(
                    "  WARNING: would write {variable_count} variables to {}",
                    project_dotenv_path(project)?.display()
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
        report_profile_status(&store, project)?;
    }
    if failures.is_empty() {
        Ok(0)
    } else {
        eprintln!("Failed projects: {}", failures.join(", "));
        Ok(1)
    }
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

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = match options.open(&dotenv_path) {
        Ok(file) => file,
        // `create_new` is what actually enforces "never overwrite": the earlier exists()
        // check is only for reporting, and something may have created the file since.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(DotenvMaterialization::Skipped(
                "one appeared while purser was running",
            ));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not create {}", dotenv_path.display()));
        }
    };
    file.write_all(contents.as_bytes())
        .with_context(|| format!("could not write {}", dotenv_path.display()))?;
    contents.zeroize();
    for (_, plaintext) in &mut plaintexts {
        plaintext.zeroize();
    }
    for (name, _) in &plaintexts {
        store.append_audit_event(None, "env_written", Some(name), "used")?;
    }

    Ok(DotenvMaterialization::Written(plaintexts.len()))
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

    if !path.exists() {
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
            run_command(
                Command::new("git").arg("clone").arg(git_remote).arg(path),
                "git clone",
            )?;
        }
        if let Some(branch) = project.branch.as_deref() {
            actions.push(format!("check out {branch}"));
            if !dry_run {
                run_command(
                    Command::new("git")
                        .arg("-C")
                        .arg(path)
                        .arg("checkout")
                        .arg(branch),
                    "git checkout",
                )?;
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
    let output = Command::new("git")
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
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

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
}
