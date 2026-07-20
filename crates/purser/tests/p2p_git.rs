use purser_repo_sync::{bind_git, device_ref_namespace, serve_git_connection, GIT_ALPN};
use purser_store::{Store, SyncProject};
use std::ffi::OsStr;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

struct TestScope {
    name: String,
    database_dir: PathBuf,
}

impl Drop for TestScope {
    fn drop(&mut self) {
        std::env::set_var("PURSER_DEVICE", &self.name);
        let _ = purser_vault::delete_all_keys();
        let _ = fs::remove_dir_all(&self.database_dir);
        std::env::remove_var("PURSER_DEVICE");
    }
}

fn temporary_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("purser-p2p-git-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn git<I, S>(directory: &Path, arguments: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    output
}

fn git_text<I, S>(directory: &Path, arguments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    String::from_utf8(git(directory, arguments).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn commit_all(directory: &Path, message: &str) -> String {
    git(directory, ["add", "."]);
    git(
        directory,
        [
            "-c",
            "user.name=Purser Test",
            "-c",
            "user.email=purser@example.invalid",
            "commit",
            "-m",
            message,
        ],
    );
    git_text(directory, ["rev-parse", "HEAD"])
}

fn run_project_sync(scope: &str, project_id: &str, direct_addr: SocketAddr) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_purser"))
        .args(["project", "sync", project_id, "--from", "source-device"])
        .env("PURSER_DEVICE", scope)
        .env("PURSER_GIT_DIRECT_ADDR", direct_addr.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..600 {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        thread::sleep(Duration::from_millis(100));
    }
    child.kill().unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn real_incremental_git_fetch_preserves_dirty_diverged_receiver() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let local = tokio::task::LocalSet::new();
            tokio::time::timeout(
                Duration::from_secs(120),
                local.run_until(async {
                    let fixture = temporary_directory("integration");
                    let source = fixture.join("source");
                    let receiver = fixture.join("receiver");
                    fs::create_dir_all(&source).unwrap();
                    fs::create_dir_all(&receiver).unwrap();
                    git(&source, ["init", "-b", "main"]);
                    git(&receiver, ["init", "-b", "main"]);
                    fs::write(source.join("base.txt"), b"base\n").unwrap();
                    let first_source_commit = commit_all(&source, "source-a");

                    let scope_name = format!("p2p-git-test-{}", std::process::id());
                    std::env::set_var("PURSER_DEVICE", &scope_name);
                    let database_path = Store::database_path().unwrap();
                    let scope_guard = TestScope {
                        name: scope_name.clone(),
                        database_dir: database_path.parent().unwrap().to_owned(),
                    };
                    let _ = fs::remove_dir_all(&scope_guard.database_dir);

                    let client_key_bytes = purser_vault::device_key().unwrap();
                    let client_key = iroh::SecretKey::from_bytes(&client_key_bytes);
                    let server_key = iroh::SecretKey::generate();
                    let endpoint = bind_git(server_key.clone()).await.unwrap();
                    let direct_port = endpoint
                        .bound_sockets()
                        .into_iter()
                        .find(SocketAddr::is_ipv4)
                        .unwrap()
                        .port();
                    let direct_addr = SocketAddr::from(([127, 0, 0, 1], direct_port));
                    let _ = tokio::time::timeout(Duration::from_secs(15), endpoint.online()).await;

                    let client_store = Store::open().unwrap();
                    client_store
                        .upsert_self_device("receiver-device", client_key.public().as_bytes())
                        .unwrap();
                    client_store
                        .upsert_paired_device("source-device", server_key.public().as_bytes())
                        .unwrap();
                    let project_id = client_store
                        .upsert_project(
                            "example",
                            None,
                            Some("main"),
                            None,
                            None,
                            receiver.to_str().unwrap(),
                        )
                        .unwrap();
                    drop(client_store);

                    let server_database = fixture.join("server.db");
                    let server_store = Store::open_at(&server_database).unwrap();
                    server_store
                        .upsert_self_device("source-device", server_key.public().as_bytes())
                        .unwrap();
                    server_store
                        .upsert_paired_device("receiver-device", client_key.public().as_bytes())
                        .unwrap();
                    server_store
                        .insert_synced_project(&SyncProject {
                            id: &project_id,
                            name: "example",
                            git_remote: None,
                            branch: Some("main"),
                            package_manager: None,
                            profile_ref: None,
                            updated_at: "2026-07-20T00:00:00.000000000Z",
                        })
                        .unwrap();
                    server_store
                        .set_project_local_path(&project_id, source.to_str().unwrap())
                        .unwrap();
                    drop(server_store);

                    let accepting = endpoint.clone();
                    let serving_database = server_database.clone();
                    let server_task = tokio::spawn(async move {
                        for _ in 0..2 {
                            let connection = accepting.accept().await.unwrap().await.unwrap();
                            assert_eq!(connection.alpn(), GIT_ALPN);
                            let store = Store::open_at(&serving_database).unwrap();
                            serve_git_connection(connection, store, Path::new("git"))
                                .await
                                .unwrap();
                        }
                    });

                    let first_project_id = project_id.clone();
                    let first_scope = scope_name.clone();
                    let first = tokio::task::spawn_blocking(move || {
                        run_project_sync(&first_scope, &first_project_id, direct_addr)
                    })
                    .await
                    .unwrap();
                    assert!(
                        first.status.success(),
                        "initial sync failed: {}",
                        String::from_utf8_lossy(&first.stderr)
                    );
                    let first_stdout = String::from_utf8(first.stdout).unwrap();
                    assert!(first_stdout.contains("Branches imported: main"));
                    assert!(first_stdout.contains("main: no local branch"));

                    let namespace =
                        device_ref_namespace("source-device", &server_key.public()).unwrap();
                    let peer_branch = format!("refs/remotes/purser/{namespace}/main");
                    assert_eq!(
                        git_text(&receiver, ["rev-parse", &peer_branch]),
                        first_source_commit
                    );
                    git(&receiver, ["cat-file", "-e", &first_source_commit]);
                    git(&receiver, ["branch", "main", &peer_branch]);
                    git(&receiver, ["checkout", "main"]);

                    fs::write(source.join("base.txt"), b"base\nsource-b\n").unwrap();
                    let second_source_commit = commit_all(&source, "source-b");
                    git(&source, ["tag", "v1"]);

                    fs::write(receiver.join("local.txt"), b"local commit\n").unwrap();
                    let local_commit = commit_all(&receiver, "receiver-c");
                    fs::write(receiver.join("base.txt"), b"dirty receiver bytes\r\n").unwrap();
                    let base_before = fs::read(receiver.join("base.txt")).unwrap();
                    let local_before = fs::read(receiver.join("local.txt")).unwrap();
                    let index_before = fs::read(receiver.join(".git").join("index")).unwrap();
                    let head_before = git_text(&receiver, ["rev-parse", "HEAD"]);
                    assert!(git_text(&receiver, ["remote"]).is_empty());

                    let second_project_id = project_id.clone();
                    let second_scope = scope_name.clone();
                    let second = tokio::task::spawn_blocking(move || {
                        run_project_sync(&second_scope, &second_project_id, direct_addr)
                    })
                    .await
                    .unwrap();
                    assert!(
                        second.status.success(),
                        "incremental sync failed: {}",
                        String::from_utf8_lossy(&second.stderr)
                    );
                    let second_stdout = String::from_utf8(second.stdout).unwrap();
                    assert!(second_stdout.contains("Branches imported: main"));
                    assert!(second_stdout.contains("Tags imported: v1"));
                    assert!(second_stdout.contains("main: diverged"));
                    assert!(second_stdout.contains("Working tree dirty before fetch: yes"));
                    assert!(second_stdout.contains(
                        "No local branch, HEAD, index, or working-tree file was changed."
                    ));

                    assert_eq!(
                        git_text(&receiver, ["rev-parse", &peer_branch]),
                        second_source_commit
                    );
                    assert_eq!(
                        git_text(
                            &receiver,
                            [
                                "rev-parse",
                                &format!("refs/purser/{namespace}/tags/v1^{{commit}}")
                            ]
                        ),
                        second_source_commit
                    );
                    assert_eq!(git_text(&receiver, ["rev-parse", "main"]), local_commit);
                    assert_eq!(git_text(&receiver, ["rev-parse", "HEAD"]), head_before);
                    assert_eq!(fs::read(receiver.join("base.txt")).unwrap(), base_before);
                    assert_eq!(fs::read(receiver.join("local.txt")).unwrap(), local_before);
                    assert_eq!(
                        fs::read(receiver.join(".git").join("index")).unwrap(),
                        index_before
                    );
                    assert!(
                        Command::new("git")
                            .arg("-C")
                            .arg(&receiver)
                            .args(["show-ref", "--verify", "--quiet", "refs/tags/v1"])
                            .status()
                            .unwrap()
                            .code()
                            != Some(0),
                        "ordinary local tag namespace was modified"
                    );
                    git(&receiver, ["cat-file", "-e", &second_source_commit]);
                    assert!(git_text(&receiver, ["remote"]).is_empty());

                    server_task.await.unwrap();
                    endpoint.close().await;
                    drop(scope_guard);
                    fs::remove_dir_all(fixture).unwrap();
                }),
            )
            .await
            .expect("real Git integration test timed out");
        });
}
