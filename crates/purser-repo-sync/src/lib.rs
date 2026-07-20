//! Read-only Git transport over authenticated iroh QUIC connections.
//!
//! Git owns negotiation, object storage, pack generation, and delta compression. This crate
//! only authorizes an opaque project identity, starts a constrained `git upload-pack`, and
//! streams its full-duplex protocol without buffering pack data.

use anyhow::{anyhow, bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, SecretKey};
use purser_store::Store;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub const GIT_ALPN: &[u8] = b"purser/git/1";
pub const GIT_UPLOAD_PACK: &str = "git-upload-pack";
pub const GIT_PROTOCOL_V2: &str = "version=2";
pub const GIT_PROTOCOL_V0: &str = "version=0";

const REQUEST_MAGIC: &[u8; 8] = b"PURGIT1\0";
const MAX_REQUEST_BYTES: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_ACCEPTED: u8 = 0;
const RESPONSE_REFUSED: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRequest {
    pub project_id: String,
    pub service: String,
    pub git_protocol: String,
}

impl GitRequest {
    pub fn upload_pack(project_id: impl Into<String>) -> Result<Self> {
        Self::upload_pack_with_protocol(project_id, GIT_PROTOCOL_V2)
    }

    pub fn upload_pack_with_protocol(
        project_id: impl Into<String>,
        git_protocol: &str,
    ) -> Result<Self> {
        let request = Self {
            project_id: project_id.into(),
            service: GIT_UPLOAD_PACK.to_owned(),
            git_protocol: git_protocol.to_owned(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        validate_project_id(&self.project_id)?;
        if self.service != GIT_UPLOAD_PACK {
            bail!("unsupported Git service");
        }
        if !matches!(
            self.git_protocol.as_str(),
            GIT_PROTOCOL_V0 | GIT_PROTOCOL_V2
        ) {
            bail!("unsupported Git protocol version");
        }
        Ok(())
    }
}

pub fn validate_project_id(value: &str) -> Result<()> {
    if value.len() != 26 || ulid::Ulid::from_string(value).is_err() {
        bail!("project ID must be a canonical ULID");
    }
    Ok(())
}

pub fn encode_request(request: &GitRequest) -> Result<Vec<u8>> {
    request.validate()?;
    let mut payload = Vec::new();
    payload.extend_from_slice(REQUEST_MAGIC);
    write_field(&mut payload, request.project_id.as_bytes())?;
    write_field(&mut payload, request.service.as_bytes())?;
    write_field(&mut payload, request.git_protocol.as_bytes())?;
    if payload.len() > MAX_REQUEST_BYTES {
        bail!("Git request exceeds the protocol limit");
    }
    let length = u16::try_from(payload.len()).expect("bounded request fits in u16");
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_request(frame: &[u8]) -> Result<GitRequest> {
    if frame.len() < 2 {
        bail!("Git request is truncated");
    }
    let declared = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
    if declared > MAX_REQUEST_BYTES {
        bail!("Git request exceeds the protocol limit");
    }
    if frame.len() != declared + 2 {
        bail!("Git request length is invalid");
    }
    decode_payload(&frame[2..])
}

fn decode_payload(payload: &[u8]) -> Result<GitRequest> {
    let mut cursor = 0;
    if take(payload, &mut cursor, REQUEST_MAGIC.len())? != REQUEST_MAGIC {
        bail!("Git request has an invalid format");
    }
    let request = GitRequest {
        project_id: read_field(payload, &mut cursor)?,
        service: read_field(payload, &mut cursor)?,
        git_protocol: read_field(payload, &mut cursor)?,
    };
    if cursor != payload.len() {
        bail!("Git request has trailing bytes");
    }
    request.validate()?;
    Ok(request)
}

fn write_field(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u16::try_from(bytes.len()).context("Git request field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_field(encoded: &[u8], cursor: &mut usize) -> Result<String> {
    let length = take(encoded, cursor, 2)?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let bytes = take(encoded, cursor, length)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| anyhow!("Git request field is not UTF-8"))
}

fn take<'a>(encoded: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| anyhow!("Git request length overflow"))?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("Git request is truncated"))?;
    *cursor = end;
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    pub peer: EndpointId,
    pub project_id: String,
}

pub fn parse_remote_url(url: &str) -> Result<RemoteTarget> {
    let rest = url
        .strip_prefix("purser::")
        .ok_or_else(|| anyhow!("Purser Git URL must start with purser::"))?;
    let (peer, project_id) = rest
        .split_once('/')
        .ok_or_else(|| anyhow!("Purser Git URL must contain a peer and project ID"))?;
    if peer.is_empty() || project_id.is_empty() || project_id.contains('/') {
        bail!("Purser Git URL has an invalid shape");
    }
    let peer = peer
        .parse()
        .context("Purser Git URL has an invalid peer key")?;
    validate_project_id(project_id)?;
    Ok(RemoteTarget {
        peer,
        project_id: project_id.to_owned(),
    })
}

/// Produce one safe, stable Git ref component from a human label and authenticated key.
pub fn device_ref_namespace(label: &str, peer: &EndpointId) -> Result<String> {
    let mut output = String::new();
    let mut separator = false;
    for character in label.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
            output.push(character.to_ascii_lowercase());
            separator = false;
        } else if !output.is_empty() && !separator {
            output.push('-');
            separator = true;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        output.push_str("device");
    }
    if output == "." || output == ".." || output.ends_with(".lock") {
        bail!("device label cannot form a safe Git ref namespace");
    }
    output.push('-');
    output.extend(peer.to_string().chars().take(12));
    if output.len() > 128 {
        output.truncate(128);
    }
    Ok(output)
}

pub async fn bind_git(secret_key: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![GIT_ALPN.to_vec()])
        .bind()
        .await
        .context("could not bind the iroh Git endpoint")
}

pub async fn bind_with_alpns(secret_key: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(alpns)
        .bind()
        .await
        .context("could not bind the iroh service endpoint")
}

pub struct GitClientStream {
    connection: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

pub async fn connect_git(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    request: &GitRequest,
) -> Result<GitClientStream> {
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(peer, GIT_ALPN))
        .await
        .context("timed out connecting to the Purser Git peer")??;
    let (mut send, mut recv) = tokio::time::timeout(STREAM_TIMEOUT, connection.open_bi())
        .await
        .context("timed out opening the Purser Git stream")??;
    let frame = encode_request(request)?;
    tokio::time::timeout(STREAM_TIMEOUT, send.write_all(&frame))
        .await
        .context("timed out sending the Purser Git request")??;
    let mut response = [0_u8; 1];
    tokio::time::timeout(STREAM_TIMEOUT, recv.read_exact(&mut response))
        .await
        .context("timed out waiting for the Purser Git response")??;
    if response[0] != RESPONSE_ACCEPTED {
        bail!("peer refused the Git service request");
    }
    Ok(GitClientStream {
        connection,
        send,
        recv,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferMetrics {
    pub bytes_to_upload_pack: u64,
    pub bytes_from_upload_pack: u64,
}

impl GitClientStream {
    pub async fn proxy<R, W>(mut self, input: &mut R, output: &mut W) -> Result<TransferMetrics>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut counted_input = CountingReader::new(input);
        let mut to_peer = Box::pin(tokio::io::copy(&mut counted_input, &mut self.send));
        let mut from_peer = Box::pin(tokio::io::copy(&mut self.recv, output));

        // Git keeps the helper's stdin open while it waits for the helper to exit. The
        // upload-pack side closing output is therefore also an end-of-service signal; do
        // not wait for an EOF Git sends only after this process exits.
        enum FirstFinished {
            FromPeer(u64),
            ToPeer,
        }
        let first = tokio::select! {
            result = &mut from_peer => FirstFinished::FromPeer(result?),
            result = &mut to_peer => {
                result?;
                FirstFinished::ToPeer
            }
        };
        let bytes_from_upload_pack = match first {
            FirstFinished::FromPeer(bytes) => {
                drop(to_peer);
                drop(from_peer);
                self.send.finish()?;
                bytes
            }
            FirstFinished::ToPeer => {
                drop(to_peer);
                self.send.finish()?;
                from_peer.await?
            }
        };
        output.flush().await?;
        let bytes_to_upload_pack = counted_input.bytes_read;
        self.connection.close(0_u8.into(), b"Git fetch complete");
        Ok(TransferMetrics {
            bytes_to_upload_pack,
            bytes_from_upload_pack,
        })
    }
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.bytes_read += (buffer.filled().len() - before) as u64;
        }
        result
    }
}

pub enum Authorization {
    Authorized { peer_label: String },
    Refused,
}

pub fn authorize_peer(store: &Store, peer: EndpointId) -> Result<Authorization> {
    Ok(match store.find_device_by_public_key(peer.as_bytes())? {
        Some(device) if !device.is_self && !device.revoked => Authorization::Authorized {
            peer_label: device.label,
        },
        _ => Authorization::Refused,
    })
}

/// Serve one already-handshaken Git connection.
///
/// SECURITY BOUNDARY: the endpoint identity is authorized before any stream is accepted or
/// application byte is written. The bounded request then supplies only an opaque ULID and a
/// fixed service name; the local Store alone chooses the filesystem path and upload-pack gets
/// no peer-controlled argument.
pub async fn serve_git_connection(
    connection: iroh::endpoint::Connection,
    store: Store,
    git_executable: &Path,
) -> Result<TransferMetrics> {
    let peer = connection.remote_id();
    if matches!(authorize_peer(&store, peer)?, Authorization::Refused) {
        connection.close(0_u8.into(), b"Git service refused");
        bail!("Git peer is not authorized");
    }

    let (mut send, mut recv) = tokio::time::timeout(STREAM_TIMEOUT, connection.accept_bi())
        .await
        .context("timed out waiting for a Git request stream")??;
    let request = match read_request(&mut recv).await {
        Ok(request) => request,
        Err(error) => {
            refuse_stream(&mut send).await;
            return Err(error);
        }
    };
    let project_path = match resolve_registered_path(&store, &request.project_id) {
        Ok(path) => path,
        Err(error) => {
            refuse_stream(&mut send).await;
            return Err(error);
        }
    };
    drop(store);
    let git_directory = match validate_repository_path(&project_path, git_executable).await {
        Ok(path) => path,
        Err(error) => {
            refuse_stream(&mut send).await;
            return Err(error);
        }
    };

    // SECURITY BOUNDARY: upload-pack is spawned only after peer, request, project identity,
    // registered local projection, and Git repository validation have all succeeded.
    let mut command = tokio::process::Command::new(git_executable);
    command
        .arg("upload-pack")
        .arg("--strict")
        .arg(&git_directory)
        .env("GIT_NO_LAZY_FETCH", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if request.git_protocol == GIT_PROTOCOL_V2 {
        command.env("GIT_PROTOCOL", GIT_PROTOCOL_V2);
    } else {
        command.env_remove("GIT_PROTOCOL");
    }
    let mut child = command
        .spawn()
        .context("could not start the local Git service")?;
    let mut child_stdin = child.stdin.take().expect("piped child stdin");
    let mut child_stdout = child.stdout.take().expect("piped child stdout");
    send.write_all(&[RESPONSE_ACCEPTED]).await?;

    let mut counted_recv = CountingReader::new(&mut recv);
    let mut to_upload_pack = Box::pin(tokio::io::copy(&mut counted_recv, &mut child_stdin));
    let mut from_upload_pack = Box::pin(async {
        let bytes = tokio::io::copy(&mut child_stdout, &mut send).await?;
        send.finish()?;
        anyhow::Ok(bytes)
    });
    enum FirstFinished {
        FromUploadPack(u64),
        ToUploadPack,
    }
    let first = tokio::select! {
        result = &mut from_upload_pack => FirstFinished::FromUploadPack(result?),
        result = &mut to_upload_pack => {
            result?;
            FirstFinished::ToUploadPack
        }
    };
    let bytes_from_upload_pack = match first {
        FirstFinished::FromUploadPack(bytes) => {
            drop(to_upload_pack);
            drop(from_upload_pack);
            child_stdin.shutdown().await?;
            bytes
        }
        FirstFinished::ToUploadPack => {
            drop(to_upload_pack);
            child_stdin.shutdown().await?;
            from_upload_pack.await?
        }
    };
    let bytes_to_upload_pack = counted_recv.bytes_read;
    let status = child
        .wait()
        .await
        .context("could not wait for Git upload-pack")?;
    if !status.success() {
        bail!("local Git service failed");
    }
    Ok(TransferMetrics {
        bytes_to_upload_pack,
        bytes_from_upload_pack,
    })
}

async fn read_request(recv: &mut iroh::endpoint::RecvStream) -> Result<GitRequest> {
    let mut length = [0_u8; 2];
    tokio::time::timeout(STREAM_TIMEOUT, recv.read_exact(&mut length))
        .await
        .context("timed out reading the Git request length")??;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_REQUEST_BYTES {
        bail!("Git request exceeds the protocol limit");
    }
    let mut payload = vec![0_u8; length];
    tokio::time::timeout(STREAM_TIMEOUT, recv.read_exact(&mut payload))
        .await
        .context("timed out reading the Git request")??;
    decode_payload(&payload)
}

async fn refuse_stream(send: &mut iroh::endpoint::SendStream) {
    let _ = send.write_all(&[RESPONSE_REFUSED]).await;
    let _ = send.finish();
}

fn resolve_registered_path(store: &Store, project_id: &str) -> Result<PathBuf> {
    let project = store
        .find_project_by_id(project_id)?
        .ok_or_else(|| anyhow!("Git project is unavailable"))?;
    let path = project
        .local_path
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("Git project is unavailable"))?;
    if !path.is_dir() {
        bail!("Git project is unavailable");
    }
    Ok(path)
}

async fn validate_repository_path(path: &Path, git: &Path) -> Result<PathBuf> {
    let output = tokio::process::Command::new(git)
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--absolute-git-dir"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .context("could not validate the local Git repository")?;
    if !output.status.success() {
        bail!("Git project is unavailable");
    }
    let path =
        String::from_utf8(output.stdout).map_err(|_| anyhow!("Git project is unavailable"))?;
    let path = PathBuf::from(path.trim());
    if !path.is_dir() {
        bail!("Git project is unavailable");
    }
    Ok(path)
}

#[cfg(test)]
async fn resolve_repository(store: &Store, project_id: &str, git: &Path) -> Result<PathBuf> {
    let path = resolve_registered_path(store, project_id)?;
    let _ = validate_repository_path(&path, git).await?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purser_store::SyncProject;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn valid_id() -> String {
        ulid::Ulid::new().to_string()
    }

    fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        let port = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 test socket")
            .port();
        EndpointAddr::new(endpoint.id()).with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "purser-repo-sync-{label}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn valid_project_request_round_trips() {
        let request = GitRequest::upload_pack(valid_id()).unwrap();
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn oversized_and_malformed_requests_are_rejected() {
        assert!(decode_request(&[0, 5, 1, 2]).is_err());
        let oversized = [2_u8, 1];
        assert!(decode_request(&oversized).is_err());
        let mut trailing = encode_request(&GitRequest::upload_pack(valid_id()).unwrap()).unwrap();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn unknown_service_is_rejected() {
        let request = GitRequest {
            project_id: valid_id(),
            service: "git-receive-pack".to_owned(),
            git_protocol: GIT_PROTOCOL_V2.to_owned(),
        };
        assert!(encode_request(&request).is_err());
    }

    #[test]
    fn invalid_project_id_is_rejected() {
        assert!(GitRequest::upload_pack("../private/repository").is_err());
    }

    #[test]
    fn remote_helper_url_parsing_is_strict() {
        let key = SecretKey::generate().public();
        let id = valid_id();
        let parsed = parse_remote_url(&format!("purser::{key}/{id}")).unwrap();
        assert_eq!(parsed.peer, key);
        assert_eq!(parsed.project_id, id);
        assert!(parse_remote_url(&format!("file::{key}/{}", valid_id())).is_err());
        assert!(parse_remote_url(&format!("purser::{key}/../repo")).is_err());
    }

    #[test]
    fn device_namespace_is_safe_and_key_disambiguated() {
        let key = SecretKey::generate().public();
        let namespace = device_ref_namespace("Mac Book/Work..lock", &key).unwrap();
        assert!(namespace.starts_with("mac-book-work-lock-"));
        assert!(!namespace.contains('/'));
        assert!(!namespace.contains(".."));
    }

    #[test]
    fn repository_resolution_refuses_unknown_pathless_and_non_git_projects() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let store = Store::open_in_memory().unwrap();
                assert!(resolve_repository(&store, &valid_id(), Path::new("git"))
                    .await
                    .is_err());

                let pathless_id = valid_id();
                store
                    .insert_synced_project(&SyncProject {
                        id: &pathless_id,
                        name: "pathless",
                        git_remote: None,
                        branch: None,
                        package_manager: None,
                        profile_ref: None,
                        updated_at: "2026-07-20T00:00:00.000000000Z",
                    })
                    .unwrap();
                assert!(resolve_repository(&store, &pathless_id, Path::new("git"))
                    .await
                    .is_err());

                let directory = temporary_directory("non-git");
                let non_git_id = store
                    .upsert_project(
                        "non-git",
                        None,
                        None,
                        None,
                        None,
                        directory.to_str().unwrap(),
                    )
                    .unwrap();
                assert!(resolve_repository(&store, &non_git_id, Path::new("git"))
                    .await
                    .is_err());
                std::fs::remove_dir_all(directory).unwrap();
            });
    }

    fn unauthorized_peer_receives_no_application_bytes(revoked: bool) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(30), async {
                    let server = bind_git(SecretKey::generate()).await.unwrap();
                    let server_addr = direct_addr(&server);
                    let client_key = SecretKey::generate();
                    let store = Store::open_in_memory().unwrap();
                    if revoked {
                        store
                            .upsert_paired_device("revoked", client_key.public().as_bytes())
                            .unwrap();
                        store.revoke_peer_by_label("revoked").unwrap();
                    }

                    let server_side = async {
                        let connection = server.accept().await.unwrap().await.unwrap();
                        serve_git_connection(connection, store, Path::new("git")).await
                    };
                    let client_side = async {
                        let client = bind_git(client_key).await.unwrap();
                        let connection = client.connect(server_addr, GIT_ALPN).await.unwrap();
                        let (mut send, mut recv) = connection.open_bi().await.unwrap();
                        let request = GitRequest::upload_pack(valid_id()).unwrap();
                        let _ = send.write_all(&encode_request(&request).unwrap()).await;
                        let received = recv.read_to_end(MAX_REQUEST_BYTES).await;
                        client.close().await;
                        received
                    };
                    let (served, received) = tokio::join!(server_side, client_side);
                    assert!(served.is_err());
                    assert!(
                        received.is_err() || received.as_ref().is_ok_and(Vec::is_empty),
                        "unauthorized peer received Git advertisement or pack bytes"
                    );
                    server.close().await;
                })
                .await
                .expect("authorization test timed out");
            });
    }

    #[test]
    fn unpaired_peer_receives_no_git_data() {
        unauthorized_peer_receives_no_application_bytes(false);
    }

    #[test]
    fn revoked_peer_receives_no_git_data() {
        unauthorized_peer_receives_no_application_bytes(true);
    }
}
