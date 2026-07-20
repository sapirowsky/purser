use anyhow::{bail, Context, Result};
use purser_repo_sync::{
    bind_git, connect_git, parse_remote_url, GitRequest, GIT_PROTOCOL_V0, GIT_PROTOCOL_V2,
    GIT_UPLOAD_PACK,
};
use purser_store::Store;
use std::io::{BufRead, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, ReadBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("git-remote-purser: {error:#}");
        std::process::exit(1);
    }
}

struct ChannelStdin {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    offset: usize,
}

impl AsyncRead for ChannelStdin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.offset < self.chunk.len() {
                let count = output
                    .remaining()
                    .min(self.chunk.len().saturating_sub(self.offset));
                output.put_slice(&self.chunk[self.offset..self.offset + count]);
                self.offset += count;
                return Poll::Ready(Ok(()));
            }
            match self.receiver.poll_recv(context) {
                Poll::Ready(Some(chunk)) => {
                    self.chunk = chunk;
                    self.offset = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn channel_stdin() -> ChannelStdin {
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut chunk = vec![0_u8; 64 * 1024];
            match input.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    chunk.truncate(count);
                    if sender.blocking_send(chunk).is_err() {
                        break;
                    }
                }
            }
        }
    });
    ChannelStdin {
        receiver,
        chunk: Vec::new(),
        offset: 0,
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let _remote_name = arguments
        .next()
        .context("Git did not provide a remote name")?;
    let url = arguments
        .next()
        .context("Git did not provide a Purser URL")?;
    if arguments.next().is_some() {
        bail!("unexpected remote-helper arguments");
    }
    let url = url.to_str().context("Purser Git URL must be valid UTF-8")?;
    // For `transport::address`, Git passes only `address` as argv[2]. Keep the public URL
    // parser strict, and restore the transport prefix at this process boundary.
    let normalized_url;
    let url = if url.starts_with("purser::") {
        url
    } else {
        normalized_url = format!("purser::{url}");
        &normalized_url
    };
    let target = parse_remote_url(url)?;

    // The helper is independently fail-closed. The higher-level Purser command already
    // resolves labels and rejects self/revoked peers, but ordinary `git fetch purser::...`
    // must not bypass that local pairing policy.
    let device = Store::open()?
        .find_device_by_public_key(target.peer.as_bytes())?
        .filter(|device| !device.is_self && !device.revoked)
        .context("target is not a paired, non-revoked device")?;

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout().lock();
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("could not read the remote-helper capability request")?;
    if line.trim_end() != "capabilities" {
        bail!("Git did not request remote-helper capabilities");
    }
    stdout.write_all(b"connect\n\n")?;
    stdout.flush()?;

    line.clear();
    reader
        .read_line(&mut line)
        .context("could not read the remote-helper connect request")?;
    let service = line
        .trim_end()
        .strip_prefix("connect ")
        .context("unsupported remote-helper command")?;
    if service != GIT_UPLOAD_PACK {
        bail!("only git-upload-pack is supported");
    }
    drop(reader);

    let key_bytes = purser_vault::device_key()?;
    let key = iroh::SecretKey::from_bytes(&key_bytes);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the Purser Git networking runtime")?;
    runtime
        .block_on(async move {
            let endpoint = bind_git(key).await?;
            let git_protocol = match std::env::var("GIT_PROTOCOL") {
                Ok(value) if value == GIT_PROTOCOL_V2 => GIT_PROTOCOL_V2,
                Err(std::env::VarError::NotPresent) => GIT_PROTOCOL_V0,
                Ok(_) => bail!("Git requested an unsupported protocol version"),
                Err(std::env::VarError::NotUnicode(_)) => {
                    bail!("Git requested an invalid protocol version")
                }
            };
            let request = GitRequest::upload_pack_with_protocol(target.project_id, git_protocol)?;
            // A direct address is only a routing hint. The URL's public key remains the
            // authenticated identity, so the hint cannot impersonate another peer.
            let peer_addr = match std::env::var("PURSER_GIT_DIRECT_ADDR") {
                Ok(address) => {
                    let address: SocketAddr = address
                        .parse()
                        .context("PURSER_GIT_DIRECT_ADDR is not a socket address")?;
                    iroh::EndpointAddr::new(target.peer).with_ip_addr(address)
                }
                Err(std::env::VarError::NotPresent) => iroh::EndpointAddr::new(target.peer),
                Err(std::env::VarError::NotUnicode(_)) => {
                    bail!("PURSER_GIT_DIRECT_ADDR is not valid Unicode")
                }
            };
            let stream = connect_git(&endpoint, peer_addr, &request).await?;

            // A blank line is the remote-helper success response. From the next byte onward,
            // stdout is exclusively Git protocol data and every diagnostic stays on stderr.
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            drop(stdout);

            // Tokio's global async stdin uses an uncancellable blocking read. Git keeps the
            // helper pipe open until the helper exits, so that adapter deadlocks runtime
            // shutdown. A detached bounded-channel reader lets process exit end the thread.
            let mut input = channel_stdin();
            let mut output = tokio::io::stdout();
            let _metrics = stream.proxy(&mut input, &mut output).await?;
            endpoint.close().await;
            anyhow::Ok(())
        })
        .with_context(|| format!("Git fetch from device {:?} failed", device.label))
}
