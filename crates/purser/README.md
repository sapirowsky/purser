# purser 🦀

One command sets up any of your machines — clone every repo, rehydrate deps, inject env —
and secret values sync peer-to-peer between your devices while staying invisible to AI agents.

Built with Rust. Rust good.

> **Status: early scaffold.** Commands are not implemented yet. This release exists to hold
> the name and establish the workspace. See the repository for the design and roadmap.

```
purser up                 # reproduce this machine (clone, install, inject env)
purser agent -- claude    # run an agent that can't see secret values
purser run -- npm test    # run with secrets injected in memory only
```

No plaintext `.env` on disk. No hosted server. Committed code still travels through git.

License: MIT
