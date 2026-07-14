---
title: "Purser OSS landscape and positioning"
status: "research note"
created: "2026-07-14"
relates_to: ".plans/purser_v4_plan.md"
one_line: "Purser is not a unique secret manager; its credible OSS opportunity is an integrated, agent-safer developer-workstation bootstrap."
---

# Purser OSS landscape and positioning

## Question

Does something like the current Purser plan already exist, and does Purser make sense as
an open-source project for developers beyond its owner?

Research and repository inspection were performed on 2026-07-14. Product descriptions in
this note reflect what their maintainers claimed publicly on that date; they are not security
audits or endorsements.

## Short answer

Yes, most individual parts of Purser already exist, and the secrets portion is increasingly
crowded:

- P2P secret synchronization already exists.
- Runtime secret injection without a plaintext `.env` already exists.
- Products specifically marketed as letting coding agents use secrets without seeing them
  already exist.
- Repository cloning and reproducible development environments already exist as separate,
  mature categories.

No mature project was found that clearly combines all of the following into one opinionated
personal workflow:

1. A manifest of all of a developer's projects.
2. Cross-platform cloning and dependency rehydration.
3. Local-first or P2P secret replication between the developer's own devices.
4. An agent-specific execution boundary with value-blind metadata and audit receipts.
5. A one-command experience spanning Windows, WSL, Linux, and macOS.

Therefore:

> Purser makes sense as a personal tool immediately. It can make sense as OSS if it is
> positioned as an agent-safer developer-workstation bootstrap. It is not differentiated
> enough if positioned primarily as another P2P or "AI-proof" secret manager.

The strongest product sentence is:

> `purser up` turns a fresh Windows, WSL, Linux, or macOS installation into your coding
> machine -- repos, dependencies, and agent-safer runtime configuration included.

## Category map

Purser currently bundles three product categories:

```text
developer bootstrap       project manifest, clone, install/rehydrate, status
secret distribution       encrypted local vault, versions, P2P replication, pairing
agent secret broker       sanitized agent launch, scoped injection, metadata, audit
```

Each row already has competitors. The possible differentiation is the integration and its
cross-platform daily ergonomics, not a novel primitive in any single row.

## Closest products

### env-sync

Links: <https://envsync.arnav.tech/> and
<https://github.com/championswimmer/env.sync.local>

This is a real and close competitor to Purser's device-sync half. Its public repository had
roughly 41 stars, 306 commits, 11 releases, and a latest release dated 2026-03-10 when
checked.

Overlap:

- P2P/distributed synchronization of environment secrets.
- No mandatory central cloud service.
- Linux, macOS, and WSL2 support.
- Peer discovery and approval modes.
- Encrypted-at-rest option using age.
- Per-key timestamps, merge behavior, and backups of old values.
- Background service or periodic synchronization.

Differences and openings for Purser:

- Its trusted-owner default can store plaintext and uses SSH/SCP.
- It remains dotenv/file and shell oriented; `eval "$(env-sync load)"` puts secrets into an
  interactive shell and therefore does not create a coding-agent boundary.
- It does not reproduce a developer's repositories and dependencies.
- It does not offer Purser's proposed metadata-only MCP surface or command-scoped audit
  receipts.

Conclusion: P2P secret sync alone is not Purser's novelty.

### envctl

Link: <https://envctl.dev/>

The site claims almost the whole secret half of Purser:

- "Git for your secrets" positioning.
- No plaintext `.env` files.
- Process-level runtime injection.
- P2P sync across the internet.
- Optional relay for asynchronous/offline delivery.
- Cryptographically signed audit history.
- Environment/branch-like workflows.
- Linux, macOS, and Windows binaries.
- Free/open-source CLI with a paid relay as the monetization layer.

This directly overlaps both Purser's product language and its proposed open-core seam.
However, the site's linked `github.com/uradical/envctl` repository and latest-release URL
returned 404 when checked. Treat it as strong evidence that the idea and positioning already
exist, but not yet as evidence of a mature, inspectable OSS implementation.

Conclusion: even Purser's proposed "free P2P core, paid relay" business story is not unique.

### Keyway

Links: <https://keyway.sh/> and <https://github.com/keywaysh/keyway>

Keyway explicitly markets open-source, AI-safe secret management:

- No `.env` on disk.
- `keyway run -- ...` runtime injection.
- MCP integration for assistants.
- Scoped access and an audit trail.
- GitHub-native authorization.
- Self-hosting support.

Its public repository had roughly 4 stars and no published releases when checked, although
it contained a substantial multi-package implementation and hundreds of commits.

Differences and openings for Purser:

- Keyway is GitHub/team/server centered rather than personal P2P.
- Self-hosting involves a backend, database, dashboard, crypto service, and GitHub App.
- It does not attempt whole-workstation project bootstrap.

Conclusion: runtime injection plus MCP plus "AI-safe" is already an occupied product claim.

### Cloak

Link: <https://getcloak.dev/>

Cloak is an especially close local secret competitor:

- Written in Rust.
- Keys stored in macOS Keychain, libsecret, or Windows Credential Manager.
- No real secret values in a readable project `.env`.
- `cloak run` injects real values into a child process.
- Sandbox values remain available to tools and agents.
- TTY/biometric/password approval gates.
- VS Code/Cursor integration.
- No hosted account and effectively no network use.
- A skill file tells coding agents how to cooperate with the workflow.

Differences and openings for Purser:

- Cloak deliberately has no network sync.
- It protects one project's dotenv workflow rather than reproducing a workstation.
- Its safety depends partly on human-only authentication and sandbox values; Purser proposes
  a daemon, metadata-only MCP, and receipts.

Conclusion: a local Rust vault using OS keyrings and runtime injection is not differentiated.

### Agent Secret

Links: <https://agent-secret.sh/> and
<https://github.com/kovyrin/agent-secret>

Agent Secret is a strong reference for an honest agent-broker boundary. Its public repository
had roughly 15 stars and 636 commits when checked.

Overlap:

- Agents request exact secret references rather than raw values.
- A native approval prompt shows command, reason, working directory, and requested refs.
- Approved values are injected only into a child process.
- Audit data records metadata, not values.
- Sessions are bounded by command/process ancestry, directory, TTL, and read count.
- The project explicitly says it is an approval broker, not a sandbox.

Differences and openings for Purser:

- macOS/Apple Silicon only.
- Depends on 1Password or Bitwarden Secrets Manager for custody.
- Does not write/update secrets or synchronize devices itself.
- Does not bootstrap projects or dependencies.

Conclusion: command-scoped grants and honest threat-model wording should inform Purser. A
cross-platform equivalent integrated with bootstrap would still be valuable.

### kovra and other agent-secret tools

Link: <https://kovra.sh/>

kovra also claims an encrypted local vault, biometric authorization, MCP metadata, process
injection, and values that never enter model context. Other products and small OSS projects
found in the same space included secr, Klavex, Keyway, Cloak, LLM Secrets/scrt4, psst, and
secret-shuttle. Their maturity and exact guarantees vary, but collectively they show that
"agents use secrets without seeing them" became a recognizable category rather than an
unclaimed niche.

## Adjacent bootstrap tools

### ghorg

Link: <https://github.com/gabrie30/ghorg>

ghorg is a mature multi-forge repository cloning tool, with roughly 2,100 stars and 1,000
commits when checked. It supports GitHub, GitLab, Bitbucket, Gitea/Forgejo, Codeberg, and
SourceHut, including explicit repository lists and onboarding use cases.

It proves that "clone all or a selected set of repositories" is useful, but it does not
rehydrate dependencies or provide a secret broker. Purser should learn from its provider
coverage, filters, dry-run expectations, and dangerous-clean warning.

### chezmoi

Link: <https://github.com/twpayne/chezmoi>

chezmoi is a mature cross-platform dotfile and machine-configuration manager, with roughly
20,000 stars when checked. It can securely template configuration, integrate with password
managers, install packages through scripts, and bootstrap a fresh machine.

Many developers can approximate Purser by combining chezmoi, encrypted files or a password
manager, package manifests, and custom clone scripts. The weakness is assembly burden rather
than missing capability.

### mise, Devbox, Nix/Home Manager, devcontainers

Links: <https://mise.jdx.dev/> and <https://www.jetify.com/devbox>

These tools cover reproducible toolchains, task execution, packages, and isolated development
environments. They are not direct Purser replacements, but Purser should interoperate with
them rather than invent another package/toolchain format.

The bootstrap value is therefore not "Purser knows how to run pnpm." It is that Purser owns
the higher-level personal manifest and orchestrates existing project-native mechanisms.

## What appears differentiated

The defensible wedge is the complete transition from a blank machine to an agent-ready
workspace:

```text
pair or restore identity
        -> obtain project manifest and encrypted configuration
        -> clone exactly the selected repositories
        -> detect/use project-native dependency tooling
        -> report missing requirements without guessing destructively
        -> launch human tools with scoped configuration
        -> launch agents without ambient secrets
        -> broker approved secret-backed child commands with receipts
```

This is more compelling than requiring a developer to assemble chezmoi + ghorg + mise +
Syncthing + sops/age + a password manager + an agent wrapper.

The integration only matters if it is substantially easier and more reliable than that
assembly. "One command" must be real rather than a slogan: idempotent, resumable, observable,
and safe when only half the machine is configured.

## Current repository audit

The repository is farther along than its top-level README claims. The README still says
"Nothing is implemented yet," but a useful portion of the local single-machine vault exists.

Implemented now:

- XChaCha20-Poly1305 authenticated encryption.
- Persistent vault key through the OS keyring.
- SQLite schema and repositories.
- Secret versions.
- Dotenv import, secret list, and prompted secret set.
- Human `run` and `shell` child-process injection.
- Sanitized `agent` launcher.
- Hash-chained audit events.

Not implemented now:

- Project commands, manifest orchestration, `status`, or `purser up`.
- P2P transport, pairing, key transfer, replication, or conflict handling.
- The resident daemon and process-approval broker.
- MCP tools and endpoint wiring.
- WSL key-file fallback.
- Agent-requested, policy-checked child execution.
- Cross-platform end-to-end tests of the promised experience.

`cargo test --workspace` passed on 2026-07-14. The suite covered core IDs, encryption
round-trips/authentication failure, storage/version behavior, migration idempotence, audit
chain behavior, and basic dotenv parsing. It did not yet prove the major security or
cross-platform acceptance claims.

## Security claim gap

The current phrase "agent-blind secrets" overstates the implemented boundary. The plan itself
partly acknowledges that a hostile same-user process is out of scope, but prominent wording
still implies a stronger guarantee.

### Agent environment is not actually guaranteed to contain zero secrets

`purser agent` enumerates the parent's environment and removes variables only when their
names match secrets already registered in Purser. Any unknown ambient credential remains,
for example an unimported `GITHUB_TOKEN`, cloud variable, signing credential, or proprietary
tool token.

The correct implementation direction is an explicit allowlist of known-safe variables plus
the minimum variables needed for the launched agent, with documented platform behavior.

### `run` injects an entire profile

The current `run` path loads every active secret in the selected profile. It does not inject
only the resources declared for the requested command. That is inconsistent with the plan's
generic grants/capabilities story and expands blast radius.

Profiles should support explicit secret selection, and agent-triggered commands should be
bound to command, working directory, resource IDs, requester/process ancestry, expiry, and
use count.

### An agent can invoke the CLI

An agent launched as the same OS user inherits the ability to execute `purser`. Without an
out-of-process human approval boundary, it can request `purser run`, cause a child to print
its environment, inspect accessible same-user process state, or access an unlocked keyring.
Auditing this action does not prevent disclosure.

The daemon/broker cannot decide that a request is human merely because it came from a CLI.
It needs a meaningful requester identity and an approval/policy boundary that the agent
cannot trivially impersonate.

### Process environment is not magically secret memory

"Injected only in memory" accurately distinguishes runtime injection from a plaintext file,
but environment variables can be observable to the child, its descendants, debuggers, crash
reporters, same-user process inspection on some systems, and any command that prints them.

Runtime injection reduces default leakage. It does not make the value invisible to the
process that uses it or contain a malicious process.

### Recommended honest claim

For the current rung:

> Purser removes plaintext `.env` files from the coding agent's default reach, launches the
> agent without known Purser-managed values, injects configuration only into selected child
> processes, and records value-blind receipts. It does not contain a hostile same-user agent.

After allowlist sanitization, command/resource-scoped grants, and an external approval broker,
the wording can become stronger. Hard containment still requires OS sandboxing, network and
filesystem policy, and careful output handling.

## Other architecture and plan risks

### Four weeks is not credible for the full promise

Local vault + reliable machine bootstrap + Windows/macOS/Linux/WSL behavior + PAKE pairing +
QUIC/NAT traversal + relay behavior + replication/recovery + daemon/MCP + a meaningful agent
boundary is too much to harden in four weeks.

A prototype may fit. A security-sensitive, recoverable cross-platform tool suitable for
other developers will not.

### "No server" conflicts with relay-assisted connectivity

The plan says both "No server" and that a lightweight relay assists connection setup. The
honest distinction is:

```text
no hosted source of truth
no server that stores or sees plaintext
optional E2EE discovery/relay infrastructure may still be required
```

NAT traversal is unreliable without a reachable coordination/relay path. Offline devices
also cannot perform pure synchronous P2P replication. Be precise about whether v1 supports
only simultaneously-online devices, LAN/Tailscale peers, or store-and-forward relay delivery.

### One shared vault key limits revocation

A single symmetric key is simple for one owner, but removing a device from a peer list does
not revoke a key the device already possesses. Meaningful revocation requires rotating the
vault key and re-encrypting or rewrapping records for remaining devices. The v1 UI should not
imply stronger revocation than it provides.

### `purser up` executes supply-chain-sensitive commands

Cloning repositories and automatically running install/post-clone commands executes code from
those repositories. `up` needs:

- An explicit trusted manifest rather than arbitrary discovery.
- A dry run and a clear command preview.
- Per-project opt-in for custom commands.
- Idempotence and resume after partial failure.
- No destructive cleaning of existing worktrees.
- Detection of dirty repositories before pulls or changes.
- Concurrency limits and usable progress/error summaries.
- Platform-specific overrides without turning the manifest into a new configuration language.

### `up` cannot permanently "inject env"

Bootstrap can ensure the encrypted profile exists and then launch a command/shell through
Purser. It cannot inject variables persistently without contaminating the parent shell or
writing configuration. The command description should say exactly what happens after clone
and rehydration.

### Import behavior needs recovery-focused hardening

The current import encrypts entries and then deletes the plaintext source. For an OSS secret
tool, import needs explicit handling of partial database writes, unsupported dotenv syntax,
duplicate keys, comments/format loss, backups, confirmation/noninteractive behavior, and a
recoverability test. Secret deletion ergonomics should bias against data loss without silently
leaving plaintext behind.

### Future seams risk distracting from the wedge

Opaque IDs and an opaque sync-record interface are cheap and reasonable. The broader object
OS, permissioned Git, hosted monetization, and generic resource-capability future should not
drive user-visible v1 complexity. External users will judge bootstrap reliability, recovery,
and security honesty, not whether the schema anticipates a future substrate.

## Recommended product position

Do not lead with:

```text
P2P secrets manager
AI-proof secrets
Git for secrets
new developer environment/package manager
```

Those claims are crowded or invite security expectations that v1 cannot yet satisfy.

Lead with:

```text
Reproduce your personal coding workstation on any machine, safely for agent-heavy workflows.
```

Supporting messages:

- Git remains the source of truth for committed code.
- Project-native lockfiles and tools remain the source of truth for dependencies.
- Purser owns the personal project manifest and orchestration.
- Real configuration stays out of project files and the agent's ambient context.
- Humans and agents enter projects through different execution policies.
- Local-first operation works without adopting a hosted team platform.

The secrets layer is an enabling capability, not the entire identity.

## Recommended validation sequence

### 1. Correct the existing local security behavior and language

- Replace denylist sanitization with an allowlist environment for `agent`.
- Make secret injection explicit and resource-scoped.
- Prevent an agent from self-approving a broker request.
- Add tests that inspect real child environments and verify parent isolation.
- Add tests ensuring audit, errors, stdout, and metadata paths never serialize values.
- Document the same-user limitation prominently.
- Update the stale README to reflect what is actually implemented.

### 2. Build the differentiated part: project manifest and `purser up`

Implement:

```text
purser project add .
purser project list
purser status
purser up --dry-run
purser up
```

Use existing project-native mechanisms. Avoid becoming another toolchain manager. The quality
bar is a clean, resumable run across real mixed repositories on Windows, WSL, and macOS.

### 3. Release the single-device workflow before custom networking

Let external developers try bootstrap + local vault + agent sanitization. For early device
validation, consider an encrypted export/import bundle or a pluggable user-supplied sync
directory/transport. This tests demand without first committing to NAT traversal, discovery,
relay operations, key recovery, and conflict reconciliation.

This does not mean P2P is never built. It means the project earns its most expensive and
least differentiated subsystem through observed demand.

### 4. Test with external developers

Recruit at least five developers who use more than one machine or OS environment. Ask them to
reproduce real workstations, not toy repositories.

Measure:

- Did `purser up` replace personal bootstrap scripts or manual checklists?
- How many manual interventions were required?
- Could a failed run resume cleanly?
- Did users trust the secret workflow enough to remove plaintext `.env` files?
- Did they understand the agent threat model without explanation?
- Which existing tools did Purser replace, and which did they insist on keeping?

Do not treat stars, launch traffic, or compliments as the gate. Repeated use on the second
machine is the gate.

### 5. Build P2P and the stronger broker only after the wedge passes

If users keep the bootstrap but use 1Password/Infisical/SOPS, make secret providers pluggable.
If users specifically demand owner-controlled device sync, build or adopt the P2P transport.
If users demand agent containment, prioritize an OS-backed broker/sandbox boundary over more
vault features.

## Kill and pivot criteria

Continue the integrated OSS direction if:

- External users reproduce real workstations with `purser up` more than once.
- The combined workflow is materially simpler than their existing dotfiles/scripts stack.
- Users remove plaintext `.env` files and continue launching agents through Purser.
- Cross-platform behavior is a reason they choose it.

Narrow or pivot if:

- Users want only `purser up`: remove or modularize the custom secret manager.
- Users want only the vault: compete on a concrete security boundary, not P2P novelty.
- Users keep established secret providers: make Purser an orchestrator over those providers.
- Only the owner values the all-project manifest: keep it a high-quality personal OSS tool
  without forcing a startup/open-core roadmap.

## Final verdict

Purser is not building a unique secret manager. P2P sync, process injection, OS-keyring
custody, MCP metadata, audit trails, agent approvals, and "use but never see" messaging all
have direct precedents.

Purser may still be building a useful and unusually cohesive developer tool. The opportunity
is to make a fresh machine feel like the developer's machine, including the special safety
requirements introduced by coding agents. That is a concrete problem with a credible wedge.

Build and market the workstation transition. Keep the secret system honest and supporting.
Let repeated use by developers other than the owner decide whether custom P2P, hard sandboxing,
and hosted/team layers are earned.
