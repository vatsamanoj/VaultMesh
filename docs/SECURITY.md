# VaultMesh Security Model — "only me and my apps"

Defense in depth, zero-knowledge, self-sovereign. VaultMesh is a **private,
closed backend**: no public signup, no anonymous access. Every layer
independently proves the caller is you or one of your apps; a caller that fails
*any* layer is rejected before the next.

## Self-sovereign machinery (no third parties)

- **Self-hosted naming (dynamic → static).** Each dialable machine runs a DDNS
  agent that reports its current public IP — signed with its own cert — to a
  self-hosted rendezvous service mapping `stable VaultMesh name → current IP`.
  Clients resolve by stable name; the floating IP is invisible. Bootstrap uses a
  vendor seed list baked into the installer (plus optional delivery via the
  app's own update channel).
- **Self-hosted NAT traversal.** Node-agents connect **outbound only** to the
  coordinator (QUIC/WebSocket). Peer↔peer transfers use VaultMesh's own
  hole-punching; if a NAT won't punch, the coordinator **relays** the (still
  encrypted) shard. No external STUN/TURN.
- **Self-signed CA.** VaultMesh runs its own offline Root CA + online issuing
  intermediate and signs everything: coordinator server cert, per-app client
  certs, per-node certs. Trust is bootstrapped by **pinning** the root in the
  installer — stronger than public-CA TLS because both ends are controlled.
  Leaves are short-lived and auto-renewed; revocation via a self-hosted list.

## Two planes (same trust root, separated authority)

1. **App data plane** — coordinator mTLS ingress. No VaultMesh-CA client cert ⇒
   TLS handshake fails ⇒ request never reaches app code.
2. **Admin/control plane** — separate endpoint + separate admin CA + MFA, closed
   by default. App certs can never perform admin ops.

The **RustFS anchor** is bound to the private overlay only; clients never touch
it — the node-agent gets short-lived, path-scoped presigned URLs per operation.

## Layered auth (all must pass)

| Layer | Check | A stolen/forged credential yields |
|-------|-------|-----------------------------------|
| **L1 mTLS app cert** (private CA) | "this is a vendor app/install"; revocable | nothing without a valid, unrevoked cert |
| **L2 Capability token** | signed `{namespace, op, nonce, expiry}`, minutes-TTL | single-namespace, single-op, expires fast |
| **L3 Namespace ACL** | cert's `AppId` must own the namespace | App A can never read App B's blobs |
| **L4 Client-side encryption** | AES-256-GCM, key VaultMesh never holds | zero plaintext even on full server compromise |
| **L5 At-rest + in-transit** | TLS 1.3, RustFS SSE, per-shard SHA-256 | tampering detected on restore |

## Threat model → mitigation

| Threat | Mitigation |
|--------|-----------|
| Stranger on the internet | no client cert → rejected at mTLS handshake |
| Stolen capability token | scoped + minutes-TTL + nonce → tiny blast radius |
| Rogue peer holding shards | ciphertext + only 1/K of the blob → learns nothing |
| Network MITM | TLS 1.3 + mTLS pinning |
| Compromised coordinator/RustFS | still zero plaintext (L4); tamper caught by hashes |
| Stolen customer machine | node-agent cert revoked; local content key machine-sealed |
| Abuse / DoS | per-app + per-namespace rate limits & quotas at coordinator |

Every op (register, token issue, put, get, repair, revoke) is appended to a
**tamper-evident audit ledger**.

## Trespasser & hacker defense (active perimeter)

- **Detect & classify:** invalid/revoked/forged cert, bad/expired/replayed
  token, admin-plane hit with an app cert, wrong-namespace access, brute-force
  bursts, endpoint probing/fuzzing, exploit attempts (injection, oversized
  payloads, protocol abuse).
- **Kick away (escalating):** drop at the earliest layer (TLS handshake) →
  **tarpit** repeat offenders → temporary block → permanent block. Blocking keys
  on **multiple signals** (TLS JA3/JA4 fingerprint, cert serial, ASN, behavior)
  — not IP alone — so a floating IP can't dodge the ban.
- **Mesh-wide ejection:** a peer that attempts unauthorized shard access is
  dropped locally and reported to the coordinator, which propagates the
  blocklist to every node.
- **Store the footprints:** an append-only, tamper-evident intrusion/evidence
  ledger records source IP + ASN/geo, JA3/JA4, SNI, any presented/forged cert,
  the classified attack type, the exact rejection reason, timestamp, captured
  request/payload shape, and hit-rate; streamed to a dashboard + alerts.

Modeled cleanly as a `ThreatResponder` port (classify → allow / tarpit / block)
+ an `IntrusionSink` port (append the footprint), so the policy is testable and
swappable and the mesh-wide blocklist is one adapter. *(Declared for P3.)*

## Prying eyes — confidentiality against passive observers

- **Minimal-knowledge coordinator:** only opaque, random namespace ids and blob
  ids — never who a tenant is. The customer↔namespace and CA↔customer mapping
  lives only in the consuming app. Manifests are encrypted at rest.
- **Traffic-analysis resistance:** fixed-size padded shards (byte sizes don't
  leak backup size), content-addressed random ids (no filenames/labels), timing
  jitter / batched flushes, optional cover traffic.
- **On-the-wire blindness:** TLS 1.3 forward secrecy + Encrypted Client Hello
  (hides the SNI/servicename). Peer↔peer transfers are end-to-end encrypted.
- **At-rest double-lock:** client-ciphertext **and** RustFS at-rest encryption
  under opaque object keys — a disk image of the anchor is inert.
- **Peer sees 1/K of noise:** an opaque, fixed-size, erasure-coded fragment — no
  size signal, no identity, no content.
