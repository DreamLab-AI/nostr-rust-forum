# ADR-096: ACL Container Resolution + Per-Container Delegation

- **Status**: Accepted
- **Date**: 2026-06-11
- **Crate**: `crates/nostr-bbs-pod-worker` (Cloudflare Worker, Rust → wasm32)
- **Touches**: `src/acl.rs` (resolver + delegation builder), `src/lib.rs`
  (`handle_acl_request` PUT route)
- **Supersedes**: nothing. **Refines**: ADR-088 (WAC serializer quirk),
  the audit-C3 Control-coercion guard in `coerce_required_mode_for_acl`.

## Context

The pod worker is the access-tier authority for a Solid-style pod. It
evaluates Web Access Control (WAC) against a JSON-LD ACL document whose
canonical shape is:

```json
{
  "@context": { "acl": "http://www.w3.org/ns/auth/acl#" },
  "@graph": [{
    "acl:agent":   { "@id": "did:nostr:<hex>" },
    "acl:accessTo":{ "@id": "<path>" },
    "acl:default": { "@id": "<path>" },
    "acl:mode":    [ { "@id": "acl:Read" } ]
  }]
}
```

Agents are identified by `did:nostr:<hex>` and matched by exact string in the
upstream evaluator (`solid_pod_rs::wac`). Modes are `acl:Read`, `acl:Write`
(maps to Write+Append), `acl:Append`, `acl:Control`.

Two defects motivated this ADR.

### Defect 1 — the container-resolution gap (the resolver bug)

The resolver `find_effective_acl` (the resolver) walks UP the container tree
looking for `.acl` sidecars. The legacy walk derived each parent by stripping
the **trailing slash before** computing the parent, so it only ever produced
the *flat* sidecar form at each level. For `/private/agent/SOUL.md` it probed:

```
pods/<owner>/private/agent/SOUL.md.acl   (own resource sidecar)
pods/<owner>/private/agent.acl           (flat ancestor)
pods/<owner>/private.acl                 (flat ancestor)
pods/<owner>/.acl                         (root)
```

It **never** probed the per-container sidecar `pods/<owner>/private/agent/.acl`
— the form every Solid container actually uses (the `.acl` *inside* the
container directory). A normal per-container ACL was therefore unreachable.
The production deployment had to work around this by writing a flat
`private/agent.acl` instead of the correct `private/agent/.acl`, diverging
from the WAC container model and from any interop client.

### Defect 2 — delegation required hand-authored JSON-LD

Granting another agent access to a container meant an `acl:Control` holder
hand-writing the full ACL `@graph` and PUTting it to the sidecar. This is
error-prone in the exact way that matters most: an owner who forgets to
re-include their own `acl:Control` grant **locks themselves out** of their own
container, because writing an ACL requires Control on the parent and the new
(broken) ACL no longer grants it.

## Access-control semantics (stated precisely)

These are the invariants the worker enforces; this ADR does not change them,
it makes the resolver honour them correctly.

1. **Who may write an ACL.** Only a holder of `acl:Control` on the parent
   resource may PUT/DELETE its `.acl` sidecar. The worker coerces every
   write-class method on an `.acl` path up to a required mode of `Control`
   (`coerce_required_mode_for_acl`), and `handle_acl_request` independently
   re-checks `acl:Control` on the parent before any mutation. A principal with
   mere `acl:Write` can never escalate by overwriting a sidecar.

2. **Who may read an ACL.** `acl:Read` on the parent **OR** `acl:Control`.

3. **Container default-inheritance (WAC §4.2).** `acl:accessTo` names an
   **exact** resource (plus direct children of a container target).
   `acl:default` applies **recursively** to descendants. When an ACL is
   resolved from an **ancestor** container's sidecar — i.e. the walk-up found
   it one or more levels up — only its `acl:default` rules may apply; its
   `acl:accessTo` rules must NOT leak to descendants. The upstream evaluator
   enforces this via the `AclDocument::inherited` flag; the resolver is
   responsible for **setting** that flag correctly per resolution level.

4. **Most-specific wins.** Resolution returns the first parseable sidecar
   found, walking from the resource's own sidecar outward to the root, so a
   resource-specific `.acl` overrides a container `.acl`, which overrides the
   root `.acl`.

## Decision

### Part A — fix the resolver to probe container sidecars

`find_effective_acl` is refactored to drive its walk from a pure helper,
`acl_probe_sequence(resource_path) -> Vec<(key_path, inherited)>`, which emits
the ordered probe list (most-specific first). At **every** level of the
upward walk it now probes BOTH the container sidecar `<dir>/.acl` AND the
legacy flat `<dir>.acl`, so both remain reachable during migration and
most-specific still wins.

**Before** (probe sequence for `/private/agent/SOUL.md`):

```
/private/agent/SOUL.md.acl        inherited=false
/private/agent.acl                inherited=false  ← flat only
/private.acl                      inherited=false  ← flat only
/.acl                             inherited=false
   ▲ container sidecar /private/agent/.acl NEVER probed
   ▲ ancestor inheritance flag never set (accessTo could leak)
```

**After**:

```
/private/agent/SOUL.md.acl        inherited=false   (own resource sidecar)
/private/agent/.acl               inherited=true    ← container sidecar (THE FIX)
/private/agent.acl                inherited=true     (legacy flat, preserved)
/private/.acl                     inherited=true    ← container sidecar
/private.acl                      inherited=true     (legacy flat, preserved)
/.acl                             inherited=true     (root container sidecar)
```

The resource's own sidecar keeps `inherited=false` (its `acl:accessTo` applies
directly). Every ancestor — container or legacy-flat — is marked
`inherited=true`, so the upstream evaluator applies only its `acl:default`
rules (closing a latent `accessTo`-leak hole at the same time). For a
container **target** `/private/agent/`, its own sidecar IS `/private/agent/.acl`
with `inherited=false`, so container-self and direct-child rules apply.

Container detection and parent derivation are handled by a small
`parent_dir` helper that normalises every directory to a trailing-slash form,
so `/a/b/c → /a/b/`, `/a/b/ → /a/`, `/a → /`, `/ → /`.

### Part B — first-class delegation operation

A new pure builder in `acl.rs`:

```rust
pub fn build_delegation_acl(
    owner_did: &str,
    agent_did: &str,
    container_path: &str,
    modes: &[AccessMode],
) -> AclDocument
```

emits the canonical merged ACL document for "grant `agent_did` `modes` on
`container_path`". Its invariants:

- The `@graph` **always** contains an `#owner` authorisation granting
  `acl:Read acl:Write acl:Control` on `container_path` via BOTH `acl:accessTo`
  (the container) and `acl:default` (its descendants). **The owner can never
  be locked out** — every emitted doc re-asserts owner Control, even for an
  empty `modes` slice.
- The `#delegate` authorisation grants exactly the requested modes **minus
  `acl:Control`**. A delegation never confers Control — that would let the
  grantee re-delegate or seize the container. An empty effective set emits no
  delegate authorisation at all.
- Output round-trips cleanly through this crate's `AclDocument` parser.

**Route shape.** `handle_acl_request`'s PUT branch (after the existing
`acl:Control`-on-parent check) detects a structured grant envelope:

```
PUT /pods/<owner>/<container>/.acl        (NIP-98 authed; Control required)
Content-Type: application/json
{ "@delegation": { "agent": "did:nostr:<hex>",
                   "modes": ["acl:Read", "acl:Write"] } }
```

The worker derives `owner_did = did:nostr:<owner_pubkey>`, computes the
container path from the sidecar's parent, calls `build_delegation_acl`, and
serialises the canonical doc to R2 — merging with the owner's full-Control
grant so the owner never loses Control. `acl:Control` in the request `modes`
is ignored (never delegated). Any non-`@delegation` body falls through to the
existing raw-JSON-LD path unchanged, so hand-authored ACLs still work.

All authority checks (Control coercion, the parent-Control re-check,
size cap, `Cache-Control`/`WAC-Allow`/`ETag` emission) are preserved exactly.

## Consequences

- **Positive.** Per-container ACLs at `<dir>/.acl` now resolve correctly,
  matching the WAC container model and interop clients. Delegation is a
  one-call operation that cannot lock the owner out. Ancestor `accessTo`-leak
  is closed as a side-effect of setting `inherited` correctly.
- **Migration.** The flat-sidecar workaround can be retired: deployments may
  move `private/agent.acl → private/agent/.acl`. Both forms remain reachable,
  so the migration is non-breaking and can be done lazily.
- **Negative.** The probe sequence is ~2× longer per level (container +
  legacy-flat). R2 `get` on a missing key is cheap; the walk still terminates
  at root. The flat form can be dropped from the sequence in a later cleanup
  once no deployment relies on it.

## Testing

`find_effective_acl` needs R2 + KV (worker runtime types) and is not
unit-testable on the native target; it is a thin loop returning the first
parseable hit, so probe **order == resolution order**. Tests therefore target
the pure `acl_probe_sequence` (the load-bearing logic) and `build_delegation_acl`:

- container `<dir>/.acl` is probed for `/dir/file` AND `/dir/sub/file`
  (the previously-broken case);
- most-specific precedence holds (`/dir/file.acl` ≺ `/dir/.acl` ≺ `/.acl`);
- own sidecar is `inherited=false`, every ancestor `inherited=true`;
- `build_delegation_acl` emits owner-Control + agent-Read and round-trips;
- a delegation never confers Control on the grantee, and owner Control
  survives even an empty grant (the lock-out guard).

Verified: native `cargo test -p nostr-bbs-pod-worker acl` — 41 passed
(15 new). The wasm32 target check fails on the pre-existing
`secp256k1-sys`/`gnu/stubs-32.h` toolchain issue, unrelated to this change.
