# Agent Control Surface Protocol: Value Assessment & Sprint Plan

**Status:** DRAFT — awaiting sign-off
**Date:** 2026-05-12
**Author:** Operator mega-sprint (automated)
**Ref:** E1–E3 ecosystem integration tasks, SSO/DID alignment
**Scope:** (1) Evaluate lifting an enterprise decision broker (here, VisionClaw) into the forum. (2) Generalize: extend nostr-rust-forum upstream as a generic agent control surface protocol with MCP/API, instantiated against an operator's specific agent-platform use case. (3) SSO alignment via did:nostr as the identity unifier across all repos.

**Key principle:** nostr-rust-forum upstream ships the generic protocol. The operator configures against their specific use case. The upstream knows "agents that publish panels via nostr events" — not any one operator's agent.

---

## 1. PRD: Problem & Opportunity

### 1.1 Current State

A representative operator ecosystem has **two separate governance UIs**:

| Surface | Stack | Auth | Persistence | Users See |
|---------|-------|------|-------------|-----------|
| VisionClaw enterprise drawer + `/enterprise` page | React + Actix actors + Neo4j | `X-Enterprise-Role` header (demo RBAC) | Neo4j graph DB | Broker inbox, decisions, workflows, KPIs, policy, connectors |
| NRF forum | Leptos WASM + CF Workers | NIP-98 Schnorr (production) | D1 + KV | Forum channels, moderation, invites, pods |

Users managing such an ecosystem must context-switch between two apps with two auth systems. The VisionClaw enterprise auth (`X-Enterprise-Role` header) is explicitly a Phase 1 placeholder — ADR-040 acknowledges OIDC JWT extraction is needed for Phase 2.

### 1.2 Opportunity

The forum already has production-grade nostr-native auth (NIP-98, WebAuthn/passkey, did:nostr DID documents, invite gating, WoT). VisionClaw's `BrokerActor` already emits **kind 30300 nostr events** for decisions via `ServerNostrActor`. The bridge point exists.

### 1.3 Strategic Question

> Should we lift the enterprise decision broker features from VisionClaw into the forum, replacing REST/WebSocket with nostr message mediation?

---

## 2. Inventory: What Exists

### 2.1 VisionClaw Enterprise Stack (11,224 LOC total)

**Backend Rust — 5,329 LOC across 23 files:**

| Module | LOC | Purpose |
|--------|-----|---------|
| `domain/broker/` (case, decision, precedent, mod) | 965 | BrokerCase aggregate, DecisionOrchestrator, PrecedentRegistry |
| `domain/contributor/` (7 files) | 1,969 | ContributorProfile, Workspace, GuidanceSession, ShareIntent, WorkArtifact, ContextAssembly |
| `actors/broker_actor.rs` | 571 | Supervised actor: inbox cache, decisions, WS broadcast, Neo4j persist, nostr signing |
| `actors/contributor_studio_supervisor.rs` | 286 | Child actor supervision for contributor domain |
| `models/enterprise.rs` | 304 | Shared types: roles, cases, workflows, KPIs, policies, connectors |
| `events/enterprise_events.rs` | 261 | Domain events for audit trail |
| `middleware/enterprise_auth.rs` | 296 | RBAC middleware (X-Enterprise-Role header) |
| `adapters/neo4j_broker_adapter.rs` | 337 | Neo4j persistence for broker cases |
| `adapters/broker_case_projection.rs` | 84 | Domain → legacy type projection |
| `ports/` (broker, workflow, policy) | 129 | Repository/engine port traits |
| `handlers/api_handler/broker/` | ~150 | REST API: inbox, cases, decisions, migration candidates |

**Frontend TypeScript/React — 5,895 LOC across ~40 files:**

| Feature | LOC | Components |
|---------|-----|------------|
| `features/broker/` | 1,415 | BrokerWorkbench, BrokerInbox, DecisionCanvas, BrokerTimeline, CaseSubmitForm |
| `features/enterprise/` | 1,258 | EnterprisePanel, EnterpriseNav, EnterpriseDrawer (frosted glass + WASM FX), DrawerToggle/Mount |
| `features/contributor-studio/` | 2,059 | ContributorStudioRoot (4-pane), WorkLane, AIPartnerLane, OntologyGuideRail, SkillDojo, 5 Zustand stores |
| `features/workflows/` | 305 | WorkflowStudio |
| `features/kpi/` | 224 | MeshKpiDashboard |
| `features/policy/` | 273 | PolicyConsole |
| `features/connectors/` | 361 | ConnectorPanel |

**Separate entry point:** `enterprise-standalone.tsx` + `enterprise.html` (Vite multi-entry)

### 2.2 Nostr Integration Already Present

The `BrokerActor` already signs decisions via `ServerNostrActor`:
- **Kind 30300** events for `KnowledgeEnrichment` broker decisions
- Tags: `d` (case_id), `decision` (action), `broker` (pubkey as `did:nostr:{hex}`), `urn` (entity), `h` (server group tag)
- Currently limited to enrichment category — not all case types

### 2.3 NRF Forum Auth Stack (production-grade)

| Capability | Implementation | Status |
|------------|---------------|--------|
| NIP-98 HTTP Auth (kind 27235) | `nostr_bbs_core::nip98` + D1 replay cache | Production |
| WebAuthn/Passkey + PRF key derivation | `auth-worker/webauthn.rs` (hand-rolled CBOR/COSE) | Production |
| NIP-07 browser extension | `forum-client/auth/nip07.rs` | Production |
| did:nostr DID documents | `nostr_bbs_core::did` (Tier-1 + Tier-3 with Solid) | Production |
| Invite codes + tenure gating | `auth-worker/invites.rs` | Production |
| Web-of-Trust gating | `auth-worker/wot.rs` (NIP-02 follow-list) | Production |
| Admin RBAC | `members.is_admin` + `whitelist.is_admin` | Production |
| Account enumeration prevention | Audit C2 hardening in login_options | Production |

---

## 3. ADR: Architectural Decision

### 3.1 Decision: Selective Lift of Broker Workbench Only

**LIFT** the Judgment Broker (case management + decision workflow) into the forum.
**KEEP** Contributor Studio, WorkflowStudio, KPI Dashboard, PolicyConsole, ConnectorPanel in VisionClaw.
**KEEP** the VisionClaw control center as-is.

### 3.2 Rationale

#### Features evaluated for lift:

| Feature | Verdict | Rationale |
|---------|---------|-----------|
| **Broker Workbench** | **LIFT** | Self-contained aggregate, already emits nostr events, maps to forum's NIP-98 auth, highest cross-ecosystem value |
| **Enterprise Panel/Nav shell** | **LIFT** | Lightweight UI wrapper (~77 LOC), needed to host broker in forum |
| **Contributor Studio** | **DEFER** | 4,028 LOC, deeply coupled to VisionClaw ontology/AI partner system, 5 specialized stores, requires OntologyGuidanceActor + ContextAssemblyActor |
| **WorkflowStudio** | **DEFER** | Coupled to VisionClaw automation orchestrator actor |
| **KPI Dashboard** | **DEFER** | VisionClaw-specific metrics (mesh velocity, trust variance, HITL precision) |
| **PolicyConsole** | **DEFER** | Coupled to VisionClaw policy engine |
| **ConnectorPanel** | **DEFER** | VisionClaw-specific external connectors (GitHub, Jira, Slack) |

#### Why only the Broker Workbench?

1. **Domain isolation.** `BrokerCase` is a self-contained aggregate root with clean invariants (no self-review, append-only history, terminal state idempotency). Zero dependencies on Neo4j graph queries, ontology, or AI partners.

2. **Nostr bridge exists.** `SignBrokerDecision` already produces kind 30300 events. Extending to all case categories (not just `KnowledgeEnrichment`) is a small change.

3. **Auth alignment.** Replacing `X-Enterprise-Role` header (VisionClaw demo) with NIP-98 + DID document claims (forum production) is a strict upgrade.

4. **User journey.** Forum users who govern contributions (approve/reject work artifacts, manage share-state transitions) should not need a second application. The broker inbox is the governance UI.

5. **Contributor Studio is VisionClaw-native.** The 4-pane workspace (ontology guide, work lane, AI partner lane, session memory) only makes sense within VisionClaw's graph visualization context. Lifting it would lose its primary value — spatial context.

### 3.3 Nostr Message Mediation Architecture

Replace VisionClaw's REST + WebSocket + Neo4j with nostr events:

```
Current (VisionClaw):
  Client → POST /api/broker/cases/{id}/decide → BrokerActor → Neo4j + WS broadcast

Proposed (Forum):
  Client → NIP-98 signed nostr event (kind 30310) → Relay DO → D1 persistence
  Client ← REQ subscription on broker event kinds ← Relay DO
```

**Proposed event kinds (replaceable range 30300-30320):**

| Kind | Purpose | Replaces |
|------|---------|----------|
| 30310 | BrokerCase created | POST /api/broker/cases |
| 30311 | BrokerCase claimed | POST /api/broker/cases/{id}/claim |
| 30312 | BrokerDecision recorded | POST /api/broker/cases/{id}/decide |
| 30313 | BrokerCase delegated | (subset of 30312 with action=delegate) |
| 30300 | Audit record (existing) | ServerNostrActor SignAuditRecord |

**Tag schema (30312 example):**
```json
{
  "kind": 30312,
  "content": "{\"action\":\"approve\",\"reasoning\":\"Meets quality bar\"}",
  "tags": [
    ["d", "<case_id>"],
    ["e", "<case_creation_event_id>"],
    ["p", "<case_creator_pubkey>"],
    ["broker", "<deciding_broker_pubkey>"],
    ["action", "approve"],
    ["h", "forum-broker"]
  ]
}
```

**Auth mapping:**

| VisionClaw | Forum Equivalent |
|------------|-----------------|
| `X-Enterprise-Role: Broker` | NIP-98 token + `members.is_admin` or role in DID document service claims |
| `require_role(&req, Broker)` | Relay DO validates pubkey against `broker_roles` D1 table |
| Neo4j case persistence | D1 `broker_cases` + `broker_decisions` tables |
| WebSocket `broker:*` events | Nostr relay subscription (REQ filter on kind 30310-30313) |

### 3.4 Consequences

**Positive:**
- Single auth system (NIP-98) across all governance
- Decisions are cryptographically signed nostr events (immutable audit trail)
- Forum users govern without context-switching
- VisionClaw can subscribe to forum relay for decision notifications (reverse bridge)
- JSS SSO alignment: same did:nostr identity works across forum + JSS + VisionClaw

**Negative:**
- ~2,500 LOC of new Rust code (domain model port + CF Worker handlers + D1 schema)
- ~800 LOC of new Leptos components (broker inbox, decision canvas, case form)
- React → Leptos rewrite of UI components (no direct port)
- Neo4j → D1 persistence migration for case history
- Must maintain VisionClaw's existing broker for backward compatibility during migration

**Neutral:**
- BrokerCase domain model (broker_case.rs, broker_decision.rs) can be extracted to `nostr-bbs-core` as a shared crate — VisionClaw and forum both consume it
- DecisionOrchestrator is framework-agnostic (plain struct, no actor state) — portable as-is

---

## 4. DDD: Domain Model for Forum Broker

### 4.1 Bounded Context: Forum Governance (BC-GOV)

**Aggregate Root:** `BrokerCase`

Reuse VisionClaw's existing domain model (it's clean DDD):

```
BrokerCase (aggregate root)
├── id: String
├── category: CaseCategory
│   ├── ContributorMeshShare  (share-state promotion: Private → Team → Mesh)
│   ├── WorkflowReview
│   ├── PolicyException
│   ├── TrustAlert
│   ├── ManualSubmission
│   └── KnowledgeEnrichment
├── subject: SubjectRef { kind, id, from_state?, to_state? }
├── state: CaseState (Open → UnderReview → Decided|Delegated|Promoted|Precedent|Closed)
├── priority: u8
├── created_by: String (nostr pubkey hex)
├── assigned_to: Option<String> (broker pubkey)
├── history: Vec<DecisionHistoryEntry>  (append-only)
└── metadata: HashMap<String, String>

DecisionOutcome (value object)
├── Approve
├── Reject
├── Amend { diff }
├── Delegate { delegate_to }
├── Promote { pattern_id }
└── Precedent { scope }

ShareState (value object): Private → Team → Mesh (monotonic)
```

**Invariants (preserved from VisionClaw):**
1. Append-only decision history
2. No self-review (broker pubkey != creator pubkey)
3. Provenance chain (each decision links prior decision id)
4. Terminal state idempotency (Decided/Closed blocks further decisions)

### 4.2 Integration Points

```
┌─────────────────────────────────────────────────────┐
│  Forum (Leptos WASM + CF Workers)                   │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────┐      │
│  │ Broker UI    │───▶│ Relay DO             │      │
│  │ (Leptos)     │◀───│ (nostr event handler)│      │
│  └──────────────┘    └─────────┬────────────┘      │
│                                │                    │
│                        ┌───────▼────────┐          │
│                        │ D1: broker_    │          │
│                        │ cases/decisions│          │
│                        └───────┬────────┘          │
│                                │                    │
│  ┌──────────────┐    ┌────────▼─────────┐          │
│  │ Auth Worker  │───▶│ NIP-98 verify    │          │
│  │ (existing)   │    │ + role lookup    │          │
│  └──────────────┘    └──────────────────┘          │
└─────────────────────────────────────────────────────┘
                         │ nostr events
                         ▼
┌─────────────────────────────────────────────────────┐
│  VisionClaw (subscribes to forum relay)             │
│  BrokerActor receives decision events               │
│  ServerNostrActor emits case-creation events         │
└─────────────────────────────────────────────────────┘
                         │ did:nostr
                         ▼
┌─────────────────────────────────────────────────────┐
│  JSS (jss.live/sso)                                 │
│  NIP-98 token verification via did:nostr resolution  │
│  Cross-service SSO with same keypair                 │
└─────────────────────────────────────────────────────┘
```

### 4.3 New D1 Schema (Auth Worker or new Broker Worker)

```sql
CREATE TABLE IF NOT EXISTS broker_cases (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    subject_json TEXT NOT NULL,       -- JSON SubjectRef
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'open',
    priority    INTEGER NOT NULL DEFAULT 50,
    created_by  TEXT NOT NULL,        -- nostr pubkey hex
    assigned_to TEXT,                 -- broker pubkey
    metadata_json TEXT DEFAULT '{}',
    nostr_event_id TEXT,              -- creation event id
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_decisions (
    decision_id      TEXT PRIMARY KEY,
    case_id          TEXT NOT NULL REFERENCES broker_cases(id),
    outcome_action   TEXT NOT NULL,
    outcome_payload  TEXT DEFAULT '{}',  -- JSON (diff, delegate_to, pattern_id, scope)
    broker_pubkey    TEXT NOT NULL,
    reasoning        TEXT NOT NULL DEFAULT '',
    prior_decision_id TEXT,
    nostr_event_id   TEXT,               -- decision event id
    decided_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_roles (
    pubkey  TEXT PRIMARY KEY,
    role    TEXT NOT NULL DEFAULT 'contributor',  -- contributor|auditor|broker|admin
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL
);

CREATE INDEX idx_cases_state ON broker_cases(state);
CREATE INDEX idx_cases_created_by ON broker_cases(created_by);
CREATE INDEX idx_decisions_case ON broker_decisions(case_id);
```

---

## 5. SSO & Workflows Alignment

### 5.1 Melvin Sync: NIP-98 Token Format

**Current:** JSS at `jss.live/sso/` requires PodKey browser extension for NIP-98 signing.
**Gap:** Users need PodKey installed alongside their passkey/NIP-07 setup.

**Alignment path:**

1. **Immediate (no code):** Document the NIP-98 token format both systems expect. NRF's `nostr_bbs_core::nip98::verify_token_at()` and solid-pod-rs's `Nip98Verifier` should produce/accept identical tokens. Verify field-level compatibility:
   - `kind: 27235`
   - Tags: `["u", url]`, `["method", method]`, optional `["payload", sha256]`
   - Timestamp window: NRF allows ±60s (configurable); JSS TBD
   - Schnorr signature verification: both use secp256k1

2. **Short-term (forum change):** Expose a NIP-98 signing endpoint in the forum that external services can redirect to. User authenticates via passkey/NIP-07 in the forum, forum signs a NIP-98 token for the external service's URL. This eliminates the PodKey requirement for forum users.

3. **Medium-term (JSS change):** JSS accepts tokens signed by the forum's NIP-98 endpoint (or directly by passkey-derived keys). Mutual DID document service endpoint discovery: forum serves `did:nostr:{pubkey}` documents with JSS service endpoint, JSS resolves forum's DID documents.

### 5.2 did:nostr as Universal Identity Anchor

```
User's nostr keypair (passkey-derived or NIP-07)
    │
    ├── Forum: NIP-98 auth → full forum access
    │   └── did:nostr:{pubkey} → /.well-known/did/nostr/{pubkey}.json
    │       └── service: SolidStorage, NostrRelay, SolidWebID
    │
    ├── JSS/Solid: NIP-98 auth → pod read/write
    │   └── WebID profile → links to did:nostr:{pubkey}
    │
    ├── VisionClaw: NIP-98 auth → graph viz + enterprise features
    │   └── BrokerActor uses did:nostr:{pubkey} for decision provenance
    │
    └── Forum Broker (proposed): NIP-98 auth → governance decisions
        └── Broker decisions signed as nostr events by user's keypair
```

### 5.3 Signup Workflow Supersession Analysis

| Current Forum Signup | Would Broker Lift Change It? |
|---------------------|------------------------------|
| Passkey/WebAuthn registration → PRF key derivation | No change — broker uses existing auth |
| NIP-07 browser extension login | No change |
| Invite code redemption (tenure-gated) | No change — broker roles granted separately |
| WoT gating (NIP-02 follow-list) | No change |
| Admin role assignment | Extended: new `broker_roles` table for Broker/Auditor roles |

The broker lift does NOT supersede existing signup workflows. It adds a governance layer on top of the existing auth system.

---

## 6. Sprint Plan

### 6.1 Milestone 1: Domain Model Extraction (2 days)

- [ ] Extract `BrokerCase`, `DecisionOutcome`, `DecisionOrchestrator` from VisionClaw into `nostr-bbs-core` as `governance` module
- [ ] Add `governance` feature flag to `nostr-bbs-core/Cargo.toml`
- [ ] Port tests (VisionClaw has 12 broker domain tests — all pass)
- [ ] Define nostr event kinds 30310-30313 with tag schema
- [ ] D1 schema migration for broker_cases, broker_decisions, broker_roles

### 6.2 Milestone 2: Relay DO Integration (2 days)

- [ ] Handle kind 30310 (case creation) in relay DO NIP handler
- [ ] Handle kind 30312 (decision) with domain invariant enforcement
- [ ] D1 persistence for case lifecycle
- [ ] REQ subscription support for broker event kinds
- [ ] NIP-98 auth + role check (broker_roles table)

### 6.3 Milestone 3: Forum UI — Broker Page (3 days)

- [ ] Leptos `BrokerInbox` component (case list with priority/status badges)
- [ ] Leptos `DecisionCanvas` component (case detail + 6-action decision grid)
- [ ] Leptos `CaseSubmitForm` component (manual case creation)
- [ ] Leptos `BrokerTimeline` component (audit log)
- [ ] Forum nav integration (new "Governance" section for broker-role users)
- [ ] Nostr event subscription for real-time inbox updates

### 6.4 Milestone 4: VisionClaw Bridge (1 day)

- [ ] VisionClaw `BrokerActor` subscribes to forum relay for case events
- [ ] VisionClaw `ServerNostrActor` publishes case-creation events to forum relay
- [ ] Backward compatibility: VisionClaw REST API still works during migration

### 6.5 Milestone 5: SSO Alignment (1 day)

- [ ] Document NIP-98 token format parity with JSS
- [ ] Add JSS service endpoint to did:nostr Tier-3 documents
- [ ] Test cross-service NIP-98 token acceptance

**Total estimate: 9 days (1 sprint)**

---

## 7. Value Assessment Summary

### 7.1 LIFT: Broker Workbench

| Dimension | Score | Notes |
|-----------|-------|-------|
| **Strategic alignment** | 9/10 | Unifies governance under nostr, reduces cognitive load |
| **Technical feasibility** | 8/10 | Clean domain model, nostr bridge exists, CF Workers can host it |
| **Effort vs. value** | 7/10 | ~3,300 LOC new code for a governance system that serves all ecosystem users |
| **Risk** | Low | Domain model is well-tested, invariants are explicit, backward-compatible |
| **Auth upgrade** | 10/10 | Replaces demo header auth with production NIP-98 Schnorr |

### 7.2 DEFER: Everything Else

| Feature | Why Defer |
|---------|-----------|
| Contributor Studio | 4,028 LOC, coupled to VisionClaw ontology/AI system, loses spatial context outside graph |
| WorkflowStudio | Coupled to VisionClaw automation orchestrator actor chain |
| KPI Dashboard | VisionClaw-specific metrics with no forum analogue |
| PolicyConsole | Coupled to VisionClaw policy engine and connector signals |
| ConnectorPanel | External data sources (GitHub/Jira/Slack) specific to VisionClaw ingestion |

### 7.3 Recommendation

**Proceed with Broker Workbench lift.** The domain model is portable, the nostr mediation path is natural (kind 30300 events already exist), and the auth upgrade from demo headers to production NIP-98 is a strict improvement. The forum becomes the single governance surface for the operator's ecosystem.

**Do not lift Contributor Studio or other VisionClaw-specific features.** They lose their primary value (spatial graph context) outside VisionClaw, and the coupling to ontology/AI systems would require reimplementing significant VisionClaw infrastructure in CF Workers.

---

---

## 8. ADR-EXT: Forum as Agent Control Surface (MCP/API Extension)

### 8.1 The Deeper Play

The broker workbench is the primitive. The real architectural insight: **the forum becomes a rendering surface where agents deploy interactive control panels to humans, mediated entirely by nostr events.**

This inverts the normal agent UX model. Instead of agents having their own dashboards that humans visit, agents publish structured nostr events into the forum relay, and the forum renders them as rich interactive decision surfaces. Humans respond through the same relay. The forum becomes a **universal human-in-the-loop (HITL) control plane** for any agent system.

### 8.2 Why This Is Powerful

1. **Single attention surface.** Humans already live in the forum. Agents meet them there instead of requiring context switches to agent-specific UIs.

2. **Cryptographic accountability.** Every agent action proposal and every human decision is a signed nostr event. Immutable audit trail with no extra infrastructure.

3. **Composable.** Any agent — VisionClaw, agentbox, external Claude agents, custom MCP servers — can publish control surface events to the same relay. The forum renders them uniformly.

4. **Evolving.** Control surfaces aren't static pages. Agents publish updated panel state as new nostr events. The forum subscribes and re-renders in real time.

5. **Decentralized.** No single agent backend owns the control plane. The relay is the coordination point. Multiple agents can collaborate on the same decision surface.

### 8.3 Architecture: Agent Control Surface Protocol

**Layer 1: Nostr Event Schema for Control Surfaces**

New event kind range: **31400–31499** (parameterized replaceable, `d`-tag addressable)

| Kind | Purpose |
|------|---------|
| 31400 | **PanelDefinition** — Agent declares a control panel (schema, fields, actions, layout hints) |
| 31401 | **PanelState** — Agent publishes current panel state (data rows, status indicators, metrics) |
| 31402 | **ActionRequest** — Agent requests human decision (approve/reject/configure/escalate) |
| 31403 | **ActionResponse** — Human responds to an action request (signed by human's nostr key) |
| 31404 | **PanelUpdate** — Agent pushes incremental state update (diff, not full replace) |
| 31405 | **PanelRetired** — Agent retires a control panel |

**PanelDefinition (kind 31400) example:**
```json
{
  "kind": 31400,
  "pubkey": "<agent_pubkey>",
  "content": "{\"title\":\"VisionClaw Enrichment Queue\",\"description\":\"Ontology enrichment proposals awaiting human review\",\"version\":\"1.0.0\"}",
  "tags": [
    ["d", "visionclaw-enrichment-queue"],
    ["agent", "<agent_pubkey>", "VisionClaw"],
    ["schema", "action-inbox"],
    ["field", "entity_urn", "string", "Entity URN"],
    ["field", "confidence", "float", "AI Confidence"],
    ["field", "proposed_change", "json", "Proposed Change"],
    ["field", "evidence_count", "int", "Evidence Items"],
    ["action", "approve", "Approve Enrichment", "primary"],
    ["action", "reject", "Reject", "destructive"],
    ["action", "defer", "Defer for Review", "secondary"],
    ["action", "amend", "Approve with Amendment", "secondary"],
    ["layout", "inbox-table"],
    ["capability", "bulk-action"],
    ["capability", "filter"],
    ["refresh", "30"]
  ]
}
```

**ActionRequest (kind 31402) example:**
```json
{
  "kind": 31402,
  "pubkey": "<agent_pubkey>",
  "content": "{\"entity_urn\":\"urn:kg:node:12345\",\"confidence\":0.87,\"proposed_change\":{\"add_class\":\"owl:Thing\"},\"evidence_count\":3,\"reasoning\":\"High structural fit, confirmed by reasoner\"}",
  "tags": [
    ["d", "visionclaw-enrichment-queue:req:abc123"],
    ["e", "<panel_definition_event_id>"],
    ["p", "<target_human_pubkey>"],
    ["agent", "<agent_pubkey>", "VisionClaw"],
    ["priority", "high"],
    ["expires", "1747180800"],
    ["context", "https://visionclaw.example.com/graph?node=12345"]
  ]
}
```

**ActionResponse (kind 31403) — signed by human:**
```json
{
  "kind": 31403,
  "pubkey": "<human_pubkey>",
  "content": "{\"action\":\"approve\",\"reasoning\":\"Looks correct, reasoner confirms\"}",
  "tags": [
    ["e", "<action_request_event_id>"],
    ["p", "<agent_pubkey>"],
    ["d", "visionclaw-enrichment-queue:resp:abc123"],
    ["decision", "approve"]
  ]
}
```

### 8.4 Forum Rendering: Panel Registry & Dynamic Components

The forum client maintains a **panel registry** — a subscription to kind 31400 events from agents the user has authorized. Each panel definition declares:

- **Schema type** (`action-inbox`, `dashboard`, `config-form`, `status-board`, `chat-bridge`)
- **Fields** with types (string, float, json, enum, bool)
- **Actions** the human can take (with button style hints)
- **Layout hint** (inbox-table, kanban, card-grid, split-detail)
- **Capabilities** (bulk-action, filter, search, sort, export)
- **Refresh cadence** (how often the agent pushes state updates)

The forum renders these using a finite set of **Leptos meta-components**:

```
/governance                    → Panel list page (all registered agent panels)
/governance/:panel_d_tag       → Single panel view
/governance/:panel_d_tag/:item → Item detail + action form
```

Meta-components (reusable, not per-agent):
- `InboxTable` — rows of action requests, bulk approve/reject, filters
- `DecisionCanvas` — single-item detail + action buttons + reasoning textarea
- `DashboardGrid` — metric cards + charts (agent publishes data, forum renders)
- `ConfigForm` — agent asks human to configure parameters (form fields from schema)
- `StatusBoard` — read-only status display (agent pushes updates)

The forum never executes agent code. It interprets declarative schemas and renders native Leptos components. Agents can only define structure — not inject behavior.

### 8.5 MCP Tool Surface: Forum-as-MCP-Server

The forum relay exposes an **MCP server interface** so agents can interact programmatically:

```
MCP Server: forum-governance
├── tools:
│   ├── register_panel(definition: PanelDefinition)     → panel_id
│   ├── update_panel_state(panel_id, state: PanelState)  → event_id
│   ├── submit_action_request(panel_id, request: ActionRequest) → request_id
│   ├── get_action_responses(panel_id, since?: timestamp) → Vec<ActionResponse>
│   ├── retire_panel(panel_id)                            → ack
│   └── list_panels(agent_pubkey?)                        → Vec<PanelSummary>
├── resources:
│   ├── panel://{panel_d_tag}                             → current panel definition
│   ├── panel://{panel_d_tag}/state                       → latest state snapshot
│   ├── panel://{panel_d_tag}/pending                     → pending action requests
│   └── panel://{panel_d_tag}/decisions                   → completed decisions
└── prompts:
    ├── create_governance_panel                            → guided panel definition
    └── submit_decision_batch                              → bulk action request creation
```

Under the hood, each MCP tool call translates to a signed nostr event published to the forum relay. The MCP server is a thin adapter — the relay is the source of truth.

**Agent authentication:** NIP-98 signed HTTP requests to the MCP endpoint, or direct nostr event publication to the relay WebSocket. Agent pubkeys must be in an `agent_registry` D1 table (admin-gated).

### 8.6 Trust & Gating

| Actor | Can Do | Gated By |
|-------|--------|----------|
| Agent (registered) | Publish PanelDefinition, PanelState, ActionRequest | `agent_registry` D1 table, admin-approved |
| Agent (unregistered) | Nothing | Blocked at relay ingress |
| Human (broker role) | Respond to ActionRequests, bulk actions | `broker_roles` D1 table |
| Human (member) | View panels, respond if `p`-tagged | Standard forum membership |
| Admin | Register/deregister agents, grant broker roles | `members.is_admin` |

Trust-level integration with existing relay:
- Kind 31400-31405 events from agents: validated against `agent_registry`
- Kind 31403 responses from humans: standard NIP-98 auth + role check
- Relay DO `handle_event` extended with agent-kind routing block (same pattern as NIP-29 admin kinds)

### 8.7 VisionClaw as First Agent Consumer

VisionClaw's `BrokerActor` + `ServerNostrActor` become the first agent to deploy control panels into the forum:

1. VisionClaw publishes a `PanelDefinition` (kind 31400) for its enrichment queue
2. `ServerNostrActor` publishes `ActionRequest` events (kind 31402) for each enrichment proposal — replacing the current REST `POST /api/broker/cases`
3. Forum renders the enrichment queue as an `InboxTable` with approve/reject/defer actions
4. Human broker reviews in the forum and publishes `ActionResponse` (kind 31403)
5. VisionClaw subscribes to kind 31403 responses and executes the decision (WriteBackSaga, ontology PR, etc.)

The entire `BrokerWorkbench` React app becomes unnecessary — the forum renders it from the panel definition. VisionClaw doesn't ship UI for governance anymore; it ships nostr events.

### 8.8 Agentbox as Second Consumer

Agentbox agent jobs that require human approval (cost > threshold, access to sensitive data, deployment decisions) publish `ActionRequest` events to the forum. The forum renders them as a decision inbox. Human approves, agentbox proceeds.

This replaces agentbox's current zero-auth WebSocket management API with cryptographically signed human decisions.

### 8.9 Implications for Sprint Plan

The panel registry architecture subsumes the "Broker Workbench lift" from Section 6. Instead of porting VisionClaw's BrokerWorkbench React components to Leptos 1:1, we build the meta-component rendering system once and let agents declare their panels.

**Revised milestones (cross-repo, SSO-first):**

| # | Milestone | Repo(s) | Days | Deliverable |
|---|-----------|---------|------|-------------|
| **0** | **SSO parity verification** | solid-pod-rs, NRF | 1 | Confirm NIP-98 field/timestamp/signature parity between `nostr_bbs_core::nip98` and `solid_pod_rs::Nip98Verifier`. Document any divergence. Automated cross-verification test. |
| **1** | Event kind schema + domain model | NRF (nostr-bbs-core) | 2 | Kind 31400-31405 type definitions, tag schema, `AgentPanelEvent` types in `nostr-bbs-core::governance`. BrokerCase domain model extracted from VisionClaw (framework-agnostic). |
| **2** | Relay DO: agent registry + event handling | NRF (relay-worker) | 2 | `agent_registry` D1 table, admin CRUD. Relay DO `handle_event` extended: validate agent events, store panel/action state, route subscriptions. NIP-98 signing endpoint for cross-service tokens. |
| **3** | Forum UI: panel registry + meta-components | NRF (forum-client) | 4 | `/governance` route. `PanelRegistry` Leptos store. 4 meta-components: `InboxTable`, `DecisionCanvas`, `StatusBoard`, `ConfigForm`. Renders any conforming panel — not VisionClaw-specific. |
| **4** | MCP server adapter | NRF (new: governance-mcp) | 2 | `forum-governance` MCP server. Tools: `register_panel`, `submit_action_request`, `get_action_responses`, `list_panels`. Thin adapter: MCP calls → signed nostr events. |
| **5** | VisionClaw agent integration | VisionClaw | 1 | `ServerNostrActor` publishes kind 31400 PanelDefinition + kind 31402 ActionRequests. Subscribes to kind 31403 responses. Replace `X-Enterprise-Role` with NIP-98. Register pubkey in forum `agent_registry`. |
| **6** | JSS/Melvin SSO alignment | solid-pod-rs, NRF | 1 | Mutual DID resolution (forum ↔ JSS). Add JSS service endpoint to Tier-3 DID docs. Test cross-service NIP-98 acceptance. Draft PodKey elimination path. |
| **7** | Operator website pin + agentbox | website, agentbox | 1 | Pin the operator website to an NRF version with governance route. Agentbox: register as agent, wire job approvals to forum ActionRequests. |

**Total: 14 days (2 sprints)**

The 5 extra days (vs. 9 for broker-only lift) buy:
- A generic protocol that serves **any agent** (each new agent is a 1-day integration)
- SSO verification across the ecosystem (eliminates identity fragmentation)
- MCP tool surface (agents can be orchestrated by other agents via the forum)
- Cross-repo identity alignment that unblocks all future integration work

### 8.10 SSO as the Enabler — Cross-Repo Identity Layer

The agent control surface is only as strong as the identity layer underneath it. If agents, humans, and services can't verify each other's signatures and resolve each other's identities, panel responses are meaningless across service boundaries.

**SSO is the on-ramp, not a side concern.**

```
                    did:nostr:{pubkey}
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼─────┐   ┌─────▼─────┐
    │  Forum  │    │    JSS    │   │ VisionClaw│
    │ NIP-98  │    │  NIP-98   │   │  NIP-98   │
    │ Passkey │    │  PodKey   │   │  Server   │
    │ NIP-07  │    │  (bridge) │   │  Identity │
    └────┬────┘    └─────┬─────┘   └─────┬─────┘
         │               │               │
         │  ┌─────────────────────────┐  │
         └──▶ DID Document Resolution ◀──┘
            │ /.well-known/did/nostr/ │
            │ Tier-3: services, pods  │
            └─────────────────────────┘
```

**What each repo contributes to the SSO/identity layer:**

| Repo | Identity Contribution | Sprint Work |
|------|----------------------|-------------|
| **solid-pod-rs** | `Nip98Verifier` (shared verifier), `did_nostr_types` (DID document types), LWS-CID agent credentials | Verify timestamp window parity with forum (±60s). Expose `verify_nip98()` as a feature-gated public API that external consumers (JSS, agentbox) can call directly. |
| **nostr-rust-forum** (upstream) | NIP-98 token creation/verification, DID document serving (Tier-1/3), WebAuthn→nostr key derivation, `agent_registry` table for agent pubkeys | Add `agent_registry` D1 table. Extend DID Tier-3 documents with `AgentControlPanel` service endpoint. Publish NIP-98 signing endpoint for cross-service token issuance. |
| **VisionClaw** | `ServerNostrActor` (agent identity), `did:nostr:{hex}` in broker decisions, OIDC planned (ADR-040 Phase 2) | Replace `X-Enterprise-Role` header auth with NIP-98 tokens signed by agent's server identity. Publish agent pubkey in DID document. Register as agent in forum's `agent_registry`. |
| **agentbox** | NIP-98 Schnorr verification (existing), DID:nostr 3-tier custody (existing), Solid pod on :8484 | Wire agent job approval to forum ActionRequest events instead of zero-auth WebSocket. Register agent pubkey in forum's `agent_registry`. |
| **Operator website** | Forum client embedding, passkey/NIP-07 auth | Pin to NRF rc that includes agent control surface. SSO flow: user authenticates once via passkey → NIP-98 tokens valid across forum + JSS + agent panels. |

**The SSO alignment sequence (dependency-ordered):**

```
Step 1: solid-pod-rs — verify NIP-98 parity (timestamp, fields, signature)
   ↓ (shared verifier confirmed)
Step 2: nostr-rust-forum — NIP-98 signing endpoint + agent_registry
   ↓ (forum can issue tokens for external services)
Step 3: VisionClaw — replace X-Enterprise-Role with NIP-98, register as agent
   ↓ (first agent authenticated via shared identity)
Step 4: JSS alignment — Melvin sync, mutual DID resolution, PodKey elimination
   ↓ (SSO across forum ↔ JSS)
Step 5: agentbox — register as agent, wire job approvals to forum
   ↓ (second agent, validates generality)
Step 6: Operator website — pin to new NRF, enable agent panels in UI
```

### 8.11 Generalized Upstream vs. Operator Instance

**What goes into nostr-rust-forum (upstream, generic):**

- Event kind definitions (31400-31405) with tag schema
- Relay DO handler: validate agent events against `agent_registry`, store panel state in D1, route subscriptions
- Forum client: `PanelRegistry` store, `InboxTable` / `DecisionCanvas` / `StatusBoard` / `ConfigForm` meta-components
- `/governance` route with panel list and detail views
- MCP server adapter: `forum-governance` tool surface
- `agent_registry` D1 table and admin management UI
- NIP-98 signing endpoint for cross-service token issuance
- DID document Tier-3 `AgentControlPanel` service type
- Trust-level gating: agent events require registered pubkey, human responses require membership + optional role

**What stays in operator configuration (instance-specific):**

- Which agents are registered (VisionClaw pubkey, agentbox pubkey)
- Which humans have broker role (governance decision-makers)
- Panel layout customizations (branding, default views)
- Agent-specific rate limits
- Integration with VisionClaw's enrichment/writeback pipeline
- Integration with agentbox's job approval pipeline

**The upstream doesn't import VisionClaw types.** It imports nostr event schemas. VisionClaw publishes conforming events — the forum renders them generically.

### 8.12 Open Questions

1. **Panel schema versioning.** When an agent updates its panel definition (new fields, changed actions), how does the forum handle in-flight action requests from the old schema? Proposal: panel definitions are versioned; responses reference the definition event id.

2. **Sandboxing.** Panel definitions are declarative, not executable. But `context` URLs in action requests link to external agent UIs. Should the forum render these as iframes, or just as clickable links? Recommendation: links only (no iframe sandbox escape risk).

3. **Agent-to-agent coordination.** Can one agent's panel reference another agent's action responses? This enables multi-agent decision chains (Agent A proposes, Human approves, Agent B executes). The nostr event graph supports this natively via `e`-tag references.

4. **Rate limiting.** Agents can publish high-frequency PanelState updates. The relay needs per-agent rate limits on kind 31401/31404 events. Configurable per agent in `agent_registry`.

5. **Nostr kind allocation.** 31400-31499 is a large range. Should we submit a NIP proposal to reserve these, or use application-specific kinds with a `h`-tag namespace?

---

## Appendix A: Melvin Sync Message Draft

> Melvin — SSO prototype at jss.live/sso/ looks solid. Here's where we're headed for ecosystem alignment:
>
> 1. **NIP-98 token format parity** — we need to verify our implementations accept each other's tokens. NRF uses `nostr_bbs_core::nip98::verify_token_at()`, solid-pod-rs uses `Nip98Verifier`. Key question: what timestamp window does JSS enforce? We use ±60s.
>
> 2. **Eliminate PodKey requirement** — we're exploring a forum-hosted NIP-98 signing endpoint so users authenticated via passkey can get tokens for external services without needing PodKey installed.
>
> 3. **did:nostr mutual discovery** — forum already serves DID documents at `/.well-known/did/nostr/{pubkey}.json` with Solid pod service endpoints. Can JSS resolve these and include them in its SSO flow?
>
> 4. **Broker governance lift** — we're moving VisionClaw's enterprise decision broker into the forum, mediated by nostr events. This means governance decisions (approve/reject work artifacts, share-state promotions) will be signed nostr events on the forum relay. JSS could subscribe to these for cross-service awareness.
>
> Next step: 30-min sync to walk through token format field-by-field and test cross-acceptance.

## Appendix B: ADR Cross-References

| ADR | Title | Relevance |
|-----|-------|-----------|
| ADR-040 | Enterprise Roles | Defines Contributor/Auditor/Broker/Admin hierarchy — maps to `broker_roles` D1 table |
| ADR-041 | Broker Cases & Decisions | Core domain model — ported to `nostr-bbs-core::governance` |
| ADR-042 | Workflow Proposals | Deferred — stays in VisionClaw |
| ADR-043 | KPI Metric Snapshots | Deferred — stays in VisionClaw |
| ADR-045 | Policy Evaluation | Deferred — stays in VisionClaw |
| ADR-051 | Share-State Ladder | `Private → Team → Mesh` monotonic transitions — preserved in forum broker |
| ADR-057 | Actor Supervision Topology | VisionClaw-specific — forum uses CF Worker Durable Objects instead |
