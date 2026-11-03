# Independent local demo connector — P2

Schema: `MUSE_DEMO_LIVE_SCOPE_2`. This replaces the unavailable private-host
requirement for the public main workflow. The older optional adapter interface
remains only for baseline compatibility tests; it is not the P2 launch path.

`live.py` connects the existing editor to `core/demo_host.py`, the bounded terminal
channel and the existing `MetaHTTPS` adapter/parser. `app.py` remains the offline
backup. Neither launcher reads a key or transmits merely by starting.

## Authority and identity

The local server builds a context from its saved workspace, never browser-supplied
SHA claims: request ID/body SHA/byte count, source ID/version/SHA/Epoch, saved draft
revision/SHA, session, goal, policy, adapter version, program Manifest SHA, model,
fixed endpoint, non-secret account label, one-attempt limit, creation/expiry,
and a proposed US$0.10 risk allowance (not a provider cost cap). Preview expires
after five minutes and rejects a clock earlier than creation.

POST `/api/prepare` returns exact content and a fresh confirmation token.
`/api/live/execute` accepts only request_id, token, decisions and immediate;
unknown fields, old scope packets and uploaded grant JSON are rejected. The five
booleans are B1, risk, data_egress, budget_once and final_dispatch. All must be true;
the final button separately supplies immediate=true. Six distinct event IDs are
saved. This is a trusted local operator ceremony, not remote identity proof or
RBAC. Automated controlled tests use SYNTHETIC_TEST_OPERATOR, never an actual
operator approval. Selecting a mode, viewing or cancelling a preview is no grant.

## Once-only records and failure semantics

An owner-only registry (700 directory; 600 records) is separate from the working
draft. The workspace binds the registry ID. An exclusive process lock plus
create-exclusive, fsynced spent markers allows at most one consumption of a given
request. The marker precedes workspace begin, credential access and transport.
Atomic record replacement uses fsync. Partial writes, missing records, corruption,
owner/mode/symlink errors fail closed; they never release a consumed identity.

A second confirmed request has a new ID and its own six decisions. No action
reuses old consent. Program/content changes are rechecked before credential
access and before transmission. Pending requests and current results are
invalidated on restart; in-progress state becomes UNKNOWN_NO_RETRY. Copied normal
workspaces cannot replace their registry. Whole-disk rollback by an administrator
is explicitly outside this local threat model.

## Credentials and transport

Only after durable consumption, `TerminalCredentials` opens the controlling TTY,
turns echo and signal-character handling off, and reads at most 4096 printable
ASCII bytes for at most 60 seconds. Cancellation, EOF, invalid format and timeout
restore terminal attributes on the handled paths. No TTY means refusal, not
visible getpass/input fallback. Secrets do not enter browser payloads, CLI args,
settings, environment lookup or logs. Mutable buffers are overwritten on exit;
Python strings/TLS internals do not provide guaranteed secure erasure.

The process audit fence permits local UI sockets. In a confirmed Live call only,
a context-bound connection resolves the fixed Meta hostname and connects once to
the first public address, with TLS hostname/certificate validation. No redirect,
proxy environment, address retry, alternate provider, count or hidden continuation
is used. Test mode is locked and never permits external DNS/connections. This is
application-process protection, not a claim of OS-wide isolation against arbitrary
local code or administrators.

No secret is acquired in this task's verification: actual TTY mechanics run only
with synthetic input and a controlled transport. The credential mechanism is
implemented; an actual account/credential and real-use decisions remain pending.

## Reply, content and usage are different facts

The request outcome separately records NOT_STARTED / ATTEMPTED_UNKNOWN /
HTTP_RESPONSE_RECEIVED / RESPONSE_BODY_RECEIVED, HTTP status, content validity,
usage or null, and UNRECONCILED billing. Synthetic tests are not billable usage
measurements. Receipt provenance is SYNTHETIC_PREFLIGHT_TRANSPORT for injected
transport and REAL_META_RESPONSE only for the exact native HTTPS class.

Raw replies are bounded. Credential echo, including decoded visible JSON answer
strings, is rejected and withheld. Invalid/unparseable material may be withheld
rather than persisted as safe evidence; transport remains recorded. Validly
structured, safe but rejected replies retain their raw bytes and available usage.
Schema, complete claim coverage and exact source quotations are independently
checked. Four categories are allowed, not a required distribution. No fallback
manufactures a successful answer. Semantic acceptance remains a human decision.

A result returns CURRENT only if the saved binding, program identity, time and
Stop state still match at commit. Otherwise the safe reply and usage survive as
STALE history. Source/draft/Policy changes never resurrect old results, even if
text is restored. Stop prevents later local work; it does not promise cancellation
of remote computation or fees. Normal shutdown cancels terminal waiting and leaves
any interrupted attempt consumed, without automatic retry.

## Public boundary

Only competition code and documentation are distributed. Local session and
consumption records, real keys, private source, account proofs and formal systems
are excluded. Judges use their own account and consent. No formal execution
identity, organizational approval, credit ownership or competition eligibility is
asserted by this connector.
