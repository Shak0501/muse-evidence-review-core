# Public live-adapter interface — MUSE_META_RESPONSES_R1

This is the interface implemented by the current adapter, not an enabled Live
host. Offline Demo runs independently. The distributed launcher has no authority
or credential connection; selecting Live only prepares a request preview.

## Server-side interfaces

A separately reviewed host must provide:

- `inspect(request) -> scope`: authenticate the operator's permission and return
  the exact authorized scope. Do not trust grants supplied by the browser.
- `consume(request, scope) -> True`: durably consume the one-use permission before
  obtaining a secret or sending. Reject duplicates across concurrent calls and
  restarts, including when an ordinary workspace is replaced.
- `revalidate(request, scope) -> True`: check the same consumed permission is
  still applicable. Never reissue it or replenish an attempt.
- `credentials.acquire(scope) -> bytearray`: obtain the account's secret only
  after consumption, restricting the caller, purpose and credential reference.

The strict scope fields in `core/meta_live.py:approved_scope` are:

`request_id`, `body_sha`, `endpoint`, `model`, `binding`, `issued_at`, `expires_at`,
`maximum_attempts`, `risk_micro_usd`, `risk_policy`, `grants`, `runner_reference`,
`pilot_reference`, `account_reference`, `credential_reference`.

These existing field names are retained for adapter compatibility. References
must be non-secret opaque identifiers, not credentials. The validator requires
one attempt, a positive risk allowance no greater than 100000 micro-USD, its
fixed policy identifier and four distinct grants: `DATA_EGRESS`, `BUDGET_ONCE`,
`FINAL_DISPATCH`, `IMMEDIATE_HUMAN_CONFIRMATION`.

The core checks shape and content binding; it cannot establish a host's
legitimacy from method names or plausible reference strings. Synthetic test
objects provide no permission to send. A proposed independent demo host needs
a separately accepted, versioned scope; the current scope must not be renamed
or populated with invented references to make it appear compatible.

## Request and execution boundary

The request binds the session, source ID/version/raw UTF-8 SHA/epoch, saved draft
revision/raw UTF-8 SHA, goal/revision, policy SHA and adapter version. Its body is
rebuilt from authoritative saved state and compared byte-for-byte before use.
Unadopted drafts, generation history and unrelated fields are not included.

The adapter permits one TLS-verified POST to `https://api.meta.ai/v1/responses`,
model `muse-wonder-1.0`, reasoning low and at most 2048 output tokens including
reasoning. Tools, background, storage, streaming and truncation are disabled.
There is no automatic retry, redirect, Count request or provider fallback.

The local attempt marker is persisted before permission consumption and secret
acquisition. It is not a global permission store or proof of payment reservation.
The host must enforce durable replay protection independently of deletable
workspace state, and bound its own calls and credential cancellation.

Scope is rechecked before sending, during reads and before saving the result.
Result commit checks current saved identities under the workspace lock. Edits or
Stop cannot make an old response current for changed content. Failures after
consumption retain the attempt and `UNKNOWN_NO_RETRY`; they do not establish
zero charges. Stop cannot retract work already received by Meta.

## Credentials, records and cost

No secret belongs in source control, a browser, a command argument or a log.
The hidden-terminal credential class is unapproved, disabled by the launcher,
and not qualified for bounded cancellation. A host must use a separately
accepted server-side mechanism. Buffer clearing is not secure memory erasure.

Safe successful raw responses, usage and quotation checks are saved in private
local state; rejected responses that could expose secrets are not retained.
Sanitized failure codes and consumed state remain. Storage is not encrypted.
Billing remains `UNRECONCILED` until checked independently. A US$0.10 risk
allowance is not a provider-guaranteed charge ceiling. Operators need their own
eligible account, applicable pricing and explicit permission; the repository
does not supply credits or authorize use of the author's account.

## What offline tests establish

Synthetic transports exercise request/response formats, local quotation checks
and refusal paths. They do not qualify a real host, credentials, account, network
connection or model behavior. Test output uses `SYNTHETIC_PREFLIGHT_TRANSPORT`;
only the real transport may produce `REAL_META_RESPONSE`. No real review has
been completed for this core. A reproducible independent Live host remains a
delivery gap; copying the test doubles is not a deployment method.
