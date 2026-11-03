# MUSE Evidence Review Core

**Private release candidate · MIT license approved by Shak Lai; publication pending.**

## What existed before the event

Earlier private editor scaffolding and governance research informed the product
requirements. They are not included, imported or required by this new core. We
do not claim that the earlier platform was created during the hackathon.

## What was built during the event

This specification-based R1 was newly implemented on **2026-11-03**: one synthetic
source, human-saved UTF-8 draft revisions, a bounded review request, exact local
quotation checks, four distinct verdict displays and stale-result invalidation.
The Python server, storage, Meta HTTPS adapter and browser interface were written
for this standalone core; the earlier private implementation is not bundled.
The four-sentence test was provided in the task; the short Larch notice and offline
response fixture were newly authored for this implementation. No historical Git
timestamps or commits are fabricated. On 2026-11-03 (Asia/Taipei), Shak Lai
confirmed the right to license this standalone competition core under MIT.
See [LICENSE](LICENSE) and [RIGHTS_STATUS.md](RIGHTS_STATUS.md). Unincluded private
works and local user data are outside this distribution.

## How to run the new project

Requirements: an existing **Python 3.9+ on macOS or Linux**, a modern browser, and
a writable local directory. Only the Python standard library is used. No pip,
Node, CDN, downloaded model, private source code or API key is needed.

In Terminal, from this directory:

```sh
python3 -I -B -S verify.py
python3 -I -B -S app.py
```

Open the exact `http://127.0.0.1:PORT` URL printed by the server. It listens only
on loopback. The port is chosen locally; there is no fixed private absolute path.
Local data goes into `.muse-local/` with owner-only permissions; it is excluded
from the release manifest and Git. Never commit this folder. Use a private local
filesystem. This storage is not encrypted and does not establish payment or
execution permission. Close the server with **Control-C**, and confirm `stopped: true`.

In the browser:

1. **Load Larch source**.
2. **Use the four-sentence example**, or write it manually; press **Save draft**.
3. Keep **Offline demo** selected. **Preview this review request**, then explicitly
   **Run this offline review once**.
4. Read the four simulated findings. Expand **View exact source quotation** beside
   the home-visits contradiction. The missing bulbs claim is not a contradiction.
5. Edit and save the draft. The earlier result becomes **STALE**, even if later
   edits restore identical text. Old revision evidence never approves a new one.
6. **Emergency Stop** blocks subsequent work immediately. It does not delete the
   draft or claim that remote work/costs are cancelled. Then Control-C the server.

One offline review attempt is allowed in this local workspace. Reopening the same
workspace does not replenish attempts or make old reviews current. There is no
Reset-to-retry button. An offline result never grants permission to make a paid call.

Optional targeted verification (only this new core):

```sh
python3 -I -B -S test.py
```

## How to use real Meta inference

The adapter implements a single TLS-verified POST to
`https://api.meta.ai/v1/responses` using `muse-wonder-1.0`. It parses actual
Responses output/usage and verifies source quotes locally. It does not force
real results to match the four synthetic labels.

**The distributed launcher deliberately has no Live authority or credential
connection. Selecting Meta Live produces an exact request preview, not permission
to send. No CLI switch, browser field or uploaded grant can enable it.**

A server-side host connection is still required through
`make_server(store, authority=..., credentials=...)`; the exact interface and
remaining requirements are in [LIVE_HOST_CONTRACT.md](LIVE_HOST_CONTRACT.md).
No independently runnable Live host is included yet. Test doubles must never be
used to authorize real requests. A future demo-only host needs its own versioned
scope and acceptance; documentation alone does not enable that path.

The optional hidden-terminal credential class is an **unapproved proposal**, not
an enabled or qualified secret service. No real credential has been used with it.
Do not put keys in a browser, command argument, recording, repository or log.
Clearing a Python buffer is not a guarantee that every memory copy is erased.

Real use requires the operator's own eligible Meta account, a reviewed server-side
credential connection, explicit approval of the exact outgoing data, a one-use
risk allowance and immediate confirmation before sending. The operator is
responsible for actual provider charges. This repository grants no account access,
credits or execution permission. **LIVE_AUTHORIZATION_PENDING**: no real Meta
review has been completed for this core.

## What remains simulated

Offline findings are deterministic fixture output. Unknown wording returns
NEEDS_HUMAN_REVIEW. Fake transport/authority/credential objects exist only in the
tests. They never establish formal authorization or real usage. No second AI
provider is included. Manual writing and local quotation checking are not AI calls.

## Known limitations

- Only the fixed Larch synthetic source; no arbitrary source imports, CSV, PDF,
  professional-domain checks, signatures or team roles. English UI only.
- Sentence spans are mechanical punctuation segments, not general semantic claim
  extraction. At most eight segments; draft maximum 8,192 UTF-8 bytes. No Unicode
  normalization or newline conversion occurs when saving the submitted string.
- Exact quotes prove location/identity, not entailment or truth. Actual model
  classifications still require human review. Local arithmetic is not implemented.
- No automatic rewrite, adoption, approval, retry or fallback. An attempt consumed
  before an execution failure stays consumed/UNKNOWN; no automatic retry is allowed.
- The proposed US$0.10 risk allowance is not a provider charge ceiling. Actual
  usage is preserved; billing stays UNRECONCILED until independently checked.
- A real network call has bounded socket waits (15s) and a checked 45s deadline;
  a blocked read may return after the deadline by up to its socket timeout.
  Local Stop cannot retract a request already received by Meta.
- Successful raw responses are retained only in private local state. Rejected
  responses are not stored if they may expose secrets; sanitized failure codes
  and consumed-attempt state remain. There is no disk secure-erasure guarantee.
- Current code identity is verifiable; organizer eligibility,
  the real Live recording, repository publication and submission remain pending.
  Discord application guidance is not a final organizer ruling.

**Current default: OFFLINE DEMO. Live dispatch is disabled; no automatic retry.**
