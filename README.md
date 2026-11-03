# MUSE Evidence Review Core

Ask Meta to review a saved draft against an exact source, inspect its quotations,
then revise with an explicit version boundary. A review of an older revision
becomes **STALE**. Model judgments, local quote checks and human approval remain
separate.

Earlier private research and editor scaffolding informed this project. This
standalone competition implementation was newly written on November 3, 2026;
that earlier private implementation is not included or required. The P2 connector
adds independent local consent, terminal credential input and once-only request
records to the new core. No competition eligibility ruling is claimed.

## Recorded live demo

[Watch the hackathon demo — real Meta inference and STALE](https://youtu.be/LRThYu3e7CU)

## Run the main Meta workflow

Requirements: an existing Python 3.9+ installation on macOS or Linux, a local
interactive terminal, a browser, and your own eligible Meta Model API account.
Only Python's standard library is used. Nothing needs to be installed with pip.
Windows terminal and filesystem behavior are not qualified.

From the directory containing this README:

```sh
python3 -I -B -S verify.py
python3 -I -B -S live.py
```

Open the printed `http://127.0.0.1:...` address in the same computer's browser.
Startup does not obtain a credential, resolve Meta's hostname, or send a request.
Do not expose this local service to other machines or use an untrusted shared
computer. Keep the terminal open.

1. Load the Larch synthetic source. Insert the four-sentence example or write your
   own non-secret draft, then **Save draft**.
2. Select **Meta Live** and **Preview this review request**. Review the complete
   source, saved draft, exact serialized request, model, destination, program
   Manifest, account reference, revision and request SHA. Bytes are not tokens.
3. Make each decision separately: B1 demo-use acceptance, risk acceptance,
   DATA_EGRESS, BUDGET_ONCE and FINAL_DISPATCH. All boxes start unchecked.
   The final **Confirm and request one Meta review** button separately records
   IMMEDIATE_HUMAN_CONFIRMATION. Closing the preview sends nothing.
4. Only after that final action, enter your own Meta API credential in the server
   terminal's hidden prompt. It is never a browser field, environment variable,
   command argument or credential file. Ctrl-C or Escape cancels; Ctrl-D ends
   input; a 60-second timeout also ends it. There is no echo fallback. Ordinary
   input cancellation restores the terminal. Abrupt OS termination may require
   restoring the terminal yourself. No absolute memory-erasure claim is made.
5. Read the actual response, quote validation and reported usage. Real Meta may
   produce any valid distribution of the four categories, not necessarily one of
   each. Schema or citation failures remain failures; no mock answer replaces
   them. No result automatically approves, signs, publishes or rewrites a draft.
6. Edit and save. The previous review becomes STALE, including when the old text
   is later restored. Each new request needs a new preview and explicit consent.

Targeted engineering tests remain offline checks. Separately, on November 3,
2026, the author completed a human-confirmed integrated Meta Live demonstration
using `muse-wonder-1.0`. The application received HTTP 200, validated the
response schema and exact source quotations locally, and showed the prior
review becoming **STALE** after a saved human revision. This bounded demo does
not establish general semantic accuracy, billing reconciliation or production
approval. Judges use their own eligible Meta account, credentials, independent
decisions and costs. This code grants no access to the author's credits.

`muse-wonder-1.0` at `https://api.meta.ai/v1/responses` is the only destination.
The frozen request uses low reasoning, 2048 maximum output tokens, no tools,
background execution, streaming, count call, remote continuation, retries or
provider fallback. The US$0.10 risk allowance presented for acceptance is **not a
provider-enforced billing ceiling**. Account eligibility, current pricing and
actual fees remain the operator's responsibility. Usage and billing are not the
same thing; unknown usage is `null`, not zero.

## Offline backup (no account or key)

```sh
python3 -I -B -S app.py
```

Open the printed address; load Larch, insert the example, save, preview and run
one **Offline demo** review. Its response is a fixed synthetic fixture, explicitly
labelled as such. It demonstrates UI, identities and quote checks, not Meta's
semantic capability. One offline attempt per practice workspace remains the
baseline rule. No Live capability is unlocked by that practice consent.

## Stop, records and uncertainty

**Emergency Stop** stops new local work and cancels waiting credential input.
It cannot withdraw an already-sent remote request or guarantee a refund. An
already-sent bounded reply may be retained as STALE historical evidence.
Close the server with **Control-C** in its terminal; wait for `stopped: true`.
Closing the browser alone does not stop the server.

Live writing is in `.muse-p2-workspace`; separate private once-only records are in
`.muse-consents`. Offline writing is in `.muse-local`. These directories are
excluded from Git and from the public Manifest. They contain local session
identities, requests and safe replies, never deliberately retained credentials.
Keep them private; do not publish them or include them in a video.

A durable consumed marker is written **before** credential acquisition or
transmission. Cancellation after final confirmation consumes that request even
when transport never begins. Meta Live supports multiple new requests, each with
a new request ID, its own preview and explicit human confirmation. Each request
ID permits at most one transmission attempt: this is not a once-per-app limit
or permission to retry a failed, timed-out or UNKNOWN request. Stop and preserve
such a result; do not repeatedly send requests to obtain a better recording.
Offline Demo remains limited to one attempt per practice workspace.
A stopped workspace can be viewed but
cannot resume dispatch. To deliberately start fresh writing after stopping:

```sh
python3 -I -B -S live.py --state /path/to/a/new-private-workspace --consents /path/to/the/same-private-consents
```

Use your actual private paths outside the code directory. The parent directories
must exist. Preserve the consent directory: copying an ordinary workspace into a
new consent registry is rejected, and consumed request IDs cannot be reused.
Restart invalidates pending requests and current results; interrupted attempts
remain UNKNOWN and are not resent. Missing, corrupt, unsafe or unwritable records
fail closed. There is no Reset that restores a spent permit. At most 16 previews
per workspace and 256 consent records per registry bound local storage; reaching
those limits is a refusal, not permission to erase history or retry.

This is a local demo-use record, not an organizational authority, account balance
or financial ledger. It assumes a trusted machine owner. It does not defend
against an administrator rolling back the entire disk or editing program/state
files. Existing budgets and historical obligations are not imported or changed.
See [the connector contract](LIVE_HOST_CONTRACT.md).

## Verify the new connector offline

```sh
python3 -I -B -S connector_test.py
```

This verifies the A–D scope using synthetic secrets through actual PTYs, controlled
responses, local HTTP, process races and cold startup. Its process network fence
refuses non-loopback access and cannot switch to Live mode. Synthetic outputs and
decisions remain labelled. The existing targeted baseline tests are separately
available with `python3 -I -B -S test.py`; they are not a fresh count of new methods.
Neither command performs a real Meta inference or uses real credentials.

## Limits and disclosure

Only the fixed fictional Larch source is supported. Drafts are limited to 8192
UTF-8 bytes and eight explicitly segmented sentences. No CSV, PDF, other AI model,
organizational roles, legal certification, automated publishing or signature flow
is included. Local quotation validity proves where words occur; it does not prove
semantic truth, completeness or professional correctness. Unsupported or invalid
responses require human review.

An earlier short Meta connectivity test is separate from this integrated demo.
The first integrated live response was rejected by the original local parser;
the unchanged captured response later passed offline revalidation after a
compatibility fix, without another Meta API call. The subsequently recorded
integrated demo shows real Meta inference. Offline Demo findings remain
synthetic, not real Meta judgments.

MIT, Copyright (c) 2026 Shak Lai. See [LICENSE](LICENSE) and
[RIGHTS_STATUS.md](RIGHTS_STATUS.md). No prior private code, private session,
credential, third-party source, artwork, model weight or hidden service is
required. New work and source rights are disclosed without granting rights to
unpublished private works. Publication and competition submission are separate
human decisions.
