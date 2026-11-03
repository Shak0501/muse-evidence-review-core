"""Real fixed-destination Meta HTTPS adapter; default application has no Live authority.

Authority and credential objects are injected by an independently approved host.
This module contains no embedded credentials and does not issue execution permission.
"""
import http.client
import getpass
import os
import re
import ssl
import sys
import time
import warnings
from .contracts import (Refusal, MODEL, ENDPOINT, canonical, digest, strict_json, require,
                        integer, text, secret_like, verify_review, offline_review)

MAX_REPLY = 262144


class TtyCredentialChannel:
    """Proposed server-side manual channel, NOT enabled by the distributed launcher.

    Host must separately approve this mechanism or supply its protected service.
    Never fall back to env, files, a browser field or an echoed input prompt.
    """
    def acquire(self, scope):
        require(os.isatty(sys.stdin.fileno()) and os.isatty(sys.stderr.fileno()), 'SECURE_TTY_REQUIRED')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Approved Meta request only — secret (hidden): ')
        try:
            return bytearray(value.encode('ascii'))
        except UnicodeError:
            raise Refusal('CREDENTIAL_FORMAT') from None
        finally:
            value = None


def safe_code(exc):
    return exc.code if isinstance(exc, Refusal) and re.fullmatch(r'[A-Z0-9_]{1,100}', exc.code) else 'EXECUTION_FAILED'


def no_secret_in_decoded(value, secret):
    if type(value) is str:
        require(secret not in value, 'SECRET_ECHO_REJECTED')
    elif type(value) is list:
        for item in value:
            no_secret_in_decoded(item, secret)
    elif type(value) is dict:
        for key, item in value.items():
            no_secret_in_decoded(key, secret); no_secret_in_decoded(item, secret)


def parse_response(status, raw, req, draft):
    require(status == 200, 'HTTP_STATUS_REJECTED')
    require(not secret_like(raw.decode('utf-8', errors='replace')), 'SECRET_LIKE_RESPONSE_REJECTED')
    value = strict_json(raw, MAX_REPLY)
    require(type(value) is dict, 'RESPONSE_TYPE')
    required = {'id', 'model', 'status', 'output', 'usage', 'tools'}
    allowed = required | {'object', 'created_at', 'error', 'incomplete_details', 'instructions',
        'parallel_tool_calls', 'previous_response_id', 'reasoning', 'store', 'temperature', 'text',
        'tool_choice', 'top_p', 'truncation', 'user', 'metadata', 'service_tier', 'background',
        'max_output_tokens', 'conversation'}
    require(required <= set(value) <= allowed, 'RESPONSE_FIELDS')
    require(type(value['id']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,256}', value['id']), 'RESPONSE_ID')
    require(value['model'] == MODEL and value['status'] == 'completed', 'MODEL_OR_COMPLETION')
    require(value.get('error') is None and value.get('incomplete_details') is None, 'RESPONSE_INCOMPLETE')
    require(type(value['tools']) is list and not value['tools'], 'TOOLS_REJECTED')
    require(value.get('background', False) is False, 'BACKGROUND_REJECTED')
    require(value.get('previous_response_id') in (None, '') and value.get('conversation') in (None, ''), 'REMOTE_CONTEXT_REJECTED')
    require(value.get('store', False) is False, 'STORE_REJECTED')
    tier = value.get('service_tier')
    require(tier is None or type(tier) is str and tier in ('auto', 'default'), 'SERVICE_TIER_REJECTED')
    warnings = ['SERVICE_TIER_AUTO_ECHO_NOT_PRICE_PROOF'] if tier == 'auto' else []
    usage = value['usage']
    require(type(usage) is dict and {'input_tokens', 'output_tokens', 'total_tokens'} <= set(usage) <=
        {'input_tokens', 'output_tokens', 'total_tokens', 'input_tokens_details', 'output_tokens_details'}, 'USAGE_FIELDS')
    i = integer(usage['input_tokens']); o = integer(usage['output_tokens'], maximum=2048)
    require(integer(usage['total_tokens']) == i+o, 'USAGE_TOTAL')
    for name, detail, maximum in [('input_tokens_details', 'cached_tokens', i), ('output_tokens_details', 'reasoning_tokens', o)]:
        if name in usage:
            require(type(usage[name]) is dict and set(usage[name]) == {detail}, 'USAGE_DETAIL_FIELDS')
            integer(usage[name][detail], maximum=maximum)
    require(type(value['output']) is list and 1 <= len(value['output']) <= 8, 'OUTPUT_TYPE')
    answers = []
    for item in value['output']:
        require(type(item) is dict, 'OUTPUT_ITEM_TYPE')
        if item.get('type') == 'reasoning':
            require(set(item) <= {'id', 'type', 'summary', 'content', 'encrypted_content', 'status'}, 'REASONING_FIELDS')
            continue
        require(item.get('type') == 'message' and item.get('role') == 'assistant' and
                item.get('status') == 'completed', 'OUTPUT_CAPABILITY_REJECTED')
        require(set(item) <= {'id', 'type', 'status', 'role', 'content'} and type(item.get('content')) is list, 'MESSAGE_FIELDS')
        for part in item['content']:
            require(type(part) is dict and part.get('type') == 'output_text' and
                    set(part) <= {'type', 'text', 'annotations', 'logprobs'}, 'OUTPUT_CONTENT_REJECTED')
            require(part.get('annotations', []) == [] and part.get('logprobs', []) in (None, []), 'OUTPUT_EXTRAS_REJECTED')
            answers.append(text(part.get('text'), 65536))
    require(len(answers) == 1, 'ONE_VISIBLE_ANSWER_REQUIRED')
    review = verify_review(strict_json(answers[0].encode('utf-8'), 65536), req, draft)
    receipt = {'provider': 'META', 'model': value['model'], 'response_id': value['id'], 'usage': usage,
        'content_validation': 'SCHEMA_AND_EXACT_QUOTES_VALID', 'semantic_acceptance': 'PENDING_HUMAN_REVIEW',
        'service_tier_reported': tier, 'tier_alignment': 'UNVERIFIED', 'pricing_equivalence_verified': False,
        'warnings': warnings, 'billing': 'UNRECONCILED', 'formal_approval': 'NOT_ESTABLISHED'}
    return review, receipt


class MetaHTTPS:
    """One POST, TLS verification, no redirects/proxy/env/key lookup/retry/fallback."""
    def send(self, body, secret, still_current):
        self.trace = {'phase':'NOT_STARTED','http_status':None}
        require(type(body) is bytes and len(body) <= 65536, 'REQUEST_SIZE')
        require(type(secret) is bytearray and 16 <= len(secret) <= 4096, 'CREDENTIAL_TYPE')
        require(all(33 <= b <= 126 for b in secret), 'CREDENTIAL_FORMAT')
        require(not secret.startswith(b'SYNTHETIC_'), 'SYNTHETIC_SECRET_ON_REAL_TRANSPORT')
        still_current()
        conn = http.client.HTTPSConnection('api.meta.ai', 443, timeout=15, context=ssl.create_default_context())
        if getattr(self, 'fixed_destination_guard', False):
            from .network_guard import fixed_connection
            conn._create_connection = fixed_connection
        deadline = time.monotonic()+45
        try:
            # Headers remain transient; never included in receipts, stdout or exceptions.
            self.trace['phase']='ATTEMPTED_UNKNOWN'
            conn.request('POST', '/v1/responses', body=body, headers={
                'Content-Type': 'application/json', 'Authorization': 'Bearer '+secret.decode('ascii'),
                'Accept': 'application/json', 'User-Agent': 'MUSE-Evidence-Core-R1'})
            response = conn.getresponse()
            self.trace.update(phase='HTTP_RESPONSE_RECEIVED', http_status=response.status)
            require(response.getheader('Content-Type', '').split(';')[0].strip().lower() == 'application/json', 'HTTP_CONTENT_TYPE')
            length = response.getheader('Content-Length')
            require(length is None or length.isdigit() and int(length) <= MAX_REPLY, 'RESPONSE_SIZE')
            require(response.getheader('Content-Encoding', 'identity') == 'identity', 'COMPRESSED_RESPONSE_REJECTED')
            chunks, total = [], 0
            while True:
                still_current()
                require(time.monotonic() <= deadline, 'WALL_TIMEOUT')
                block = response.read1(min(8192, MAX_REPLY+1-total))
                if not block:
                    break
                total += len(block)
                require(total <= MAX_REPLY, 'RESPONSE_SIZE')
                chunks.append(block)
            still_current()
            self.trace['phase']='RESPONSE_BODY_RECEIVED'
            return response.status, b''.join(chunks)
        finally:
            conn.close()


def approved_scope(scope, req):
    """Validate evidence returned by the approved host; this does NOT authenticate a self-uploaded grant."""
    require(type(scope) is dict and set(scope) == {'request_id', 'body_sha', 'endpoint', 'model', 'binding',
        'expires_at', 'issued_at', 'maximum_attempts', 'risk_micro_usd', 'risk_policy', 'grants',
        'runner_reference', 'pilot_reference', 'account_reference', 'credential_reference'}, 'AUTHORITY_SCOPE_FIELDS')
    for name, expected in [('request_id', req['id']), ('body_sha', req['body_sha']), ('endpoint', ENDPOINT),
                           ('model', MODEL), ('binding', req['binding'])]:
        require(scope[name] == expected, 'AUTHORITY_BINDING')
    integer(scope['maximum_attempts'], 1, 1); integer(scope['risk_micro_usd'], 1, 100000)
    require(scope['risk_policy'] == 'META_LIVE01_RISK_ONCE_V1', 'RISK_POLICY_NOT_APPROVED')
    require(type(scope['issued_at']) in (int, float) and type(scope['expires_at']) in (int, float) and
            scope['issued_at'] <= time.time() < scope['expires_at'], 'AUTHORITY_EXPIRED_OR_CLOCK_ROLLBACK')
    grants = scope['grants']
    require(type(grants) is dict and set(grants) == {'DATA_EGRESS', 'BUDGET_ONCE', 'FINAL_DISPATCH', 'IMMEDIATE_HUMAN_CONFIRMATION'}, 'INDEPENDENT_GRANTS_REQUIRED')
    require(all(type(x) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', x) for x in grants.values()) and
            len(set(grants.values())) == 4, 'GRANT_IDENTITIES')
    for name in ['runner_reference', 'pilot_reference', 'account_reference', 'credential_reference']:
        require(type(scope[name]) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', scope[name]), 'HOST_REFERENCE')
    return scope


def run_live(store, rid, confirmed, authority=None, credentials=None, transport=None):
    # These objects can only be wired on the server by a separately approved host.
    # Browser data, JSON files and environment switches cannot install an authority.
    require(authority is not None and credentials is not None, 'LIVE_AUTHORIZATION_PENDING')
    require(confirmed is True, 'EXPLICIT_CONFIRMATION_REQUIRED')
    req = store.request(rid)
    require(req['mode'] == 'META_LIVE', 'REQUEST_MODE')
    store.check_current(req)
    scope = approved_scope(authority.inspect(req), req)
    req, draft = store.begin(rid, confirmed, 'META_LIVE')
    secret = None
    try:
        # Existing authority must durably consume its own once-only permit and reserve.
        # This local marker never substitutes for that responsibility.
        require(authority.consume(req, scope) is True, 'FORMAL_CONSUMPTION_REQUIRED')
        store.check_current(req)
        secret = credentials.acquire(scope)
        require(type(secret) is bytearray and 16 <= len(secret) <= 4096 and all(33 <= b <= 126 for b in secret), 'CREDENTIAL_TYPE')
        def authority_valid():
            approved_scope(scope, req)
            require(authority.revalidate(req, scope) is True, 'AUTHORITY_REVOKED_OR_CHANGED')
        def current_authority():
            store.check_current(req)
            authority_valid()
        current_authority()
        sender = transport if transport is not None else MetaHTTPS()
        status, raw = sender.send(req['body'].encode('utf-8'), secret, current_authority)
        require(type(raw) is bytes and len(raw) <= MAX_REPLY, 'RESPONSE_SIZE')
        require(not secret or bytes(secret) not in raw, 'SECRET_ECHO_REJECTED')
        no_secret_in_decoded(strict_json(raw, MAX_REPLY), secret.decode('ascii'))
        review, receipt = parse_response(status, raw, req, draft)
        no_secret_in_decoded(review, secret.decode('ascii'))
        no_secret_in_decoded(receipt, secret.decode('ascii'))
        receipt.update(provenance='REAL_META_RESPONSE' if type(sender) is MetaHTTPS else 'SYNTHETIC_PREFLIGHT_TRANSPORT',
                       risk_policy=scope['risk_policy'], risk_micro_usd=scope['risk_micro_usd'])
        # Never persist secret/account/credential references from the host scope.
        return store.finish(req, review, receipt, raw, authority_valid)
    except Exception as exc:
        code = safe_code(exc)
        store.fail(rid, code)
        raise Refusal(code) from None
    finally:
        if type(secret) is bytearray:
            secret[:] = b'\x00' * len(secret)
        # Python/TLS may make transient copies. This is not a secure-erasure claim.


def run_offline(store, rid, confirmed):
    req, draft = store.begin(rid, confirmed, 'OFFLINE_DEMO')
    try:
        review = verify_review(offline_review(req, draft), req, draft)
        receipt = {'provenance': 'OFFLINE_SIMULATION', 'provider_calls': 0, 'usage': None,
                   'billing': 'NOT_APPLICABLE_OFFLINE', 'semantic_acceptance': 'SIMULATED_NOT_AI_JUDGMENT',
                   'deterministic_check': 'EXACT_QUOTES_ONLY', 'formal_approval': 'NOT_ESTABLISHED'}
        return store.finish(req, review, receipt, canonical(review))
    except Exception as exc:
        code = safe_code(exc); store.fail(rid, code)
        raise Refusal(code) from None
