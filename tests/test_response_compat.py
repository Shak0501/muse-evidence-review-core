"""Synthetic response-metadata regression tests. No captured operator records.

Run only this suite: python3 -I -B -S tests/test_response_compat.py
Fixtures extend the original synthetic wire helper; no real response is embedded.
"""
import copy
import http.client
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

AUDIT = {'external_network_denied': 0, 'loopback_connects': 0,
         'child_denied': 0, 'credential_device_denied': 0}


def offline_guard(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'):
        AUDIT['child_denied'] += 1
        raise PermissionError('COMPAT_TEST_CHILD_DENIED')
    if event == 'open' and isinstance(args[0], str) and args[0].startswith('/dev/'):
        AUDIT['credential_device_denied'] += 1
        raise PermissionError('COMPAT_TEST_DEVICE_DENIED')
    if event in ('socket.gethostbyname', 'socket.gethostbyaddr'):
        AUDIT['external_network_denied'] += 1
        raise PermissionError('COMPAT_TEST_RESOLVER_DENIED')
    if event in ('socket.connect', 'socket.bind', 'socket.sendto', 'socket.getaddrinfo'):
        address = args[:2] if event == 'socket.getaddrinfo' else args[-1]
        try:
            local = isinstance(address, tuple) and ipaddress.ip_address(address[0]).is_loopback
        except (ValueError, TypeError, IndexError):
            local = False
        if not local:
            AUDIT['external_network_denied'] += 1
            raise PermissionError('COMPAT_TEST_EXTERNAL_NETWORK_DENIED')
        if event == 'socket.connect':
            AUDIT['loopback_connects'] += 1


if __name__ == '__main__':
    sys.addaudithook(offline_guard)

from core.contracts import Refusal, EXAMPLE, SOURCE, canonical, digest, strict_json
from core.meta_live import parse_response
from core.store import Store
from app import make_server
from test_core import wire

CHECKS = []


class ResponseCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.draft = EXAMPLE
        self.req = {'id': 'synthetic-response-compat-request',
                    'binding': {'draft_sha': digest(self.draft)}}
        self.good = wire(self.req, self.draft)
        self.good.update(completed_at=1700000000.25, top_logprobs=0)

    def parse(self, value=None, raw=None, status=200):
        return parse_response(status, raw if raw is not None else canonical(value), self.req, self.draft)

    def reject(self, code, value=None, raw=None, status=200):
        with self.assertRaises(Refusal) as caught:
            self.parse(value, raw, status)
        self.assertEqual(caught.exception.code, code)
        CHECKS.append({'method': self._testMethodName, 'expected_refusal': code,
                       'actual_refusal': caught.exception.code})

    def change_inner(self, change):
        value = copy.deepcopy(self.good)
        part = value['output'][0]['content'][0]
        inner = strict_json(part['text'].encode())
        change(inner)
        part['text'] = canonical(inner).decode()
        return value

    def test_B01_optional_missing_null_and_numeric_boundaries(self):
        old = wire(self.req, self.draft)
        expected = self.parse(old)
        additions = [{}, {'completed_at': None}, {'top_logprobs': None},
                     {'completed_at': None, 'top_logprobs': None}]
        # The documented Unix-time number has no extra minimum/maximum in this contract.
        additions += [{'completed_at': x} for x in (-1.5, 0, 1700000000, 1700000000.25)]
        additions += [{'top_logprobs': x} for x in (0, 1, 20)]
        additions += [{'completed_at': 1700000000.25, 'top_logprobs': 20}]
        for addition in additions:
            with self.subTest(metadata=addition):
                self.assertEqual(self.parse(dict(old, **addition)), expected)

    def test_B02_completed_at_wrong_types_and_nonfinite_rejected(self):
        for bad in (True, False, '1700000000', [], {}, [1700000000]):
            with self.subTest(value=bad):
                self.reject('RESPONSE_COMPLETED_AT', dict(self.good, completed_at=bad))
        raw = canonical(dict(self.good, completed_at=0))
        for token, code in [(b'NaN', 'JSON_NUMBER'), (b'Infinity', 'JSON_NUMBER'),
                            (b'-Infinity', 'JSON_NUMBER'), (b'1e999', 'RESPONSE_COMPLETED_AT')]:
            with self.subTest(token=token):
                self.reject(code, raw=raw.replace(b'"completed_at":0', b'"completed_at":' + token, 1))

    def test_B03_top_logprobs_exact_integer_range(self):
        for bad in (-1, 21, 999999, True, False, 0.0, 20.0, '0', [], {}):
            with self.subTest(value=bad):
                self.reject('RESPONSE_TOP_LOGPROBS', dict(self.good, top_logprobs=bad))

    def test_B04_metadata_does_not_grant_or_change_result(self):
        before = canonical(self.req)
        old_review, old_receipt = self.parse(wire(self.req, self.draft))
        review, receipt = self.parse(self.good)
        self.assertEqual((review, receipt), (old_review, old_receipt))
        self.assertEqual(canonical(self.req), before)
        self.assertEqual(receipt['semantic_acceptance'], 'PENDING_HUMAN_REVIEW')
        self.assertEqual(receipt['formal_approval'], 'NOT_ESTABLISHED')
        self.assertEqual(receipt['billing'], 'UNRECONCILED')
        self.assertNotIn('grants', receipt)
        self.assertNotIn('provenance', receipt)

    def test_C01_unknown_and_missing_outer_fields_still_rejected(self):
        for key in ('arbitrary_metadata', 'completed_at_extra', 'approved', 'tool_results'):
            with self.subTest(key=key):
                self.reject('RESPONSE_FIELDS', dict(self.good, **{key: None}))
        value = copy.deepcopy(self.good)
        del value['usage']
        self.reject('RESPONSE_FIELDS', value)

    def test_C02_model_completion_tools_and_remote_context_guards(self):
        changes = [('model', 'other-model', 'MODEL_OR_COMPLETION'),
                   ('status', 'incomplete', 'MODEL_OR_COMPLETION'),
                   ('error', {'code': 'failed'}, 'RESPONSE_INCOMPLETE'),
                   ('incomplete_details', {'reason': 'max_output_tokens'}, 'RESPONSE_INCOMPLETE'),
                   ('tools', None, 'TOOLS_REJECTED'),
                   ('tools', [{'type': 'web_search'}], 'TOOLS_REJECTED'),
                   ('previous_response_id', 'other-response', 'REMOTE_CONTEXT_REJECTED'),
                   ('conversation', {'id': 'other-session'}, 'REMOTE_CONTEXT_REJECTED'),
                   ('background', True, 'BACKGROUND_REJECTED'),
                   ('store', True, 'STORE_REJECTED'),
                   ('service_tier', 'priority', 'SERVICE_TIER_REJECTED')]
        for key, bad, code in changes:
            with self.subTest(key=key, value=bad):
                self.reject(code, dict(self.good, **{key: bad}))
        for status in (302, 400, 429, 500):
            with self.subTest(status=status):
                self.reject('HTTP_STATUS_REJECTED', self.good, status=status)

    def test_C03_inner_binding_claim_coverage_and_coordinates(self):
        changes = [('REVIEW_BINDING', lambda x: x.update(request_id='other-request')),
                   ('REVIEW_BINDING', lambda x: x.update(draft_sha='0' * 64)),
                   ('REVIEW_BINDING', lambda x: x.update(schema='OTHER_SCHEMA')),
                   ('INCOMPLETE_REVIEW', lambda x: x['findings'].pop()),
                   ('CLAIM_ID', lambda x: x['findings'][1].update(claim_id='c1')),
                   ('CLAIM_COORDINATES', lambda x: x['findings'][0].update(start=1)),
                   ('CLAIM_COORDINATES', lambda x: x['findings'][0].update(text='Different sentence.')),
                   ('INTEGER_RANGE', lambda x: x['findings'][0].update(start=False)),
                   ('VERDICT', lambda x: x['findings'][0].update(verdict='APPROVED')),
                   ('EVIDENCE_REQUIRED', lambda x: x['findings'][0].update(citations=[]))]
        for code, change in changes:
            with self.subTest(code=code):
                self.reject(code, self.change_inner(change))

    def test_C04_duplicate_json_and_unknown_inner_fields(self):
        self.reject('DUPLICATE_JSON_KEY', raw=b'{"top_logprobs":0,' + canonical(self.good)[1:])
        value = copy.deepcopy(self.good)
        part = value['output'][0]['content'][0]
        part['text'] = '{"schema":"MUSE_REVIEW_R1",' + part['text'][1:]
        self.reject('DUPLICATE_JSON_KEY', value)
        self.reject('SCHEMA_FIELDS', self.change_inner(lambda x: x.update(human_approved=True)))
        self.reject('SCHEMA_FIELDS', self.change_inner(lambda x: x['findings'][0].update(extra=True)))

    def test_C05_exact_quotes_source_identity_and_unicode_ranges(self):
        def quote_change(**values):
            return self.change_inner(lambda x: x['findings'][0]['citations'][0].update(**values))
        self.reject('SOURCE_BINDING', quote_change(source_id='different-source'))
        self.reject('SOURCE_BINDING', quote_change(source_sha='0' * 64))
        self.reject('QUOTE_MISMATCH', quote_change(quote='The source never said this.'))
        q = strict_json(self.good['output'][0]['content'][0]['text'].encode())['findings'][0]['citations'][0]
        # The em dash before this quote makes UTF-8 byte offsets differ from Unicode offsets.
        byte_start = len(SOURCE[:q['start']].encode('utf-8'))
        byte_end = len(SOURCE[:q['end']].encode('utf-8'))
        self.assertNotEqual(byte_start, q['start'])
        self.reject('QUOTE_MISMATCH', quote_change(start=byte_start, end=byte_end))
        self.reject('INTEGER_RANGE', quote_change(start=True))

    def test_C06_output_message_and_nested_logprobs_remain_restricted(self):
        changes = [('OUTPUT_CAPABILITY_REJECTED', lambda x: x['output'][0].update(type='function_call')),
                   ('OUTPUT_CAPABILITY_REJECTED', lambda x: x['output'][0].update(role='user')),
                   ('OUTPUT_CAPABILITY_REJECTED', lambda x: x['output'][0].update(status='incomplete')),
                   ('MESSAGE_FIELDS', lambda x: x['output'][0].update(extra=True)),
                   ('OUTPUT_CONTENT_REJECTED', lambda x: x['output'][0]['content'][0].update(type='refusal')),
                   ('OUTPUT_EXTRAS_REJECTED', lambda x: x['output'][0]['content'][0].update(
                       logprobs=[{'token': 'x', 'logprob': -1, 'top_logprobs': []}])),
                   ('OUTPUT_EXTRAS_REJECTED', lambda x: x['output'][0]['content'][0].update(annotations=[{}])),
                   ('ONE_VISIBLE_ANSWER_REQUIRED', lambda x: x['output'][0]['content'].append(
                       copy.deepcopy(x['output'][0]['content'][0])))]
        for code, change in changes:
            value = copy.deepcopy(self.good)
            change(value)
            with self.subTest(code=code):
                self.reject(code, value)
        for permitted in (None, []):
            value = copy.deepcopy(self.good)
            value['output'][0]['content'][0]['logprobs'] = permitted
            self.parse(value)

    def test_C07_usage_validation_still_fail_closed(self):
        changes = [('USAGE_FIELDS', lambda u: u.update(unknown=0)),
                   ('INTEGER_RANGE', lambda u: u.update(input_tokens=True)),
                   ('INTEGER_RANGE', lambda u: u.update(output_tokens=2049)),
                   ('INTEGER_RANGE', lambda u: u.update(output_tokens=400.0)),
                   ('USAGE_TOTAL', lambda u: u.update(total_tokens=550)),
                   ('USAGE_DETAIL_FIELDS', lambda u: u['output_tokens_details'].update(extra=0)),
                   ('INTEGER_RANGE', lambda u: u['output_tokens_details'].update(reasoning_tokens=401)),
                   ('INTEGER_RANGE', lambda u: u['output_tokens_details'].update(reasoning_tokens=True))]
        for code, change in changes:
            value = copy.deepcopy(self.good)
            change(value['usage'])
            with self.subTest(code=code):
                self.reject(code, value)

    def test_D01_usage_not_added_twice_and_accounting_not_inferred(self):
        value = copy.deepcopy(self.good)
        value['service_tier'] = 'auto'
        _, receipt = self.parse(value)
        usage = receipt['usage']
        self.assertEqual(usage, value['usage'])
        self.assertEqual(usage['total_tokens'], usage['input_tokens'] + usage['output_tokens'])
        self.assertEqual(usage['output_tokens_details']['reasoning_tokens'], 50)
        self.assertEqual(usage['total_tokens'], 500)
        self.assertEqual(receipt['billing'], 'UNRECONCILED')
        self.assertFalse(receipt['pricing_equivalence_verified'])
        self.assertIn('SERVICE_TIER_AUTO_ECHO_NOT_PRICE_PROOF', receipt['warnings'])

    def test_D02_synthetic_ui_payload_save_stale_and_stop_without_live(self):
        with tempfile.TemporaryDirectory(prefix='muse-synthetic-compat-') as temp:
            store = Store(Path(temp) / 'workspace')
            server = None
            try:
                store.load_source()
                store.save(EXAMPLE)
                req = store.prepare('OFFLINE_DEMO', digest(EXAMPLE))
                req, draft = store.begin(req['id'], True, 'OFFLINE_DEMO')
                value = wire(req, draft)
                value.update(completed_at=1700000000.25, top_logprobs=0)
                review, receipt = parse_response(200, canonical(value), req, draft)
                receipt.update(provenance='SYNTHETIC_COMPATIBILITY_TEST', provider_calls=0,
                               semantic_acceptance='SIMULATED_NOT_AI_JUDGMENT',
                               billing='NOT_APPLICABLE_OFFLINE')
                self.assertTrue(store.finish(req, review, receipt, canonical(value)))
                server = make_server(store)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def call(path, body=None, token=None):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    headers = {'Content-Type': 'application/json'}
                    if token:
                        headers['X-Muse-CSRF'] = token
                    try:
                        conn.request('GET' if body is None else 'POST', path,
                                     body=None if body is None else canonical(body), headers=headers)
                        response = conn.getresponse()
                        payload = strict_json(response.read())
                        self.assertEqual(response.status, 200)
                        return payload
                    finally:
                        conn.close()

                state = call('/api/state')
                token = state['csrf']
                result = state['reviews'][0]
                self.assertEqual(result['status'], 'CURRENT')
                self.assertEqual(result['receipt']['provenance'], 'SYNTHETIC_COMPATIBILITY_TEST')
                self.assertEqual(len(result['review']['findings']), 4)
                self.assertNotIn('raw_response_base64', result)
                self.assertFalse(state['real_meta_review_completed'])
                changed = call('/api/save', {'text': EXAMPLE + ' Human revision.'}, token)['state']
                self.assertEqual(changed['reviews'][0]['status'], 'STALE')
                restored = call('/api/save', {'text': EXAMPLE}, token)['state']
                self.assertEqual(restored['reviews'][0]['status'], 'STALE')
                self.assertEqual(restored['revision'], 3)
                stopped = call('/api/stop', {}, token)['state']
                self.assertTrue(stopped['stopped'])
                self.assertEqual(stopped['live_attempts'], 0)
                self.assertEqual(stopped['offline_attempts'], 1)
                self.assertEqual(stopped['formal_gate'], 'OFF')
            finally:
                if server is not None:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                store.close()


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ResponseCompatibilityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'suite': 'P2_R1_RESPONSE_COMPAT_SYNTHETIC', 'methods': result.testsRun,
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'new_provider_calls': 0, 'input_origin': 'SYNTHETIC_ONLY',
                      'scope': 'THIS_PYTHON_TEST_PROCESS_NOT_HOST_WIDE',
                      'audit': AUDIT, 'refusal_checks': CHECKS}, sort_keys=True))
    raise SystemExit(not result.wasSuccessful())
