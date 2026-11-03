"""Private local workspace persistence; not an authorization or billing service."""
import base64
import copy
import fcntl
import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
from .contracts import (Refusal, SOURCE, SOURCE_ID, POLICY, MODEL, ENDPOINT, canonical,
                        digest, strict_json, require, text, secret_like, request_body)


class Store:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        require(not self.root.is_symlink(), 'STATE_SYMLINK')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(self.root.stat().st_uid == os.getuid(), 'STATE_OWNER')
        os.chmod(self.root, 0o700)
        self.path = self.root/'workspace.json'
        require(not self.path.is_symlink(), 'STATE_SYMLINK')
        lock_path = self.root/'workspace.lock'
        require(not lock_path.is_symlink(), 'STATE_SYMLINK')
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        self.lockfile = os.fdopen(fd, 'a+b')
        try:
            fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lockfile.close()
            raise Refusal('WORKSPACE_ALREADY_OPEN')
        self.mutex = threading.RLock()
        self.faulted = False
        if self.path.exists():
            state = strict_json(self.path.read_bytes(), 2097152)
            require(type(state) is dict and state.get('schema') == 'MUSE_LOCAL_CORE_R1', 'STATE_SCHEMA')
            require(set(state) == {'schema', 'session', 'source_loaded', 'source_epoch', 'draft', 'revision',
                    'draft_sha', 'requests', 'reviews', 'offline_attempts', 'live_attempts', 'stopped', 'events'}, 'STATE_SCHEMA')
            require(type(state['requests']) is list and type(state['reviews']) is list, 'STATE_SCHEMA')
            require(state['draft_sha'] == digest(state['draft']), 'STATE_IDENTITY')
            self.state = state
            self._invalidate(state, 'PROCESS_RESTART')
            self._event(state, 'PROCESS_RESTART')
            self._persist(state)
        else:
            self.state = {'schema': 'MUSE_LOCAL_CORE_R1', 'session': str(uuid.uuid4()),
                'source_loaded': False, 'source_epoch': 0, 'draft': '', 'revision': 0,
                'draft_sha': digest(''), 'requests': [], 'reviews': [],
                'offline_attempts': 0, 'live_attempts': 0, 'stopped': False, 'events': []}
            self._persist(self.state)

    def close(self):
        self.lockfile.close()

    def _persist(self, state):
        raw = canonical(state)
        require(len(raw) <= 2097152, 'STATE_LIMIT')
        fd, name = tempfile.mkstemp(prefix='.write-', dir=str(self.root))
        try:
            with os.fdopen(fd, 'wb') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(raw); f.flush(); os.fsync(f.fileno())
            os.replace(name, str(self.path))
            parent = os.open(str(self.root), os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _change(self, fn):
        with self.mutex:
            require(not self.faulted, 'PERSISTENCE_FAULT_STOPPED')
            state = copy.deepcopy(self.state)
            result = fn(state)
            try:
                self._persist(state)
            except Exception:
                self.faulted = True
                raise Refusal('PERSISTENCE_FAULT_STOPPED') from None
            self.state = state
            return result

    @staticmethod
    def _event(s, code):
        require(len(s['events']) < 512, 'LOCAL_EVENT_LIMIT')
        s['events'].append({'sequence': len(s['events'])+1, 'code': code})

    @staticmethod
    def _invalidate(s, reason):
        for review in s['reviews']:
            if review['status'] == 'CURRENT':
                review.update(status='STALE', stale_reason=reason)
        for req in s['requests']:
            if req['status'] == 'PREPARED':
                req.update(status='STALE', stale_reason=reason)

    @staticmethod
    def binding(s):
        return {'schema': 'MUSE_CORE_BINDING_R1', 'session_id': s['session'],
            'source_id': SOURCE_ID, 'source_version': 1, 'source_sha': digest(SOURCE),
            'source_epoch': s['source_epoch'], 'draft_revision': s['revision'], 'draft_sha': s['draft_sha'],
            'goal_id': 'evidence_review', 'goal_revision': 1, 'policy_sha': digest(POLICY),
            'adapter_version': 'MUSE_META_RESPONSES_R1'}

    def load_source(self):
        def op(s):
            require(not s['stopped'], 'WORKSPACE_STOPPED')
            if not s['source_loaded']:
                s['source_loaded'] = True; s['source_epoch'] += 1
                self._invalidate(s, 'SOURCE_CHANGED'); self._event(s, 'SOURCE_LOADED')
        self._change(op)

    def save(self, draft):
        text(draft, 8192)
        require(not secret_like(draft), 'SECRET_LIKE_TEXT_REJECTED')
        def op(s):
            if s['draft'] != draft:
                s.update(draft=draft, draft_sha=digest(draft), revision=s['revision']+1)
                self._invalidate(s, 'SAVED_DRAFT_CHANGED'); self._event(s, 'DRAFT_SAVED')
        self._change(op)

    def prepare(self, mode, saved_sha):
        require(mode in ('OFFLINE_DEMO', 'META_LIVE'), 'MODE')
        def op(s):
            require(not s['stopped'], 'WORKSPACE_STOPPED')
            require(s['source_loaded'], 'SOURCE_REQUIRED')
            require(bool(s['draft'].strip()), 'EMPTY_DRAFT')
            require(saved_sha == s['draft_sha'], 'SAVED_DRAFT_CHANGED')
            require(s['offline_attempts' if mode == 'OFFLINE_DEMO' else 'live_attempts'] == 0, 'ATTEMPT_ALREADY_USED')
            require(len(s['requests']) < 16, 'PREVIEW_LIMIT')
            for old in s['requests']:
                if old['status'] == 'PREPARED':
                    old.update(status='STALE', stale_reason='NEW_PREVIEW')
            rid = 'muse-r1-'+uuid.uuid4().hex
            binding = self.binding(s)
            body = request_body(rid, binding, s['draft'])
            req = {'id': rid, 'mode': mode, 'binding': binding, 'body': body.decode('utf-8'),
                   'body_sha': digest(body), 'body_bytes': len(body), 'model': MODEL, 'endpoint': ENDPOINT,
                   'status': 'PREPARED', 'created_at': time.time(), 'expires_at': time.time()+300}
            s['requests'].append(req); self._event(s, 'REQUEST_PREPARED')
            return copy.deepcopy(req)
        return self._change(op)

    def request(self, rid):
        with self.mutex:
            found = [x for x in self.state['requests'] if x['id'] == rid]
            require(len(found) == 1, 'REQUEST_UNKNOWN')
            return copy.deepcopy(found[0])

    def check_current(self, req):
        with self.mutex:
            s = self.state
            require(not self.faulted, 'PERSISTENCE_FAULT_STOPPED')
            require(not s['stopped'], 'WORKSPACE_STOPPED')
            require(s['source_loaded'] and req['binding'] == self.binding(s), 'CONTEXT_STALE')
            require(req['body_sha'] == digest(req['body']), 'BODY_IDENTITY')
            require(req['body'].encode('utf-8') == request_body(req['id'], self.binding(s), s['draft']), 'REQUEST_NOT_CANONICAL')
            require(req['created_at'] <= time.time() <= req['expires_at'], 'REQUEST_EXPIRED_OR_CLOCK_ROLLBACK')

    def begin(self, rid, confirmed, mode):
        require(confirmed is True, 'EXPLICIT_CONFIRMATION_REQUIRED')
        def op(s):
            req = next((x for x in s['requests'] if x['id'] == rid), None)
            require(req is not None and req['mode'] == mode, 'REQUEST_MODE')
            self.check_current(req)
            require(req['status'] == 'PREPARED', 'REQUEST_REPLAY_OR_STALE')
            counter = 'offline_attempts' if mode == 'OFFLINE_DEMO' else 'live_attempts'
            require(s[counter] == 0, 'ATTEMPT_ALREADY_USED')
            s[counter] += 1; req['status'] = 'ATTEMPT_STARTED_UNKNOWN'
            self._event(s, mode+'_ATTEMPT_STARTED')
            return copy.deepcopy(req), s['draft']
        return self._change(op)

    def finish(self, req, review, receipt, raw, commit_check=None):
        def op(s):
            if commit_check is not None:
                commit_check()
            stored = next(x for x in s['requests'] if x['id'] == req['id'])
            require(stored['status'] == 'ATTEMPT_STARTED_UNKNOWN', 'RESULT_REPLAY')
            current = (not s['stopped'] and req['binding'] == self.binding(s) and
                       req['created_at'] <= time.time() <= req['expires_at'])
            result = {'request_id': req['id'], 'mode': req['mode'], 'binding': req['binding'],
                'status': 'CURRENT' if current else 'STALE', 'stale_reason': None if current else 'CONTEXT_CHANGED_DURING_REVIEW',
                'review': review, 'receipt': receipt, 'raw_response_base64': base64.b64encode(raw).decode('ascii'),
                'raw_response_sha': digest(raw), 'formal_approval': 'NOT_ESTABLISHED'}
            s['reviews'].append(result)
            stored['status'] = 'COMPLETED' if current else 'STALE'
            self._event(s, 'REVIEW_SAVED' if current else 'STALE_RESPONSE_RETAINED')
            return current
        return self._change(op)

    def fail(self, rid, code):
        def op(s):
            req = next(x for x in s['requests'] if x['id'] == rid)
            req.update(status='UNKNOWN_NO_RETRY', failure_code=code)
            self._event(s, 'ATTEMPT_FAILED_NO_RETRY')
        self._change(op)

    def stop(self, reason='EMERGENCY_STOP'):
        require(reason in ('EMERGENCY_STOP', 'NORMAL_STOP'), 'STOP_REASON')
        def op(s):
            s['stopped'] = True; self._invalidate(s, reason)
            self._event(s, reason)
        self._change(op)

    def view(self):
        with self.mutex:
            s = copy.deepcopy(self.state)
        for review in s['reviews']:
            review.pop('raw_response_base64', None)
        for req in s['requests']:
            req.pop('body', None)
        s['source'] = {'id': SOURCE_ID, 'sha256': digest(SOURCE), 'text': SOURCE} if s['source_loaded'] else None
        s['formal_gate'] = 'OFF'
        s['real_meta_review_completed'] = any(r['receipt'].get('provenance') == 'REAL_META_RESPONSE' for r in s['reviews'])
        s['live_status'] = 'LIVE_AUTHORIZATION_PENDING'
        return s
